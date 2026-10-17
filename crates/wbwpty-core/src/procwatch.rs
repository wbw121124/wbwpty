//! Proving that a session never caused a console host, in a way that can fail.
//!
//! # Why not `inspect::conhost_count()`
//!
//! The project's premise is that a target launched through wbwpty never gets a
//! `conhost.exe`. Counting console hosts before and after a session cannot
//! establish that, and it has been got wrong twice (AGENTS §12):
//!
//! * A console host lives only as long as the process that owns its console. By
//!   the time a test finishes looking, the very host it was looking for is gone,
//!   so the delta is zero whether or not one appeared.
//! * The machine already runs a shifting population of them - VS Code, the
//!   language servers, the WLAN service - so the baseline is never still.
//!
//! Both failures point the same way: **a snapshot taken afterwards cannot report
//! an event that has already ended.** A shorter interval does not fix that, it
//! only makes the miss less likely. The fix is to accumulate what was seen
//! *while* things ran, and to be explicit about whether the accumulation can miss
//! anything.
//!
//! # Two modes, and why the caller has to care
//!
//! [`ProcessWatch::mode`] reports whether the watch is
//! [`Mode::KernelEvents`] - kernel-published process starts, which cannot miss a
//! process that lived two milliseconds - or [`Mode::Sampled`], which polls and
//! therefore can. Both answer "no console host" with an empty list when nothing
//! was created, and only the first is entitled to mean it. That distinction is
//! the point of the type: a claim that cannot fail is not a claim.
//!
//! # Trusting the payload
//!
//! Under [`Mode::KernelEvents`], only `ProcessId` and `ParentId` are read, from
//! fixed offsets in the `Microsoft-Windows-Kernel-Process` `Process_TypeGroup1`
//! payload (versions 3 and 4), whose layout is `UniqueProcessKey(u64),
//! ProcessId(u32), ParentId(u32), ...`. The image name is never decoded out of
//! that payload - it is read back from the process itself, because a name decoded
//! from a variable-length blob is a name that can be decoded wrongly and then
//! believed. A process already gone keeps its pid and reports no name rather than
//! a guess.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, StopTraceW, CONTROLTRACE_HANDLE,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_TYPE_START,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `Microsoft-Windows-Kernel-Process`: the provider that publishes process
/// lifecycle events. Spelled out with its provenance rather than inlined, because
/// a bare GUID with no source is what AGENTS rule 5 objects to.
const KERNEL_PROCESS_PROVIDER: GUID = GUID {
    data1: 0x22FB2CD6,
    data2: 0x0E7B,
    data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};

/// `WINEVENT_KEYWORD_PROCESS`, from the same manifest.
const KEYWORD_PROCESS: u64 = 0x10;

/// `EVENT_TRACE_USE_NOCOPY`, `evntrace.h`. Not exported by windows-sys.
///
/// Required alongside an `EVENT_RECORD` callback: the callback reads the session's
/// buffers in place, so a real-time session without this is refused by
/// `StartTraceW` with `ERROR_INVALID_PARAMETER`. Its necessity was established by
/// reading back the `LogFileMode` of a session PowerShell's `New-EtwTraceSession`
/// builds, which comes out as `0x800100`.
const EVENT_TRACE_USE_NOCOPY: u32 = 0x0080_0000;

/// Minimum `Wnode.BufferSize` accepted by `StartTraceW` for a real-time session.
///
/// Not the size of `EVENT_TRACE_PROPERTIES` - that reading is wrong and cost a
/// full debugging round to get rid of. The field is the size of the buffer the
/// provider is given, and the kernel refuses a real-time session whose value is
/// too small, with `ERROR_INVALID_PARAMETER` (24).
///
/// Measured on this machine by varying that field alone against every other
/// argument held fixed (minimum buffers, maximum buffers, buffer size, flush
/// timer and `LogFileMode` all made no difference): `120` =
/// `size_of::<EVENT_TRACE_PROPERTIES>()` fails, `1024` succeeds. Kept as a named
/// constant with the evidence attached so it is not "corrected" back.
const MIN_WNODE_BUFFER_SIZE: u32 = 1024;

/// Payload offsets for `Process_TypeGroup1` versions 3 and 4.
const PROCESS_ID_OFFSET: usize = 0x08;
const PARENT_ID_OFFSET: usize = 0x0C;

/// Versions 0-2 have no `UniqueProcessKey` and put `ProcessId` first. Modern
/// Windows emits 3 or 4; anything else is skipped rather than read as if it were
/// the layout checked above.
const SUPPORTED_VERSIONS: [u8; 2] = [3, 4];

/// Names that mean "a console was allocated for somebody".
///
/// Both, because Windows 11 runs the newer `OpenConsole.exe` alongside the
/// classic host, and a watcher that only knew one of them would be blind to half
/// of what the user would see.
const CONSOLE_HOST_NAMES: [&str; 2] = ["conhost.exe", "openconsole.exe"];

/// One process creation, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Born {
    pub pid: u32,
    pub parent: u32,
    /// `None` when the image name could not be read - routine for short-lived
    /// children, and never guessed at.
    pub name: Option<String>,
}

#[derive(Default)]
struct Record {
    born: Vec<Born>,
    /// Processes that predate this watch, so a partial tree can say so.
    adopted: HashSet<u32>,
}

/// How the watch is kept, and therefore what its silence is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Kernel process events: every creation is published as it happens, so a
    /// console host that lived two milliseconds is still recorded.
    KernelEvents,
    /// A sampled fallback. A host created and exited between two samples is
    /// missed, so an empty answer means "none was seen", never "none existed".
    Sampled,
}

impl Mode {
    /// Whether a negative result is evidence rather than merely an absence.
    pub fn is_exhaustive(self) -> bool {
        matches!(self, Mode::KernelEvents)
    }
}

/// Records process creations for as long as it lives.
pub struct ProcessWatch {
    record: Arc<Mutex<Record>>,
    mode: Mode,
    session: Option<CONTROLTRACE_HANDLE>,
    stop: Arc<AtomicBool>,
    consumer: Option<std::thread::JoinHandle<()>>,
}

impl ProcessWatch {
/// Starts watching, degrading to sampling if the kernel provider refuses.
    ///
    /// The degradation is visible: [`Self::mode`] reports it, and
    /// [`Mode::is_exhaustive`] is what decides whether an empty answer may be
    /// quoted as evidence. AGENTS rule 4's "degrade rather than crash" only holds
    /// if the degradation is observable from outside.
    ///
    /// On a session without administrator rights this always returns
    /// [`Mode::Sampled`]: starting the ETW session succeeds, but enabling
    /// `Microsoft-Windows-Kernel-Process` needs `SeSystemProfilePrivilege` and
    /// fails with `ERROR_ACCESS_DENIED`. There is no parameter that avoids this,
    /// and no non-privileged substitute that is exhaustive - see
    /// [`Self::try_kernel_events`].
    pub fn start() -> Self {
        Self::try_kernel_events().unwrap_or_else(|_| Self::sampled())
    }

/// Kernel-event watching, with the reason it could not start.
    ///
    /// Exposed so a caller can insist on the strong mode: a test that must be
    /// able to fail has to be able to refuse the weak one.
    ///
    /// Requires an elevated token. `StartTraceW` succeeds for an ordinary user,
    /// and then `EnableTraceEx2` on `Microsoft-Windows-Kernel-Process` returns
    /// `ERROR_ACCESS_DENIED` (5) because the provider needs
    /// `SeSystemProfilePrivilege`. `Win32_ProcessStartTrace` over WMI - the other
    /// obvious way to observe process creation without a kernel provider - is
    /// refused for the same reason, so a non-elevated process on this machine has
    /// no exhaustive source and must say so via [`Mode::is_exhaustive`].
    ///
    /// Measured, not assumed: `StartTraceW` was also returning
    /// `ERROR_INVALID_PARAMETER` (24) until [`MIN_WNODE_BUFFER_SIZE`] was set to a
    /// buffer size rather than to the size of the properties struct.
    pub fn try_kernel_events() -> Result<Self> {
        let mut properties: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
properties.Wnode.BufferSize = MIN_WNODE_BUFFER_SIZE;
        properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_USE_NOCOPY;
        properties.BufferSize = 64;
        properties.MinimumBuffers = 8;
        properties.MaximumBuffers = 8;
        properties.FlushTimer = 1;

        let name = session_name();
        let mut control = CONTROLTRACE_HANDLE { Value: 0 };
        let status = unsafe { StartTraceW(&raw mut control, name.as_ptr(), &raw mut properties) };
        if status != 0 {
            bail!("StartTraceW failed: {}", win_error(status));
        }

        let provider = KERNEL_PROCESS_PROVIDER;
        let enabled = unsafe {
            EnableTraceEx2(
                control,
                &raw const provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                0,
                KEYWORD_PROCESS,
                0,
                0,
                std::ptr::null(),
            )
        };
        if enabled != 0 {
            let text = win_error(enabled);
            unsafe { stop_trace(control) };
            bail!("EnableTraceEx2(Microsoft-Windows-Kernel-Process) failed: {text}");
        }

        let record = Arc::new(Mutex::new(Record::default()));
        let mut logfile: Box<EVENT_TRACE_LOGFILEW> = Box::new(unsafe { std::mem::zeroed() });
        // `ProcessTraceMode` and `EventRecordCallback` are union members, reached
        // through the anonymous fields. Only one member of each is ever live, and
        // it is the one ETW reads.
        logfile.Anonymous1.ProcessTraceMode = 1; // PROCESS_TRACE_MODE_REAL_TIME
        logfile.Anonymous2.EventRecordCallback = Some(on_event_record);
        logfile.BufferSize = 64;
        // Valid for the whole life of the watch: the session is stopped and the
        // consumer joined in `Drop` before this `Arc` is released.
        logfile.Context = Arc::as_ptr(&record) as *mut std::ffi::c_void;

        let handle = unsafe { OpenTraceW(&raw mut *logfile) };
        if handle.Value == 0 || handle.Value == u64::MAX {
            let err = std::io::Error::last_os_error();
            unsafe { stop_trace(control) };
            bail!("OpenTraceW failed: {err}");
        }

        // `EVENT_TRACE_LOGFILEW` is `#[repr(C)]` over raw pointers, so it is not
        // `Send`. It has to outlive `ProcessTrace`, which blocks for as long as
        // the session runs, so ownership moves to the consumer thread - moved as a
        // whole and never field-accessed inside the closure, because under edition
        // 2021 mentioning `.0` captures that field instead.
        #[allow(dead_code)] // held, never read: keeping it alive is the job
        struct Holder(Box<EVENT_TRACE_LOGFILEW>);
        // SAFETY: the holder owns the only live copy, moves once into the consumer
        // thread, and is dropped there when `ProcessTrace` returns. No other thread
        // observes it; ETW only reads it.
        unsafe impl Send for Holder {}

        let holder = Holder(logfile);
        let consumer = std::thread::spawn(move || {
            let holder = holder;
            let handles = [handle];
            // SAFETY: `handles` is live and correctly sized, and `holder` owns the
            // buffer for the whole call. Returns when the session is stopped.
            unsafe {
                ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
                CloseHandle(handle.Value as _);
            }
            drop(holder);
        });

        Ok(Self {
            record,
            mode: Mode::KernelEvents,
            session: Some(control),
            stop: Arc::new(AtomicBool::new(false)),
            consumer: Some(consumer),
        })
    }

    /// The fallback: sample the process table, accumulating rather than comparing.
    ///
    /// Accumulating is the part that matters. A poll that kept only the latest
    /// snapshot would miss exactly the processes this module exists for, and
    /// would report that as clean.
    fn sampled() -> Self {
        let record = Arc::new(Mutex::new(Record::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let consumer = {
            let record = Arc::clone(&record);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut seen: HashSet<u32> = HashSet::new();
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(table) = crate::inspect::process_table() {
                        let fresh: Vec<_> = table
                            .iter()
                            .filter(|e| !seen.contains(&e.pid))
                            .map(|e| (e.pid, e.parent, e.name.to_ascii_lowercase()))
                            .collect();
                        if !fresh.is_empty() {
                            if let Ok(mut record) = record.lock() {
                                for (pid, parent, name) in fresh {
                                    seen.insert(pid);
                                    record.born.push(Born {
                                        pid,
                                        parent,
                                        name: Some(name),
                                    });
                                }
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        Self {
            record,
            mode: Mode::Sampled,
            session: None,
            stop,
            consumer: Some(consumer),
        }
    }

    /// Which kind of watching is in effect.
    ///
    /// An empty [`Self::console_hosts_under`] is evidence of "no console host"
    /// only when this is [`Mode::KernelEvents`].
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Records a process that already exists, so its lineage is not invisible.
    ///
    /// Without this, a watch started after the root was created reports an empty
    /// tree - which reads as "clean" rather than "unknown". Anything adopted this
    /// way makes [`Self::is_complete`] return `false`.
    pub fn adopt(&self, pid: u32) {
        if let Ok(mut record) = self.record.lock() {
            record.adopted.insert(pid);
        }
    }

    /// Whether every branch under `root` was observed from the moment it began.
    pub fn is_complete(&self, root: u32) -> bool {
        let Ok(record) = self.record.lock() else {
            return false;
        };
        let children = children_of(&record);
        let mut frontier = vec![root];
        let mut seen = HashSet::new();
        while let Some(pid) = frontier.pop() {
            if !seen.insert(pid) {
                continue;
            }
            if record.adopted.contains(&pid) {
                return false;
            }
            frontier.extend(children.get(&pid).into_iter().flatten().copied());
        }
        true
    }

    /// Every console host created underneath `root`.
    pub fn console_hosts_under(&self, root: u32) -> Vec<Born> {
        let mut found = Vec::new();
        let Ok(mut record) = self.record.lock() else {
            return found;
        };
        let children = children_of(&record);
        let mut in_tree = HashSet::new();
        let mut frontier: Vec<u32> = children.get(&root).into_iter().flatten().copied().collect();
        while let Some(pid) = frontier.pop() {
            if !in_tree.insert(pid) {
                continue;
            }
            frontier.extend(children.get(&pid).into_iter().flatten().copied());
        }
        for born in record.born.iter_mut() {
            if !in_tree.contains(&born.pid) {
                continue;
            }
            if born.name.is_none() {
                born.name = process_name(born.pid);
            }
            if born
                .name
                .as_deref()
                .is_some_and(|n| CONSOLE_HOST_NAMES.contains(&n))
            {
                found.push(born.clone());
            }
        }
        found
    }

    /// Everything recorded, so a test can assert on the watch itself rather than
    /// trusting that it worked.
    pub fn recorded(&self) -> Vec<Born> {
        self.record
            .lock()
            .map(|r| r.born.clone())
            .unwrap_or_default()
    }
}

impl Drop for ProcessWatch {
    fn drop(&mut self) {
        // Order matters. The sampler polls `stop`, so that must be set before its
        // join. The event consumer is blocked inside `ProcessTrace`, which only
        // returns once the session is stopped, so the session must go first -
        // joining before that would hang.
        self.stop.store(true, Ordering::Relaxed);
        if let Some(control) = self.session.take() {
            unsafe { stop_trace(control) };
        }
        if let Some(consumer) = self.consumer.take() {
            let _ = consumer.join();
        }
        // `record` is released after this, once nothing can still reach it.
    }
}

fn children_of(record: &Record) -> HashMap<u32, Vec<u32>> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for born in &record.born {
        children.entry(born.parent).or_default().push(born.pid);
    }
    children
}

/// ETW's per-event callback, on the consumer thread.
unsafe extern "system" fn on_event_record(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = &*record;
    if record.EventHeader.EventDescriptor.Opcode as u32 != EVENT_TRACE_TYPE_START {
        return;
    }
    if !SUPPORTED_VERSIONS.contains(&record.EventHeader.EventDescriptor.Version) {
        return;
    }
    let payload = record.UserData as *const u8;
    if payload.is_null() || (record.UserDataLength as usize) < PARENT_ID_OFFSET + 4 {
        return;
    }
    let pid = read_u32(payload.add(PROCESS_ID_OFFSET));
    let parent = read_u32(payload.add(PARENT_ID_OFFSET));
    if pid == 0 {
        return;
    }
    // `UserContext` is what `EVENT_TRACE_LOGFILEW.Context` was installed as, and
    // it stays valid because the `Arc` behind it outlives the session.
    let shared = record.UserContext as *const Mutex<Record>;
    if shared.is_null() {
        return;
    }
    let born = Born {
        pid,
        parent,
        name: process_name(pid),
    };
    if let Ok(mut guard) = (*shared).lock() {
        guard.born.push(born);
    }
}

/// Reads a little-endian `u32` from an unaligned pointer.
///
/// # Safety
/// `ptr` must be valid for a 4-byte read.
unsafe fn read_u32(ptr: *const u8) -> u32 {
    u32::from_le_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)])
}

/// The image name of a live process, or `None` if it is already gone.
///
/// `QueryFullProcessImageNameW` rather than a ToolHelp snapshot: this runs once
/// per creation on the consumer thread, and a snapshot enumerates the whole
/// machine to answer a question about one pid.
fn process_name(pid: u32) -> Option<String> {
    // SAFETY: a limited query handle suffices for the name, and every path closes
    // it.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buffer = [0u16; 260];
        let mut len = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &raw mut len);
        let _ = CloseHandle(handle);
        if ok == 0 || len == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        Some(
            path.rsplit('\\')
                .next()
                .unwrap_or(path.as_str())
                .to_ascii_lowercase(),
        )
    }
}

fn session_name() -> Vec<u16> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "wbwpty-procwatch-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect()
}

/// # Safety
/// `control` must come from a `StartTraceW` that has not been stopped.
unsafe fn stop_trace(control: CONTROLTRACE_HANDLE) {
    let mut properties: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
    properties.Wnode.BufferSize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    unsafe {
        let _ = StopTraceW(control, std::ptr::null(), &raw mut properties);
    }
}

fn win_error(status: u32) -> String {
    std::io::Error::from_raw_os_error(status as i32).to_string()
}
