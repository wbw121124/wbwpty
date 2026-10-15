//! wbwpty-redirect: the DLL that is manually mapped into the target process.
//!
//! Constraints (see AGENTS.md):
//!   * `#![no_std]` and `panic = "abort"` — this DLL runs inside someone else's
//!     process, possibly before that process' CRT/heap is initialised, so it
//!     must never touch the allocator, TLS or unwinding.
//!   * `DllMain` runs under the loader lock and before the target's entry
//!     point, so it only does work that is safe under those rules: opening
//!     handles, `SetStdHandle`, PEB bookkeeping, and starting a thread.
//!   * Every failure path must degrade gracefully; never make the target crash.

#![no_std]

pub mod config;
pub mod crt;
pub mod ffi;
pub mod log;
pub mod peb;
pub mod stdio;

use core::ffi::c_void;

use ffi::{HINSTANCE, DWORD};

/// Injection status word published for the host to read back after mapping.
///
/// The host maps the image with `FILE_MAP_WRITE`-like semantics (plain RWX
/// pages), so it can read this out of the mapped `base + wbwpty_status_rva`.
/// Keeping it as a plain `static mut`-free `UnsafeCell` avoids pulling `core::cell`
/// initialisation into the image; a `static` with an initial value is stored in
/// `.data`/`.bss` which the manual mapper allocates, so it is safe to touch
/// before the entry point runs.
///
/// # Layout
///
/// ```text
///   bits  0..15  how far the attach path got (see [`stage`])
///   bits 16..31  the `fdwReason` DllMain was entered with
/// ```
///
/// Both halves matter. `fdwReason` is how a host tells "the stub passed
/// arguments correctly" from "it passed garbage and the whole attach path was
/// skipped" - a failure that is otherwise completely silent, because DllMain
/// still returns TRUE. The stage is how far the attach path got before it
/// stopped, which is the only way to localise a fault that happens after the
/// image is mapped and before the target notices anything.
#[no_mangle]
pub static mut WBWPTY_STATUS: u32 = 0;

/// How far the payload got.
///
/// Mirrored by the host in `wbwpty-core::session`; the two must stay in step.
pub mod stage {
    /// The image is mapped but no code of ours has run.
    pub const IDLE: u32 = 0;
    /// `DllMain` was entered; `fdwReason` is recorded.
    pub const ENTERED: u32 = 1;
    /// `ConsoleHandle` was written with the sentinel.
    pub const CONSOLE_PATCHED: u32 = 2;
    /// `ConsoleHandle` was already non-null and was left alone.
    pub const CONSOLE_ALREADY_SET: u32 = 3;
    /// The PEB or its process parameters could not be read; nothing was changed.
    pub const CONSOLE_SKIPPED: u32 = 4;
    /// The worker thread started.
    pub const WORKER_STARTED: u32 = 5;
    /// The environment contract was read and `WBWPTY_LOG` was opened if asked.
    pub const LOG_READY: u32 = 6;
    /// The CRT streams were put into unbuffered mode.
    pub const CRT_REPAIRED: u32 = 7;
    /// The CRT streams could not be repaired; see `WBWPTY_CRT_DETAIL`.
    pub const CRT_SKIPPED: u32 = 8;
    /// The worker ran to completion.
    pub const DONE: u32 = 9;

    /// Stages after which no further progress will be reported.
    pub const TERMINAL: u32 = DONE;
}

/// Packs a stage and the `fdwReason` DllMain was entered with into the layout
/// documented on [`WBWPTY_STATUS`].
pub const fn status_word(stage: u32, reason: u32) -> u32 {
    (stage & 0xffff) | (reason << 16)
}

/// Marks the image as live. Written by [`wbwpty_probe`] so the host can tell
/// "the image mapped and its code runs" from "the image is present but its code
/// faults", which is otherwise indistinguishable from a silent failure.
pub const PROBE_MARKER: u32 = 0xc0de_cafe;

/// Bisect entry point: touches nothing but the payload's own writable data.
///
/// If the host can read [`PROBE_MARKER`] back out of the target after mapping
/// this as the entry, the manual mapper produced a working image. If it cannot,
/// the fault is in the mapping (relocations, sections, or the call itself) and
/// not in whatever [`DllMain`] happens to do.
#[no_mangle]
pub extern "system" fn wbwpty_probe() -> i32 {
    unsafe { WBWPTY_STATUS = PROBE_MARKER };
    0
}

pub const WBWPTY_STATUS_IDLE: u32 = 0;
pub const WBWPTY_STATUS_OK: u32 = 1;
pub const WBWPTY_STATUS_NO_PIPE_IN: u32 = 2;
pub const WBWPTY_STATUS_NO_PIPE_OUT: u32 = 3;

/// Detail word for [`stage::CRT_REPAIRED`] / [`stage::CRT_SKIPPED`].
///
/// Packed because the host reads it as a single `u32` and the stage word only
/// has room for "did it work":
///
/// ```text
///   bits  0..7  streams `setvbuf` accepted
///   bits  8..15 streams `setvbuf` refused
///   bits 16..23 1 if ucrtbase and both exports resolved
/// ```
#[no_mangle]
pub static mut WBWPTY_CRT_DETAIL: u32 = 0;

/// Entry point invoked by the manual mapper (and by the C runtime when the DLL
/// is loaded normally with `LoadLibrary`).
///
/// Deliberately short. Everything that can touch another module - reading the
/// environment, opening the log, reaching into ucrtbase - happens on the worker
/// thread, because `DllMain` runs under the loader lock and `dlog!`'s
/// formatting code has already been caught faulting there (AGENTS pitfall 11).
#[no_mangle]
pub extern "system" fn DllMain(_hinst: HINSTANCE, reason: DWORD, _reserved: *mut c_void) -> i32 {
    // Record that we entered DllMain with the given reason, so the host can
    // verify the stub passed arguments correctly. The attach path overwrites
    // this with how far it actually got.
    unsafe { WBWPTY_STATUS = status_word(stage::ENTERED, reason); }
    if reason == ffi::DLL_PROCESS_ATTACH {
        ATTACH_REASON.store(reason, core::sync::atomic::Ordering::Relaxed);
        let outcome = crate::stdio::install();
        unsafe { WBWPTY_STATUS = status_word(outcome.stage(), reason); }
        start_worker(reason);
    }
    ffi::TRUE
}

/// Starts the payload's worker thread and returns immediately.
///
/// The thread runs the parts that must not happen under the loader lock. It is
/// the reason `DllMain` stays trivial; see [`worker`].
fn start_worker(reason: DWORD) {
    // SAFETY: no attributes, default stack, a `LPTHREAD_START_ROUTINE` with
    // the documented signature and a null parameter. `worker` is a plain
    // `extern "system" fn(*mut c_void) -> DWORD` that ignores its argument.
    let handle = unsafe {
        ffi::CreateThread(
            core::ptr::null_mut(),
            0,
            Some(worker),
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        )
    };
    if handle.is_null() {
        // No worker means no log and no CRT repair. Record that rather than
        // pretending the attach path finished.
        unsafe { WBWPTY_STATUS = status_word(stage::CRT_SKIPPED, reason) };
        return;
    }
    // SAFETY: a live handle from the call above.
    unsafe { ffi::CloseHandle(handle) };
}

/// The payload's actual work, on a thread of its own.
///
/// Runs once. Everything here may block or take another module's init lock,
/// which is precisely why it is not in `DllMain`.
unsafe extern "system" fn worker(arg: *mut c_void) -> DWORD {
    // The parameter is the null `start_worker` passed and is deliberately
    // unused; reading it is not an unsafe operation, it just is not needed.
    let _ = arg;
    let reason = ATTACH_REASON.load(core::sync::atomic::Ordering::Relaxed);

    crate::config::load();
    crate::log::init_from_env();
    unsafe { WBWPTY_STATUS = status_word(stage::LOG_READY, reason) };

    let outcome = crate::crt::repair();
    unsafe {
        WBWPTY_CRT_DETAIL = (outcome.streams_set & 0xff)
            | ((outcome.streams_refused & 0xff) << 8)
            | (u32::from(outcome.ucrt_resolved) << 16);
        WBWPTY_STATUS = status_word(
            if outcome.is_effective() {
                stage::CRT_REPAIRED
            } else {
                stage::CRT_SKIPPED
            },
            reason,
        );
        crate::dlog!(
            "crt: ucrt_resolved={} streams_set={} streams_refused={} rows={} cols={} shim={}",
            outcome.ucrt_resolved,
            outcome.streams_set,
            outcome.streams_refused,
            crate::config::rows(),
            crate::config::cols(),
            crate::config::shim(),
        );
        WBWPTY_STATUS = status_word(stage::DONE, reason);
    }
    0
}

/// `fdwReason` handed to the worker, so every stage it publishes carries the
/// same one.
static ATTACH_REASON: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// `core` is shipped in the sysroot compiled with unwinding, so its `.xdata`
/// still references `rust_eh_personality` even though this crate is built with
/// `panic = "abort"`. Nothing in this DLL can unwind (the panic handler below
/// loops forever), so an empty personality routine satisfies the linker.
/// `cfg(not(test))` for the same reason as the panic handler below: a
/// workspace-wide `cargo test <filter>` still builds this crate's lib test
/// target, and `std` brings its own `rust_eh_personality`.
#[cfg(not(test))]
#[no_mangle]
extern "C" fn rust_eh_personality() {}

/// A panic in a `no_std` DLL must not unwind. Report and spin forever; the host
/// watchdog will terminate the target rather than corrupt its state.
///
/// `cfg(not(test))` because the `[lib] test = false` setting is not enough on
/// its own: a workspace-wide `cargo test <filter>` still builds this crate's lib
/// test target, and two `#[panic_handler]`s in one binary is `E0152`. The lib is
/// never unit tested - everything here is exercised from `wbwpty-core` against
/// a real target process - so under `cfg(test)` the harness' handler is fine.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::dlog!("panic in DllMain: {}", info);
    loop {
        // SAFETY: `Sleep` has no preconditions; `INFINITE` keeps us parked.
        unsafe { ffi::Sleep(0xffff_ffff) };
    }
}