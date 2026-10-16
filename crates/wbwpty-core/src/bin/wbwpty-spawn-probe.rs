//! Test fixture: spawn a child with a caller-chosen set of creation flags.
//!
//! # Why this exists
//!
//! The project's headline promise is that no process in the tree ever causes a
//! `conhost.exe` to appear, and that everything's standard I/O lands on our
//! pipes. That holds for the process *we* create, and fails for every process
//! the target creates afterwards - which is the part worth getting right.
//!
//! To find out what a child's creation has to look like for both promises to
//! hold, this probe exposes `CreateProcessW`'s flags and `STARTF_USESTDHANDLES`
//! to a test, so the matrix can be measured instead of guessed at. Guessing is
//! what produced the `ConsoleHandle` sentinel, which turned out to do nothing.
//!
//! # Usage
//!
//! ```text
//! wbwpty-spawn-probe [--std-handles|--no-std-handles] [--inherit|--no-inherit]
//!                    [--pidfile <path>] [--gate <path>]
//!                    [--console-write <text>] [--console-info]
//!                    <flag>...  --  <command line>
//! ```
//!
//! `<flag>` is one of `detached`, `no_window`, `new_console`, `unicode_env`,
//! or `none`. Exits with the child's exit code, or `0xff` if the child could not
//! be created at all.
//!
//! `--console-write <text>` is a mode rather than a flag: it writes `text` to
//! stdout through `WriteConsoleW` and exits, with nothing to spawn. It exists to
//! be a subject for the console API substitution - see `tests/console_shim.rs`.
//!
//! `--console-info` is the other such mode: it writes a few characters, waits for
//! the host's virtual screen to say where the cursor now is, and reports what
//! `GetConsoleScreenBufferInfo` answered.
//!
//! # `--gate`
//!
//! Waits for the named file to appear before spawning anything, and says so on
//! stderr first (`probe: gated`, then `probe: released`).
//!
//! This exists because a fixture that spawns immediately is not measuring what
//! it looks like it measures. Injection cannot happen until the target's loader
//! has settled, which takes on the order of a hundred milliseconds; a probe that
//! spawns in its first few milliseconds does so before any substitution is in
//! place, and the measurement then describes a target we never patched. The
//! gate makes "spawn now" something the test decides, which is the only way to
//! ask whether a substitution *works* rather than whether it was installed in
//! time.

use std::ffi::c_void;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_NEW_CONSOLE, CREATE_NO_WINDOW,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, STARTUPINFOW,
};

/// `GetExitCodeProcess` reports this while a process has not exited.
const STILL_ACTIVE: u32 = 259;

/// Reported when the child could not be created at all, so a test can tell
/// "the flag combination was rejected" from "the combination worked".
const SPAWN_FAILED: u32 = 0xff;
/// Reported when the fixture could not wait for its own child.
const WAIT_FAILED: u32 = 0xfe;
/// Reported when the fixture could not read the child's exit code.
///
/// Distinct from "the child exited 0", which used to look identical and made a
/// failing spawn indistinguishable from a passing one.
const EXIT_CODE_FAILED: u32 = 0xfd;

fn main() {
    let mut std_handles = false;
    let mut inherit = true;
    let mut flags: u32 = 0;
    let mut pidfile: Option<OsString> = None;
    let mut gate: Option<std::path::PathBuf> = None;
    let mut console_text: Option<OsString> = None;
    let mut console_info_mode = false;
    let mut command: Option<OsString> = None;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy();
        match text.as_ref() {
            "--std-handles" => std_handles = true,
            "--no-std-handles" => std_handles = false,
            "--inherit" => inherit = true,
            "--no-inherit" => inherit = false,
            "--pidfile" => pidfile = args.next(),
            "--gate" => gate = args.next().map(std::path::PathBuf::from),
            "--console-write" => console_text = args.next(),
            "--console-info" => console_info_mode = true,
            "--" => {
                command = args.next();
                break;
            }
            other => match parse_flag(other) {
                Some(flag) => flags |= flag,
                None => {
                    eprintln!("wbwpty-spawn-probe: unknown flag {other:?}");
                    std::process::exit(2);
                }
            },
        }
    }

    if let Some(gate) = gate {
        wait_for_gate(&gate);
    }

    if console_info_mode {
        console_info();
    }

    if let Some(text) = console_text {
        // A mode rather than a flag: there is nothing to spawn afterwards, and a
        // fixture that also did that would be measuring two things at once.
        console_write(&text.to_string_lossy());
    }

    let Some(command) = command else {
        eprintln!("wbwpty-spawn-probe: nothing to spawn; see --help output above");
        std::process::exit(2);
    };

    let mut wide: Vec<u16> = command.encode_wide().collect();
    if wide.last() != Some(&0) {
        wide.push(0);
    }

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    if std_handles {
        si.dwFlags = STARTF_USESTDHANDLES;
        // The CRT's own descriptors, not `GetStdHandle`. Measured here:
        // `GetStdHandle(0..2)` comes back as `INVALID_HANDLE_VALUE` in a
        // process whose stdout is very much a working pipe, so passing those
        // values on gives the child three broken handles and an immediate exit
        // code of 1. `as_raw_handle` on the std handles cannot drift from what
        // this process is actually writing to.
        use std::os::windows::io::AsRawHandle;
        si.hStdInput = std::io::stdin().as_raw_handle() as HANDLE;
        si.hStdOutput = std::io::stdout().as_raw_handle() as HANDLE;
        si.hStdError = std::io::stderr().as_raw_handle() as HANDLE;
        if std::env::var_os("WBWPTY_PROBE_VERBOSE").is_some() {
            eprintln!(
                "wbwpty-spawn-probe: STARTF_USESTDHANDLES in={:?} out={:?} err={:?} \
                 (GetStdHandle out={:?})",
                si.hStdInput,
                si.hStdOutput,
                si.hStdError,
                unsafe { GetStdHandle(1) as isize }
            );
        }
    } else if std::env::var_os("WBWPTY_PROBE_VERBOSE").is_some() {
        eprintln!(
            "wbwpty-spawn-probe: handle inheritance only, no STARTF_USESTDHANDLES"
        );
    }

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `wide` is a NUL terminated mutable buffer that outlives the call,
    // and every out parameter points at a live local.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            i32::from(inherit),
            flags,
            std::ptr::null::<c_void>(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        eprintln!(
            "wbwpty-spawn-probe: CreateProcessW(flags={flags:#x}) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(SPAWN_FAILED as i32);
    }

    // Report the child's pid before waiting for it, so a test can attribute a
    // `conhost.exe` to this particular spawn. Without that, "did the child get
    // a console" can only be answered by counting console hosts machine-wide,
    // which is a race whenever the child is short lived.
    //
    // A command line argument rather than an environment variable: these probes
    // run in parallel inside one test process, and an environment variable is
    // process-wide state that they would trample on each other.
    if let Some(path) = &pidfile {
        let _ = std::fs::write(path, pi.dwProcessId.to_string());
    }

    // SAFETY: both handles came from the `CreateProcessW` above.
    let waited = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
    // SAFETY: same handles.
    unsafe { CloseHandle(pi.hThread) };
    if waited != 0 {
        eprintln!("wbwpty-spawn-probe: WaitForSingleObject returned {waited}");
        // SAFETY: the process handle is live.
        unsafe { CloseHandle(pi.hProcess) };
        std::process::exit(WAIT_FAILED as i32);
    }

    let mut code = 0u32;
    // SAFETY: live handle and a live out parameter.
    let got_code = unsafe { GetExitCodeProcess(pi.hProcess, &mut code) };
    // SAFETY: the process handle is live.
    unsafe { CloseHandle(pi.hProcess) };
    if got_code == 0 {
        eprintln!("wbwpty-spawn-probe: GetExitCodeProcess failed");
        std::process::exit(EXIT_CODE_FAILED as i32);
    }
    if code == STILL_ACTIVE {
        // Would mean the wait returned without the child having finished, which
        // contradicts the API contract. Reporting it beats reporting "success".
        std::process::exit(STILL_ACTIVE as i32);
    }
    std::process::exit(code as i32);
}

/// Blocks until `gate` exists, saying so on stderr on the way in and out.
///
/// stderr, because that is the stream a session routes onto its own pipe: the
/// test that opened the gate sees the `released` line arrive before the child
/// does, which is what turns "I touched a file" into "the fixture really did
/// proceed".
///
/// No timeout. A fixture that is never released is a test that failed to set
/// itself up, and the harness's own timeout is the thing that reports that -
/// which is a better report than an invented exit code would be.
fn wait_for_gate(gate: &std::path::Path) {
    eprintln!("probe: gated on {}", gate.display());
    while !gate.exists() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    eprintln!("probe: released");
}

// `GetStdHandle` and `WriteConsoleW`, called through the import table.
//
// Declared rather than reached through dynamic lookup on purpose: the console
// API substitution rewrites **import slots**, so a program that resolves the
// function at run time has no slot to rewrite and would not be covered. This
// fixture has to import it statically to be a valid subject, and that is a real
// limitation of the mechanism rather than a detail of the test.
extern "system" {
    fn GetStdHandle(n_std_handle: u32) -> *mut std::ffi::c_void;
    #[allow(non_snake_case)]
    fn WriteConsoleW(
        console_output: *mut std::ffi::c_void,
        buffer: *const u16,
        chars_to_write: u32,
        chars_written: *mut u32,
        reserved: *mut std::ffi::c_void,
    ) -> i32;
    #[allow(non_snake_case)]
    fn GetConsoleScreenBufferInfo(
        console_output: *mut std::ffi::c_void,
        info: *mut ConsoleScreenBufferInfo,
    ) -> i32;
}

/// `SMALL_RECT`, as a caller of `GetConsoleScreenBufferInfo` sees them.
///
/// Four shorts, and the *far* corner is what carries a size: `Left`/`Top` are the
/// origin. Reading `Left` where a size was wanted gives `0`, which is why the
/// first version of this fixture reported a 1x1 window and called it a day.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SmallRect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}

/// `COORD`: two shorts and nothing else.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Coord {
    x: i16,
    y: i16,
}

/// `CONSOLE_SCREEN_BUFFER_INFO`.
///
/// Field order is the SDK's: `dwSize`, `dwCursorPosition`, `dwAttributes`,
/// `dwMaximumWindowSize`, `dwWindow`. The last two are the pair that is easy to
/// get backwards, and backwards is silent.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ConsoleScreenBufferInfo {
    size: SmallRect,
    cursor: Coord,
    attributes: u16,
    maximum_window_size: SmallRect,
    window: SmallRect,
}

/// The geometry a `--console-info` run should report.
///
/// Distinct from the 80x25 everything defaults to, on both axes, so an answer
/// that came from the payload's fallback cannot pass for one that came from the
/// host's screen.
pub const PROBE_COLS: u16 = 100;
pub const PROBE_ROWS: u16 = 30;

/// How many characters `--console-info` writes before asking where the cursor is.
///
/// Three, because the assertion is "the cursor moved by exactly this much", and a
/// number the test chose is worth more than one read back from somewhere else.
const PROBE_INFO_MOVES: usize = 3;

/// Reported when the published screen state never caught up with the write.
///
/// Distinct from every other exit code here, because "the answer was wrong" and
/// "there was no answer" are different failures.
const CONSOLE_INFO_UNSETTLED: u32 = 0x42;

/// How many consecutive identical cursor readings count as "the screen has
/// stopped moving".
const QUIET_POLLS: u32 = 4;

/// Reads the screen, once.
fn screen_info(handle: *mut std::ffi::c_void) -> Option<ConsoleScreenBufferInfo> {
    let mut info = ConsoleScreenBufferInfo::default();
    let ok = unsafe { GetConsoleScreenBufferInfo(handle, &mut info as *mut ConsoleScreenBufferInfo) };
    (ok != 0).then_some(info)
}

/// The host's geometry, or `None` if it never showed up.
fn is_host_geometry(info: &ConsoleScreenBufferInfo) -> bool {
    i32::from(info.window.right) + 1 == i32::from(PROBE_COLS)
        && i32::from(info.window.bottom) + 1 == i32::from(PROBE_ROWS)
}

/// Waits until the screen shows the host's geometry **and has stopped moving**.
///
/// The quiet part is not decoration. This probe's own log lines travel down the
/// same pipe as its output, and the host drains that pipe in chunks it chooses -
/// so a baseline taken the instant the geometry appears can still be followed by
/// a chunk of "probe: released\r\n", and the measured delta then includes the
/// fixture's own diagnostics. Waiting for the cursor to hold still removes the
/// fixture from its own measurement.
fn settled_baseline(handle: *mut std::ffi::c_void) -> Option<ConsoleScreenBufferInfo> {
    let mut last_x = i16::MIN;
    let mut quiet = 0u32;
    let mut found = None;
    for _ in 0..400 {
        let Some(info) = screen_info(handle) else {
            std::thread::sleep(std::time::Duration::from_millis(5));
            continue;
        };
        if is_host_geometry(&info) {
            found = Some(info);
            if info.cursor.x == last_x {
                quiet += 1;
                if quiet >= QUIET_POLLS {
                    return found;
                }
            } else {
                quiet = 0;
            }
            last_x = info.cursor.x;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    found
}

/// Reports where the screen says the cursor is, once the screen says so.
///
/// Four steps, and each one exists because the obvious version of it measures
/// the wrong thing:
///
/// 1. **Wait for the host's geometry, and for the screen to go quiet.** Until the
///    state has been published the answer is the payload's fallback, and a
///    fallback of 80x25 would sail through a test that never asked for 100x30.
/// 2. **Record where the cursor is.** What is comparable is a *delta*: the
///    probe's own log lines went down the same pipe as its output.
/// 3. **Write three characters.**
/// 4. **Wait for the cursor to catch up**, then report.
///
/// # Why the waits at all
///
/// The state is published, not fetched: the host writes it when it processes the
/// output, which is after the write has left the pipe. So the first query
/// legitimately sees the position from *before* the write. That is not a defect to
/// be asserted away - it is the documented cost of not answering synchronously -
/// and the property worth asserting is that the state **converges**. Polling for
/// it is the honest way to measure convergence; a fixed sleep would only be
/// measuring the machine's mood.
fn console_info() -> ! {
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };

    let baseline = settled_baseline(handle);
    let before = baseline.unwrap_or_default();

    write_console(handle, "abc");

    let want_x = before.cursor.x as i32 + PROBE_INFO_MOVES as i32;
    let mut last = before;
    let mut settled = false;
    for _ in 0..400 {
        if let Some(info) = screen_info(handle) {
            last = info;
            if info.cursor.x as i32 == want_x {
                settled = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    let report = format!(
        "info: cursor={},{} delta={} cols={} rows={} window={},{},{},{} baseline={} settled={}",
        last.cursor.x,
        last.cursor.y,
        last.cursor.x - before.cursor.x,
        last.window.right + 1,
        last.window.bottom + 1,
        last.window.left,
        last.window.top,
        last.window.right,
        last.window.bottom,
        baseline.is_some(),
        settled
    );
    // Trailing newline: this line arrives twice on the same pipe - once through
    // the shim, once through the probe's own stderr - and without a terminator the
    // two copies fuse into one unreadable line.
    write_console(handle, &format!("{report}\r\n"));
    eprintln!("probe: {report}");

    std::process::exit(if baseline.is_some() && settled { 0 } else { CONSOLE_INFO_UNSETTLED as i32 });
}

/// Writes `text` through `WriteConsoleW`, ignoring the result.
fn write_console(handle: *mut std::ffi::c_void, text: &str) {
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let chars = (wide.len() - 1) as u32;
    let mut written = 0u32;
    unsafe {
        WriteConsoleW(handle, wide.as_ptr(), chars, &mut written, std::ptr::null_mut())
    };
}

/// `STD_OUTPUT_HANDLE`.
const STD_OUTPUT_HANDLE: u32 = 0xffff_ffff;

/// Reported when `--console-write` was asked for and the console API refused.
///
/// Distinct from every other exit code here, and from zero, because "the console
/// write failed" and "the write succeeded" are the two ends of what this fixture
/// is measuring and they must not be confused with a spawn that never happened.
const CONSOLE_WRITE_FAILED: u32 = 0x41;

/// Writes `text` to stdout through `WriteConsoleW` and reports what happened.
///
/// This is the only way a program gets text onto a handle that is not a console,
/// so a program that uses it against our pipe gets `ERROR_INVALID_HANDLE` and no
/// output at all - which is the whole reason the payload substitutes the call.
/// The report line goes to stderr, which for a session is the same pipe, so the
/// test sees the verdict alongside whatever the write produced.
fn console_write(text: &str) -> ! {
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // The NUL is a terminator for the convenience of the reader, not part of the
    // text: `WriteConsoleW` counts characters, so it is excluded.
    let chars = (wide.len() - 1) as u32;
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut written = 0u32;
    let ok = unsafe {
        WriteConsoleW(handle, wide.as_ptr(), chars, &mut written, std::ptr::null_mut())
    };

    eprintln!(
        "probe: console-write ok={} written={written} of {chars} bytes={}",
        ok != 0,
        wide[..chars as usize].len() * 2
    );
    let good = ok != 0 && written == chars;
    std::process::exit(if good { 0 } else { CONSOLE_WRITE_FAILED as i32 });
}

/// Maps a flag name onto the `CreateProcessW` bit it stands for.
///
/// `CREATE_SUSPENDED` is deliberately absent: the probe has no way to resume a
/// child it did not create a thread for, and a suspended child would look like
/// a hung one. `STARTF_USESHOWWINDOW` is spelled out because
/// `CreateProcessW` rejects it without a valid `STARTUPINFOW`, which is a trap
/// worth keeping in the list.
fn parse_flag(name: &str) -> Option<u32> {
    Some(match name {
        "none" => 0,
        "detached" => DETACHED_PROCESS,
        "no_window" => CREATE_NO_WINDOW,
        "new_console" => CREATE_NEW_CONSOLE,
        "unicode_env" => CREATE_UNICODE_ENVIRONMENT,
        "show_window" => STARTF_USESHOWWINDOW,
        "suspended" => CREATE_SUSPENDED,
        _ => return None,
    })
}