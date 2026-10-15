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
//!                    [--pidfile <path>]
//!                    <flag>...  --  <command line>
//! ```
//!
//! `<flag>` is one of `detached`, `no_window`, `new_console`, `unicode_env`,
//! or `none`. Exits with the child's exit code, or `0xff` if the child could not
//! be created at all.

use std::ffi::c_void;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Console::GetStdHandle;
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
                unsafe { GetStdHandle(1) }
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