//! Target process creation.
//!
//! Two flags carry the whole "no conhost.exe" promise:
//!
//! * `DETACHED_PROCESS` — the *only* creation flag that stops the base API from
//!   allocating a console session, and therefore the only one that stops
//!   `conhost.exe` from being spawned. `CREATE_NO_WINDOW` and
//!   `CREATE_NEW_CONSOLE` both still spawn a console host.
//! * `CREATE_SUSPENDED` — the initial thread has not run a single instruction
//!   yet (not even `ntdll!LdrInitializeThunk`), which is what makes the window
//!   between "process exists" and "we inject" race free.
//!
//! The environment block is built by the host and carries the pipe names plus
//! the virtual terminal geometry; that block is the only channel the injected
//! DLL needs (see the `contract` module for the published variable names).

use std::ffi::{c_void, OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, STARTUPINFOW,
};

/// `SW_MINIMIZE`, `winuser.h`. Spelled out because the `Win32::UI` feature of
/// `windows-sys` is not enabled in this crate, and the value is one line of the
/// platform SDK rather than something to be re-derived.
const SW_MINIMIZE: i32 = 2;

use crate::error::{last_error_text, Handle};
use crate::manual_map::remote::{ConsolePatch, RemoteProcess};

/// Published environment variable contract between the host and the injected
/// DLL. Renaming any of these silently breaks every already built DLL, so they
/// are frozen (see AGENTS.md rule "环境变量契约").
pub mod contract {
    /// `\\.\pipe\wbwpty-*-in`: host writes, target reads (target stdin).
    pub const ENV_IN: &str = "WBWPTY_IN";
    /// `\\.\pipe\wbwpty-*-out`: target writes, host reads (target stdout/stderr).
    pub const ENV_OUT: &str = "WBWPTY_OUT";
    /// `\\.\pipe\wbwpty-*-ctl`: bidirectional resize/control channel.
    pub const ENV_CTL: &str = "WBWPTY_CTL";
    /// Virtual terminal height in cells.
    pub const ENV_ROWS: &str = "WBWPTY_ROWS";
    /// Virtual terminal width in cells.
    pub const ENV_COLS: &str = "WBWPTY_COLS";
    /// Target code page override; `0` means "leave whatever the target picks".
    pub const ENV_CP: &str = "WBWPTY_CP";
    /// `1` installs the console API shim, `0` leaves the target untouched.
    pub const ENV_SHIM: &str = "WBWPTY_SHIM";
    /// Optional log file path the DLL appends diagnostics to.
    pub const ENV_LOG: &str = "WBWPTY_LOG";
}

/// Creation flags shared by every target launch.
pub const TARGET_CREATION_FLAGS: u32 =
    DETACHED_PROCESS | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;

/// The three standard handles handed to the target at creation time.
///
/// Passing the real pipe handles through `STARTF_USESTDHANDLES` is what makes
/// the redirection race free: `ucrtbase!__acrt_initialize_stdio` reads them
/// with `GetStdHandle` on its very first call, so it can never observe a
/// half-installed state no matter when the payload is mapped.
#[derive(Debug, Clone, Copy)]
pub struct Stdio {
    pub stdin: HANDLE,
    pub stdout: HANDLE,
    pub stderr: HANDLE,
}

/// What to run and how to hand it its configuration.
#[derive(Debug, Clone)]
pub struct ChildSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// Extra environment entries; they win over inherited ones.
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    /// Standard handles to inherit; `None` starts the target with NULL std
    /// handles, which is only useful for tests that never do I/O.
    pub stdio: Option<Stdio>,
    /// `wShowWindow` for the target's first window, via `STARTF_USESHOWWINDOW`.
    ///
    /// Not a way to hide a failure. A target that allocates a console anyway will
    /// still allocate one; this only decides whether the very first one that
    /// exists starts minimised. It exists because a test that provokes a console
    /// on purpose should not steal the user's focus while doing it - the console
    /// existing is the finding, and the assertion is still expected to fail
    /// (AGENTS §12).
    pub show_window: Option<i32>,
}

impl ChildSpec {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            stdio: None,
            show_window: None,
        }
    }

    /// Starts the target's first window minimised rather than hidden.
    pub fn minimized(mut self) -> Self {
        self.show_window = Some(SW_MINIMIZE);
        self
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.push((key.to_owned(), value.into()));
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Hands the target these standard handles.
    ///
    /// The handles must be inheritable; see [`crate::pipe::PipePair`] for the
    /// helper that opens pipe ends and marks them so.
    pub fn stdio(mut self, stdio: Stdio) -> Self {
        self.stdio = Some(stdio);
        self
    }

    /// Resolves `program` to a concrete path, mirroring what the shell would do:
    /// an explicit path is used as is, otherwise `PATH`/`PATHEXT` are searched.
    pub fn resolve_program(&self) -> Result<PathBuf> {
        let raw = Path::new(&self.program);
        if raw.components().count() > 1 || self.program.to_string_lossy().contains('\\') {
            let abs = absolutize(raw);
            if abs.is_file() {
                return Ok(abs);
            }
            bail!("program not found: {}", abs.display());
        }

        let name = self.program.to_string_lossy().to_lowercase();
        let extensions: Vec<String> = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(|e| e.to_lowercase())
            .collect();

        for dir in std::env::var("PATH").unwrap_or_default().split(';') {
            if dir.is_empty() {
                continue;
            }
            let dir = Path::new(dir);
            if extensions.is_empty() || !name.contains('.') {
                for ext in &extensions {
                    let candidate = dir.join(format!("{name}{ext}"));
                    if candidate.is_file() {
                        return Ok(absolutize(&candidate));
                    }
                }
            }
            let candidate = dir.join(&self.program);
            if candidate.is_file() {
                return Ok(absolutize(&candidate));
            }
        }

        bail!(
            "program not found on PATH: {}",
            self.program.to_string_lossy()
        )
    }
}

/// A suspended, console-less target process.
pub struct Child {
    process: Handle,
    thread: Handle,
    pub pid: u32,
    pub image: PathBuf,
    resumed: std::sync::atomic::AtomicBool,
    /// Outcome of the console sentinel write that [`Child::spawn`] performed
    /// before the target ran a single instruction.
    ///
    /// `Err` is deliberately not fatal: `DETACHED_PROCESS` already guarantees
    /// the direct child never gets a console, so a failed patch only means
    /// descendants may be allocated one.
    pub console_patch: Result<ConsolePatch, String>,
}

/// `GetExitCodeProcess` reports this for a process that has not exited.
const STILL_ACTIVE: u32 = 259;

impl Child {
    /// Creates the process suspended. Nothing in it has executed yet.
    pub fn spawn(spec: &ChildSpec) -> Result<Self> {
        let image = spec.resolve_program()?;
        let image_wide = wide(image.as_os_str());
        let mut command_line = build_command_line(&image, &spec.args);
        let environment = build_environment_block(&spec.env)?;
        let cwd_wide: Option<Vec<u16>> = match &spec.cwd {
            Some(d) => Some(wide(d.as_os_str())),
            None => std::env::current_dir().ok().map(|d| wide(d.as_os_str())),
        };

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        // Without a `Stdio` the target starts with NULL standard handles, which
        // is only ever what a test wants. Real sessions always pass the pipes,
        // which makes the redirection deterministic (see [`Stdio`]).
        let inherit_handles = spec.stdio.is_some();
        if let Some(stdio) = spec.stdio {
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = stdio.stdin;
            si.hStdOutput = stdio.stdout;
            si.hStdError = stdio.stderr;
        }
        if let Some(show) = spec.show_window {
            si.dwFlags |= STARTF_USESHOWWINDOW;
            si.wShowWindow = show as u16;
        }

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SAFETY: `command_line` is a mutable NUL terminated buffer, `env` and
        // `cwd_wide` are NUL terminated blocks; all stay alive across the call.
        let ok = unsafe {
            CreateProcessW(
                image_wide.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                if inherit_handles { 1 } else { 0 },
                TARGET_CREATION_FLAGS,
                environment.as_ptr() as *const c_void,
                cwd_wide.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                &mut si,
                &mut pi,
            )
        };

        if ok == 0 {
            return Err(anyhow!(
                "CreateProcessW({}) failed: {}",
                image.display(),
                last_error_text()
            ))
            .context("spawning target");
        }

        // Close the thread handle on failure paths only after we own both.
        let mut child = Self {
            process: Handle::from_raw(pi.hProcess as isize),
            thread: Handle::from_raw(pi.hThread as isize),
            pid: pi.dwProcessId,
            image,
            resumed: std::sync::atomic::AtomicBool::new(false),
            console_patch: Err("not attempted".to_owned()),
        };

        // Last chance before the target executes anything: make it hand its
        // children this session's pipes instead of a console of their own.
        // Doing this here rather than from the injected DLL is what makes it
        // work for short-lived targets - `cmd /c <short command>` exits long
        // before a payload could be mapped, and that is exactly when a
        // descendant console host shows up.
        child.console_patch = RemoteProcess::new(child.process_handle())
            .patch_console_state()
            .map_err(|err| format!("{err:#}"));

        Ok(child)
    }

    /// Lets the loader run. Everything the injected DLL prepared stays in
    /// place because nothing in the target has executed yet.
    ///
    /// Idempotent: the session owns the lifecycle and both the caller and
    /// [`crate::manual_map::inject_into_child`] may want to make sure the
    /// target is running.
    pub fn resume(&self) -> Result<()> {
        if self.resumed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        // SAFETY: `hThread` is the suspended primary thread we own.
        let previous = unsafe { ResumeThread(self.thread.as_raw() as HANDLE) };
        if previous == u32::MAX {
            bail!("ResumeThread failed: {}", last_error_text());
        }
        Ok(())
    }

    /// True once [`Self::resume`] has been called on this child.
    pub fn is_resumed(&self) -> bool {
        self.resumed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// True while the target process has not exited yet.
    pub fn is_running(&self) -> bool {
        let mut code = 0u32;
        // SAFETY: we own `process` and `code` is a live local.
        let ok = unsafe { GetExitCodeProcess(self.process.as_raw() as HANDLE, &mut code) };
        ok != 0 && code == STILL_ACTIVE
    }

    /// Waits for the target and returns its exit code.
    pub fn wait(&self) -> Result<u32> {
        // SAFETY: we own `process`.
        let wr = unsafe { WaitForSingleObject(self.process.as_raw() as HANDLE, INFINITE) };
        if wr != 0 {
            bail!(
                "WaitForSingleObject(process) returned {wr}: {}",
                last_error_text()
            );
        }
        self.exit_code()
    }

    /// Waits up to `timeout` for the target to exit.
    ///
    /// `Ok(None)` means it is still running, which is a normal outcome for an
    /// interactive session rather than an error.
    pub fn wait_timeout(&self, timeout: std::time::Duration) -> Result<Option<u32>> {
        // SAFETY: we own `process`.
        let wr = unsafe {
            WaitForSingleObject(self.process.as_raw() as HANDLE, timeout.as_millis() as u32)
        };
        Ok(match wr {
            WAIT_OBJECT_0 => Some(self.exit_code()?),
            WAIT_TIMEOUT => None,
            other => bail!(
                "WaitForSingleObject(process) returned {other}: {}",
                last_error_text()
            ),
        })
    }

    /// The exit code of an already terminated target.
    fn exit_code(&self) -> Result<u32> {
        let mut code = 0u32;
        // SAFETY: we own the process handle and `code` is a live local.
        let ok = unsafe { GetExitCodeProcess(self.process.as_raw() as HANDLE, &mut code) };
        if ok == 0 {
            bail!("GetExitCodeProcess failed: {}", last_error_text());
        }
        Ok(code)
    }

    /// Kills the target; used by the session watchdog and by Ctrl+C handling.
    pub fn terminate(&self) -> Result<()> {
        // SAFETY: we own `process`.
        let ok = unsafe { TerminateProcess(self.process.as_raw() as HANDLE, 0xC000_013A) };
        if ok == 0 {
            bail!("TerminateProcess failed: {}", last_error_text());
        }
        Ok(())
    }

    pub fn process_handle(&self) -> HANDLE {
        self.process.as_raw() as HANDLE
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // `Handle` closes both handles; nothing else is required because the
        // caller owns the lifetime policy.
    }
}

/// Builds a `CreateProcessW` command line using the quoting rules the CRT
/// `CommandLineToArgvW` expects (backslashes are only special before a quote).
pub fn build_command_line(image: &Path, args: &[OsString]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    append_quoted(&mut out, image.as_os_str());
    for arg in args {
        out.push(b' ' as u16);
        append_quoted(&mut out, arg);
    }
    out.push(0);
    out
}

fn append_quoted(out: &mut Vec<u16>, arg: &OsStr) {
    let wide: Vec<u16> = arg.encode_wide().collect();
    let needs_quotes = wide.is_empty()
        || wide
            .iter()
            .any(|&c| c == b' ' as u16 || c == b'\t' as u16 || c == b'"' as u16 || c < 0x20);

    if !needs_quotes {
        out.extend_from_slice(&wide);
        return;
    }

    out.push(b'"' as u16);
    let mut backslashes = 0usize;
    for &c in &wide {
        if c == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if c == b'"' as u16 {
            // Double every run of backslashes, then escape the quote itself.
            out.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2 + 1));
        } else {
            out.extend(std::iter::repeat(b'\\' as u16).take(backslashes));
        }
        backslashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2));
    out.push(b'"' as u16);
}

/// Merges the inherited environment with `overrides` into the double NUL
/// terminated block `CREATE_UNICODE_ENVIRONMENT` expects.
pub fn build_environment_block(overrides: &[(String, String)]) -> Result<Vec<u16>> {
    let mut block: Vec<u16> = Vec::with_capacity(4096);

    for (key, value) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        if overrides.iter().any(|(k, _)| k.eq_ignore_ascii_case(&key)) {
            continue; // overridden below
        }
        push_entry(&mut block, &key, &value.to_string_lossy());
    }
    for (key, value) in overrides {
        push_entry(&mut block, key, value);
    }

    block.push(0); // end of environment
    if block.len() > 0x8000 {
        bail!("environment block too large ({} u16)", block.len());
    }
    Ok(block)
}

fn push_entry(block: &mut Vec<u16>, key: &str, value: &str) {
    block.extend(key.encode_utf16());
    block.push(b'=' as u16);
    block.extend(value.encode_utf16());
    block.push(0);
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| p.to_path_buf(), |d| d.join(p))
    }
}

/// Best effort `MAX_PATH`-sized path helper kept for diagnostics.
pub fn max_path() -> usize {
    MAX_PATH as usize
}

/// Closes a raw handle; kept public so the injector can release its own handles
/// without going through [`Child`].
pub fn close_handle(h: HANDLE) {
    if !h.is_null() && h as isize != -1 {
        // SAFETY: caller guarantees ownership.
        unsafe { CloseHandle(h) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_quoting_follows_msvc_rules() {
        assert_eq!(
            String::from_utf16(&build_command_line(Path::new("cmd.exe"), &[])[..3]).unwrap(),
            "cmd"
        );

        let line = build_command_line(
            Path::new("C:\\a b\\x.exe"),
            &[
                OsString::from("plain"),
                OsString::from("with space"),
                OsString::from(r#"quote"and\slash"#),
            ],
        );
        let s = String::from_utf16(&line[..line.len() - 1]).unwrap();
        // A backslash is only special when it immediately precedes a quote, so
        // `quote"and\slash` becomes `"quote\"and\slash"`, not `\\slash`.
        assert_eq!(s, r#""C:\a b\x.exe" plain "with space" "quote\"and\slash""#);
    }

    #[test]
    fn empty_argument_survives_as_quotes() {
        let line = build_command_line(Path::new("x.exe"), &[OsString::from("")]);
        let s = String::from_utf16(&line[..line.len() - 1]).unwrap();
        assert_eq!(s, r#"x.exe """#);
    }

    #[test]
    fn environment_overrides_win_over_inherited() {
        let block = build_environment_block(&[("PATH".into(), "Z:\\only".into())]).unwrap();
        assert!(block.ends_with(&[0, 0]));
        let text: String = String::from_utf16(&block[..block.len() - 1])
            .unwrap()
            .replace('\0', "\n");
        assert!(text.lines().any(|l| l == "PATH=Z:\\only"), "{text}");
    }

    /// End to end check of the creation flags: `cmd.exe` must accept
    /// `DETACHED_PROCESS | CREATE_SUSPENDED` and run to completion once
    /// resumed. Its output goes nowhere on purpose - the pipes only exist after
    /// the DLL has been injected.
    #[test]
    fn spawns_suspended_then_resumes_to_completion() {
        let spec = ChildSpec::new("cmd.exe")
            .args(["/c", "exit", "0"])
            .env("WBWPTY_TEST", "1");
        let child = Child::spawn(&spec).expect("spawn cmd.exe");
        assert!(child.pid != 0);
        child.resume().unwrap();
        assert_eq!(child.wait().unwrap(), 0);
    }
}
