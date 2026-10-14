//! Terminal session lifecycle.
//!
//! A session wires the moving parts together and owns their lifetime:
//!
//! ```text
//!   host stdin  ──WriteFile──►  \\.\pipe\..-in   ──►  target stdin
//!   host stdout ◄──ReadFile───  \\.\pipe\..-out  ◄──  target stdout/stderr
//! ```
//!
//! Ordering that matters:
//!
//! 1. Create the pipe *servers* first; the target's ends are opened and marked
//!    inheritable before `CreateProcessW`
//!    ([`pipe::PipePair::open_target_stdio`]).
//! 2. Spawn the child suspended + detached with those handles, so its stdio is
//!    correct from the very first instruction (`STARTF_USESTDHANDLES`).
//! 3. Resume, then map the payload once `PEB->Ldr` is walkable. stdio is already
//!    live by then, so the payload only adds semantics (console shim,
//!    `ConsoleHandle` sentinel, CRT buffering) and can never lose a race.
//! 4. Pump until the output pipe reports EOF, then reap the exit code.
//!
//! Two threads do the blocking work: an output pump mirrors the `-out` server
//! onto the host's stdout, an input pump mirrors the host's stdin onto the `-in`
//! server. Both are overlapped so they can be torn down with `CancelIoEx`
//! instead of blocking on a read that will never complete.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::child::{contract, Child, ChildSpec, Stdio};
use crate::manual_map::{inject_into_child, InjectionReport};
use crate::pipe::{PipePair, ReadEvent, SharedPipes};

/// Tunables for a session. Defaults match a normal interactive terminal.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Where the payload comes from; `None` means "next to the host executable".
    pub dll: Option<std::path::PathBuf>,
    /// Read chunk used by the output pump.
    pub chunk: usize,
    /// When set, exported to the payload as `WBWPTY_LOG`.
    pub log_path: Option<std::path::PathBuf>,
    /// Install the console API shim in the target (`WBWPTY_SHIM`).
    pub shim: bool,
    /// Map the payload DLL at all. Injection only adds console semantics; the
    /// stdio redirection itself does not depend on it.
    pub inject: bool,
    /// Report injection and shim decisions on stderr.
    pub verbose: bool,
    /// Virtual terminal geometry reported to the payload.
    pub rows: u16,
    pub cols: u16,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            dll: None,
            chunk: 16 * 1024,
            log_path: None,
            shim: true,
            inject: true,
            verbose: false,
            rows: 25,
            cols: 80,
        }
    }
}

/// A live terminal session.
///
/// Dropping a session terminates the target, so a panic anywhere above cannot
/// leave an orphaned `cmd.exe` behind.
pub struct Session {
    child: Child,
    pipes: Arc<SharedPipes>,
    config: SessionConfig,
    report: Option<InjectionReport>,
    /// RVA of the payload's exported WBWPTY_STATUS word, resolved at start.
    status_rva: Option<u32>,
    shutting_down: Arc<AtomicBool>,
}

impl Session {
    /// Builds a session for `spec`: spawns the target, injects the payload and
    /// starts the input pump.
    ///
    /// Injection is best effort. stdio is already correct thanks to
    /// `STARTF_USESTDHANDLES`, so a payload that fails to map degrades to "a
    /// plainly piped target" rather than a broken session; the reason is
    /// reported and the caller decides whether that is fatal.
    pub fn start(spec: &ChildSpec, config: SessionConfig) -> Result<Self> {
        let mut pipes = PipePair::new(nonce())?;
        let mut stdio = pipes.open_target_stdio()?;

        let mut spec = spec.clone();
        spec.stdio = Some(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        });
        spec.env
            .push((contract::ENV_ROWS.into(), config.rows.to_string()));
        spec.env
            .push((contract::ENV_COLS.into(), config.cols.to_string()));
        spec.env.push((
            contract::ENV_SHIM.into(),
            if config.shim { "1" } else { "0" }.into(),
        ));
        if let Some(log) = &config.log_path {
            spec.env
                .push((contract::ENV_LOG.into(), log.display().to_string()));
        }

        let child = Child::spawn(&spec).context("spawning target")?;
        // The child now owns its own inherited copies; ours would otherwise keep
        // a writer alive on `-out` and suppress EOF forever.
        stdio.release();

        // The target must run whether or not we manage to patch it. Resuming is
        // therefore done here, and injection is layered on top.
        let report = match inject_payload(&child, &config) {
            Some(report) => Some(report),
            None => {
                if !child.is_resumed() {
                    child.resume().context("resuming target")?;
                }
                None
            }
        };

        // Resolve the status word RVA once so `payload_status()` can read it later.
        let dll_path = config
            .dll
            .clone()
            .or_else(|| std::env::var("WBWPTY_DLL").ok().map(std::path::PathBuf::from))
            .unwrap_or_else(default_dll_path);
        let status_rva = std::fs::read(&dll_path)
            .ok()
            .and_then(|file| crate::manual_map::find_export_rva(&file, "WBWPTY_STATUS").ok().flatten());

        let session = Self {
            child,
            pipes: Arc::new(SharedPipes::new(pipes)),
            config,
            report,
            status_rva,
            shutting_down: Arc::new(AtomicBool::new(false)),
        };
        session.start_input_pump();
        Ok(session)
    }

    /// The payload report, present only when the DLL mapped successfully.
    pub fn report(&self) -> Option<&InjectionReport> {
        self.report.as_ref()
    }

    /// Reads the payload's `WBWPTY_STATUS` word out of the target.
    ///
    /// The injected thread dies on an exception when the attach path faults, and
    /// that tells us nothing about *where*; the status word is how far it got.
    pub fn payload_status(&self) -> Option<u32> {
        use crate::manual_map::remote::RemoteProcess;
        let report = self.report.as_ref()?;
        let rva = self.status_rva?;
        let proc = RemoteProcess::new(self.child.process_handle());
        let bytes = proc.read_bytes(report.image_base + rva as u64, 4).ok()?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    pub fn pid(&self) -> u32 {
        self.child.pid
    }

    /// Starts a thread mirroring the host's stdin into the `-in` pipe.
    ///
    /// Host stdin EOF must reach the target as a *pipe* EOF, which only happens
    /// once our write handle is closed - hence the explicit drop at the end
    /// rather than just returning from the loop.
    fn start_input_pump(&self) {
        let pipes = Arc::clone(&self.pipes);
        let shutting_down = Arc::clone(&self.shutting_down);

        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 4096];
            loop {
                if shutting_down.load(Ordering::Relaxed) {
                    break;
                }
                match stdin.read(&mut buf) {
                    Ok(0) => break, // host stdin closed: deliver EOF to the target
                    Ok(n) => {
                        let failed = pipes
                            .with(|p| p.input().write_all(&buf[..n]).is_err())
                            .unwrap_or(true);
                        if failed {
                            break; // target is gone
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            // Closing the `-in` server is what the target sees as stdin EOF.
            pipes.with(|p| p.input().close());
        });
    }

    /// Mirrors the target's output onto the host's stdout until the pipe closes.
    ///
    /// Returns once every writer to `-out` is gone, which is also how the target
    /// exiting is detected.
    pub fn pump_output(&self) -> Result<()> {
        let mut buf = vec![0u8; self.config.chunk.max(1024)];
        let mut stdout = std::io::stdout();

        loop {
            let read = self
                .pipes
                .with(|p| p.output().read(&mut buf, 100))
                .ok_or_else(|| anyhow::anyhow!("session pipe lock poisoned"))?;
            match read? {
                ReadEvent::Data(n) => {
                    stdout
                        .write_all(&buf[..n])
                        .context("writing target output")?;
                    stdout.flush().ok();
                }
                ReadEvent::Timeout => continue,
                ReadEvent::Eof => return Ok(()),
            }
        }
    }

    /// Signals stdin EOF to the target and waits for it to exit.
    ///
    /// Returns `None` when the target is already gone, which is not an error:
    /// `pump_output` returning is the normal way a session ends.
    pub fn wait(&self) -> Option<u32> {
        self.child.wait().ok()
    }

    /// Runs the whole session on the calling thread: output until EOF, then the
    /// exit code. This is the entry point the CLI uses.
    pub fn run_to_completion(self) -> Result<u32> {
        self.pump_output()?;
        let code = self
            .child
            .wait_timeout(std::time::Duration::from_secs(2))
            .unwrap_or(None);
        Ok(code.unwrap_or(0))
    }

    /// Terminates the target and stops the pumps.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        let _ = self.child.terminate();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        // Best effort: a detached target would otherwise outlive the host.
        let _ = self.child.terminate();
    }
}

/// Maps the payload into `child`, returning the report or `None`.
///
/// Injection is an *enhancement*: stdio is already correct because the pipes
/// were handed over at creation time, so a target that is too short lived to be
/// patched is not a failure. Two cases are expected and must stay quiet:
///
/// * the target already exited (`cmd /c echo hi` finishes in milliseconds, long
///   before the module list can settle),
/// * the payload could not be resolved at all.
///
/// Both are reported through `WBWPTY_LOG`/stderr only when `verbose` is set.
fn inject_payload(child: &Child, config: &SessionConfig) -> Option<InjectionReport> {
    if !config.inject {
        return None;
    }
    // Injection must observe a *running* target (the loader has to have mapped
    // its modules), so resume first; a dead target cannot be patched and trying
    // produces nothing but noise.
    if !child.is_resumed() {
        if let Err(err) = child.resume() {
            if config.verbose {
                eprintln!("wbwpty: could not resume target: {err:#}");
            }
            return None;
        }
    }
    if !child.is_running() {
        if config.verbose {
            eprintln!("wbwpty: target already exited; skipping payload injection");
        }
        return None;
    }

    let dll = config.dll.clone().unwrap_or_else(default_dll_path);
    match inject_into_child(child, &dll, "DllMain") {
        Ok(report) => Some(report),
        Err(err) => {
            if config.verbose {
                eprintln!("wbwpty: payload not mapped ({}): {err:#}", dll.display());
            }
            None
        }
    }
}

/// `wbwpty_redirect.dll` next to the running executable, unless `WBWPTY_DLL`
/// overrides it.
fn default_dll_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("WBWPTY_DLL") {
        return std::path::PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("wbwpty_redirect.dll")))
        .unwrap_or_else(|| std::path::PathBuf::from("wbwpty_redirect.dll"))
}

/// Per-session unique nonce for pipe names.
fn nonce() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix in the pid so two sessions started in the same nanosecond still differ.
    nanos ^ (std::process::id() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::ReadEvent;

    /// Nonce must differ between calls or two live sessions would collide on
    /// pipe names.
    #[test]
    fn nonce_is_not_constant() {
        assert_ne!(nonce(), nonce());
    }

    /// The whole stack end to end: pipes, suspended+detached target, std handles
    /// by inheritance, output mirroring and exit code.
    ///
    /// Injection is off here on purpose: `cmd /c echo` lives for milliseconds,
    /// which is shorter than the loader settle window, so asking for a payload
    /// report would only test that we can race a dying process.
    #[test]
    fn runs_a_command_and_mirrors_its_output() {
        let spec = ChildSpec::new("cmd.exe").args(["/c", "echo wbwpty-session-ok"]);
        let config = SessionConfig { shim: false, inject: false, ..Default::default() };
        let session = Session::start(&spec, config).unwrap();

        // Read what the target printed straight off the pipe.
        let mut buf = [0u8; 256];
        let mut text = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let event = session
                .pipes
                .with(|p| p.output().read(&mut buf, 200))
                .unwrap();
            match event {
                Ok(ReadEvent::Data(n)) => text.push_str(&String::from_utf8_lossy(&buf[..n])),
                Ok(ReadEvent::Eof) => break,
                Ok(ReadEvent::Timeout) => {}
                Err(e) => panic!("output read failed: {e:#}"),
            }
            if text.contains("wbwpty-session-ok") {
                break;
            }
        }
        assert!(
            text.contains("wbwpty-session-ok"),
            "target output not mirrored, got {text:?}"
        );

        let code = session.wait().expect("target exited");
        assert_eq!(code, 0, "cmd /c echo should exit 0");
    }

    /// The payload must map into a real target without killing it; the report
    /// is what the CLI surfaces and what proves injection still works after the
    /// trampoline was removed.
    #[test]
    fn payload_maps_into_a_live_target() {
        let mut pipes = crate::pipe::PipePair::new(0x11_0005).unwrap();
        let mut stdio = pipes.open_target_stdio().unwrap();
        let spec = ChildSpec::new("cmd.exe").stdio(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        });
        let config = SessionConfig { shim: false, verbose: true, inject: true, ..Default::default() };
        let inject_flag = config.inject;
        let session = Session::start(&spec, config).unwrap();

        let report = session.report();
        eprintln!("DIAG inject={inject_flag}");
        eprintln!("DIAG report={:?}", report.map(|r| r.image_base));
        eprintln!("DIAG status={:#x}", session.payload_status().unwrap_or(0));
        eprintln!("DIAG child_running={}", session.child.is_running());
        let report = report
            .expect("payload should map into a running cmd.exe");
        assert!(report.image_base != 0);
        assert!(report.patch_count > 0, "imports must be resolved");
        assert!(session.child.is_running(), "target survived DllMain");

        session.shutdown();
    }

    /// The `ConsoleHandle` sentinel must actually be in the target's PEB.
    ///
    /// This is the mechanism that stops descendants from being allocated a
    /// console (and therefore from spawning `conhost.exe`), so it is asserted
    /// directly on the target's own `RTL_USER_PROCESS_PARAMETERS` rather than
    /// inferred from a process count - a count measured from inside the test
    /// harness is polluted by whatever console the harness itself runs in.
    #[test]
    fn payload_makes_the_target_look_like_it_has_a_console() {
        let log = std::env::temp_dir().join("wbwpty-test-console.log");
        let _ = std::fs::remove_file(&log);
        let _ = std::fs::write(&log, b"");

        let spec = ChildSpec::new("cmd.exe");
        let config = SessionConfig {
            shim: false,
            log_path: Some(log.clone()),
            ..Default::default()
        };
        let session = Session::start(&spec, config).unwrap();
        let report = session
            .report()
            .expect("payload must map before its PEB patch can be observed");
        eprintln!(
            "DIAG image_base={:#x} entry_rva={:#x} patches={} modules={} wait={}ms",
            report.image_base,
            report.entry_rva,
            report.patch_count,
            report.module_count,
            report.loader_wait_ms
        );

        let proc = crate::manual_map::remote::RemoteProcess::new(session.child.process_handle());
        let handle = proc.console_handle().expect("target process parameters are readable");
        let dll_log = std::fs::read_to_string(&log).unwrap_or_default();
        eprintln!("DIAG console_handle={handle:#x}");
        eprintln!("DIAG log={dll_log:?}");
        eprintln!("DIAG status={:#x}", session.payload_status().unwrap_or(0));
        assert_ne!(
            handle, 0,
            "ConsoleHandle must be non-null or descendants get a real console; \
             payload log was:\n{dll_log}"
        );

        session.shutdown();
    }

    /// End to end: a grandchild spawned by the target must write to our pipe.
    ///
    /// The target is an interactive `cmd.exe` that is blocked reading its
    /// (never written) stdin, which makes the ordering deterministic: injection
    /// completes first, and only then is a command fed in. Feeding a command to
    /// `cmd /c` immediately would race the injection and prove nothing.
    ///
    /// `conhost.exe` is deliberately *not* counted here: the test harness itself
    /// runs in a console, so the machine-wide count moves for reasons unrelated
    /// to the target. The no-console-host claim is verified by the CLI's
    /// `--dump-conhost` acceptance run instead, where the surroundings are known.
    #[test]
    fn grandchild_output_reaches_the_pipe() {
        let spec = ChildSpec::new("cmd.exe");
        let config = SessionConfig { shim: false, ..Default::default() };
        let session = Session::start(&spec, config).unwrap();
        session
            .report()
            .expect("payload must map before the descendant behaviour is meaningful");

        let _ = session
            .pipes
            .with(|p| p.input().write_all(b"cmd.exe /c echo wbwpty-grandchild-ok\r\n"))
            .expect("pipe write");

        // Read until the grandchild's line shows up.
        let mut buf = [0u8; 4096];
        let mut text = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline && !text.contains("wbwpty-grandchild-ok") {
            match session.pipes.with(|p| p.output().read(&mut buf, 200)).unwrap() {
                Ok(ReadEvent::Data(n)) => text.push_str(&String::from_utf8_lossy(&buf[..n])),
                Ok(ReadEvent::Eof) => break,
                Ok(ReadEvent::Timeout) => {}
                Err(e) => panic!("output read failed: {e:#}"),
            }
        }
        assert!(
            text.contains("wbwpty-grandchild-ok"),
            "grandchild output never arrived; saw {text:?}"
        );

        session.shutdown();
    }

    /// stdio must work with injection disabled: that is the whole point of
    /// handing the pipes over at creation instead of installing them from
    /// inside the payload.
    #[test]
    fn stdio_works_without_injection() {
        let spec = ChildSpec::new("cmd.exe").args(["/c", "echo no-inject-ok"]);
        let config = SessionConfig { shim: false, inject: false, ..Default::default() };
        let session = Session::start(&spec, config).unwrap();
        assert!(session.report().is_none(), "injection was disabled");

        let mut buf = [0u8; 256];
        let mut text = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match session.pipes.with(|p| p.output().read(&mut buf, 200)).unwrap() {
                Ok(ReadEvent::Data(n)) => text.push_str(&String::from_utf8_lossy(&buf[..n])),
                Ok(ReadEvent::Eof) => break,
                Ok(ReadEvent::Timeout) => {}
                Err(e) => panic!("output read failed: {e:#}"),
            }
            if text.contains("no-inject-ok") {
                break;
            }
        }
        assert!(text.contains("no-inject-ok"), "output missing, got {text:?}");
    }
}
