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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// How far the injected payload's attach path got.
///
/// Mirrors `wbwpty-redirect`'s `stage` module. The two crates cannot depend on
/// each other - one is the payload, one is its injector - so the mapping is
/// written out twice and [`PayloadStatus`] is the only thing that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadStage {
    /// The image is mapped but none of our code has run.
    Idle,
    /// `DllMain` was entered.
    Entered,
    /// `ConsoleHandle` was written with the sentinel.
    ConsolePatched,
    /// `ConsoleHandle` was already non-null and was left alone.
    ConsoleAlreadySet,
    /// The PEB could not be read; nothing was changed.
    ConsoleSkipped,
    /// The attach path ran to completion.
    Done,
    /// A value this build does not know about.
    Unknown(u32),
}

impl PayloadStage {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Idle,
            1 => Self::Entered,
            2 => Self::ConsolePatched,
            3 => Self::ConsoleAlreadySet,
            4 => Self::ConsoleSkipped,
            5 => Self::Done,
            other => Self::Unknown(other),
        }
    }
}

/// The payload's `WBWPTY_STATUS` word, decoded.
///
/// Low half is [`PayloadStage`], high half is the `fdwReason` `DllMain` was
/// entered with. `fdwReason` is what separates "the stub passed arguments
/// correctly" from "it passed garbage, so every attach path was skipped, and
/// `DllMain` returned TRUE anyway" - a failure with no other symptom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadStatus {
    pub stage: PayloadStage,
    pub reason: u32,
}

impl PayloadStatus {
    /// Splits a raw status word.
    pub fn decode(raw: u32) -> Self {
        Self {
            stage: PayloadStage::from_raw(raw & 0xffff),
            reason: raw >> 16,
        }
    }

    /// True when `DllMain` ran its `DLL_PROCESS_ATTACH` path rather than
    /// skipping it because it was handed a bogus reason.
    pub fn ran_attach_path(self) -> bool {
        self.reason == 1
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
    /// Console sentinel state after the post-injection re-assert.
    console_patch: Result<crate::manual_map::ConsolePatch, String>,
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

        // `Child::spawn` had the last word while the target was suspended, but it
        // does not keep it. Measured on this machine: a target created
        // `DETACHED_PROCESS | STARTF_USESTDHANDLES` comes up with
        // `ConsoleHandle == INVALID_HANDLE_VALUE` and then normalises the field
        // to null later in its own startup - *after* the loader has finished,
        // which is the earliest the payload can run. A null handle is exactly
        // what makes the base API allocate a console for every process the
        // target creates, so the sentinel is written again once the target has
        // settled.
        let console_patch = crate::manual_map::remote::RemoteProcess::new(child.process_handle())
            .patch_console_state()
            .map_err(|err| format!("{err:#}"));

        let session = Self {
            child,
            pipes: Arc::new(SharedPipes::new(pipes)),
            config,
            report,
            status_rva,
            console_patch,
            shutting_down: Arc::new(AtomicBool::new(false)),
        };
        session.start_input_pump();

        session.describe_console_state();
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

    /// The same word, decoded.
    pub fn payload_stage(&self) -> Option<PayloadStatus> {
        self.payload_status().map(PayloadStatus::decode)
    }

    pub fn pid(&self) -> u32 {
        self.child.pid
    }

    /// Prints the target's console bookkeeping, if it can be read.
    ///
    /// This is the state the "descendants inherit our pipes" behaviour actually
    /// rests on: `ConsoleHandle` has to be non-null, and `StandardOutput` has to
    /// be one of ours. `ConsoleFlags` is printed next to it because it is what
    /// the base API uses to choose between console inheritance and handle
    /// inheritance when the target creates its own children.
    pub fn describe_console_state(&self) {
        if !self.config.verbose {
            return;
        }
        use crate::manual_map::remote::RemoteProcess;
        let proc = RemoteProcess::new(self.child.process_handle());
        let state = (|| -> anyhow::Result<String> {
            Ok(format!(
                "console_handle={:#x} console_flags={:#x} standard_output={:#x}",
                proc.console_handle()?,
                proc.console_flags()?,
                proc.standard_output()?,
            ))
        })();
        match state {
            Ok(text) => eprintln!("wbwpty: pid {} {text}", self.child.pid),
            Err(err) => eprintln!(
                "wbwpty: pid {} console state unreadable: {err:#}",
                self.child.pid
            ),
        }
        match &self.console_patch {
            Ok(patch) => eprintln!("wbwpty: pid {} sentinel {patch:?}", self.child.pid),
            Err(err) => eprintln!("wbwpty: pid {} sentinel not applied: {err}", self.child.pid),
        }
        match self.payload_stage() {
            Some(status) => eprintln!(
                "wbwpty: pid {} payload stage={:?} reason={} attach_path_ran={}",
                self.child.pid,
                status.stage,
                status.reason,
                status.ran_attach_path()
            ),
            None => eprintln!("wbwpty: pid {} payload not mapped", self.child.pid),
        }
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
///
/// `SystemTime` is not enough on its own: on Windows its resolution is around
/// 15 ms, so two sessions started inside the same tick get the same value. The
/// pid covers other processes, the counter covers this one.
fn nonce() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    nanos
        ^ (std::process::id() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ seq.wrapping_mul(0x0000_0100_0000_01b3)
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

    /// Every target we create must come up with working pipes and a non-null
    /// `ConsoleHandle`, before it has executed a single instruction.
    ///
    /// Note what this does **not** claim. It used to read as "a non-null
    /// `ConsoleHandle` stops descendants from getting a console", which is
    /// README 1.2's mechanism and which measurement here **refutes**: with the
    /// sentinel enforced continuously from after startup, a `cmd /c` child still
    /// comes up with a real 9001x120 console, and its output goes there instead
    /// of to our pipe. See `grandchild_output_reaches_the_pipe`.
    ///
    /// What the field is worth keeping an eye on for: a *null* value is what
    /// makes the base API treat the process as having no console at all, which
    /// is a different and worse starting position than the one the kernel hands
    /// out.
    #[test]
    fn every_target_is_created_with_pipes_and_a_console_handle() {
        // Real pipes, because `STARTF_USESTDHANDLES` is what puts a handle in
        // `StandardOutput`; a target created without them legitimately has none.
        let mut pipes = crate::pipe::PipePair::new(0x11_0007).unwrap();
        let mut stdio = pipes.open_target_stdio().unwrap();
        let spec = ChildSpec::new("cmd.exe")
            .args(["/c", "exit", "0"])
            .stdio(Stdio {
                stdin: stdio.stdin,
                stdout: stdio.stdout,
                stderr: stdio.stderr,
            });
        let child = Child::spawn(&spec).unwrap();
        let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());
        let state = proc.read_console_state().expect("process parameters are readable");

        assert_ne!(
            state.console_handle, 0,
            "a null ConsoleHandle leaves the target with no console at all; got {state:?}"
        );
        assert_eq!(
            state.standard_output, stdio.stdout as u64,
            "STARTF_USESTDHANDLES must have landed in StandardOutput; got {state:?}"
        );
        assert!(
            matches!(
                child.console_patch,
                Ok(crate::manual_map::ConsolePatch::Unchanged(_))
                    | Ok(crate::manual_map::ConsolePatch::Written(_))
            ),
            "console state should have been checked: {:?}",
            child.console_patch
        );
        let _ = child.terminate();
    }

    /// The payload must not be able to kill the target it is patching.
    ///
    /// `ConsoleHandle` cannot be rewritten before the target has started: any
    /// value the host installs into a still-suspended target - a bogus `0x123`
    /// or a perfectly valid handle - makes it die with
    /// `STATUS_DLL_INIT_FAILED` (`0xC0000142`) before its first instruction
    /// retires. This pins the boundary so the next person to try "just write it
    /// earlier" does not lose an afternoon to it.
    #[test]
    fn rewriting_the_console_handle_before_startup_kills_the_target() {
        let mut pipes = crate::pipe::PipePair::new(0x11_0008).unwrap();
        let mut stdio = pipes.open_target_stdio().unwrap();
        let spec = ChildSpec::new("cmd.exe")
            .args(["/c", "exit", "0"])
            .stdio(Stdio {
                stdin: stdio.stdin,
                stdout: stdio.stdout,
                stderr: stdio.stderr,
            });
        let child = Child::spawn(&spec).unwrap();
        let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());

        let peb = proc.peb().unwrap();
        let params = proc
            .read_console_state()
            .map(|_| ())
            .and_then(|()| proc.read_bytes(peb + 0x20, 8))
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .expect("process parameters are readable");

        proc.write_bytes(params + 0x10, &crate::manual_map::CONSOLE_HANDLE_SENTINEL.to_le_bytes())
            .expect("writing the sentinel is allowed");

        child.resume().unwrap();
        let code = child.wait().unwrap();
        assert_eq!(
            code,
            0xc000_0142,
            "expected STATUS_DLL_INIT_FAILED; if this now passes, ConsoleHandle can be \
             written before startup and the whole injection-ordering story changes"
        );
        let _ = stdio.release();
    }

    /// The injected payload must report how far its attach path got.
    ///
    /// `DllMain` returns TRUE even when it is handed a garbage `fdwReason` and
    /// silently skips every attach path, so "the stub returned 0" proves
    /// nothing. The status word is the only place that distinction shows up.
    #[test]
    fn payload_publishes_the_stage_it_reached() {
        let spec = ChildSpec::new("cmd.exe");
        let config = SessionConfig { shim: false, ..Default::default() };
        let session = Session::start(&spec, config).unwrap();
        session
            .report()
            .expect("payload must map before its status word can be read");

        let raw = session.payload_status().expect("status word is mapped");
        let status = PayloadStatus::decode(raw);
        assert!(
            status.ran_attach_path(),
            "DllMain was entered with reason {} instead of DLL_PROCESS_ATTACH (1): {status:?}",
            status.reason
        );
        assert!(
            !matches!(status.stage, PayloadStage::Idle | PayloadStage::Entered),
            "the attach path stopped before doing anything: {status:?}"
        );

        session.shutdown();
    }

    /// The status word layout must agree with the payload's, or `--verbose`
    /// prints confident nonsense.
    #[test]
    fn status_word_layout_splits_as_documented() {
        assert_eq!(PayloadStatus::decode(0).stage, PayloadStage::Idle);
        assert_eq!(PayloadStatus::decode(5).stage, PayloadStage::Done);
        assert_eq!(PayloadStatus::decode(0x1_0005).reason, 1);
        assert_eq!(PayloadStatus::decode(0x1_0005).stage, PayloadStage::Done);
        assert_eq!(
            PayloadStatus::decode(0x1_0009).stage,
            PayloadStage::Unknown(9)
        );
        assert!(PayloadStatus::decode(0x1_0005).ran_attach_path());
        assert!(!PayloadStatus::decode(0).ran_attach_path());
    }

    /// A process the target creates must write to our pipe.
    ///
    /// # Currently does not work - this is the test that says so
    ///
    /// A descendant gets **its own console**, and that is where its output goes.
    /// Verified two independent ways on this machine:
    ///
    /// * the process tree during `cmd /c "cmd /c ..."` shows
    ///   `wbwpty -> cmd -> cmd -> conhost.exe`;
    /// * the descendant's own `mode con` reports a 9001x120 buffer, while the
    ///   target's reports nothing at all.
    ///
    /// So the output is not lost by a transport bug, it is delivered to a
    /// console we do not own and cannot read. README 1.2's mechanism - a
    /// non-null `ConsoleHandle` sentinel - was supposed to prevent exactly this
    /// and **does not**: enforced continuously from after startup it changes
    /// nothing. `ConsoleFlags |= STARTF_USESTDHANDLES` likewise does nothing.
    /// What does work is narrowing the gap: `ConsoleHandle` cannot be rewritten
    /// before the target starts at all (see
    /// `rewriting_the_console_handle_before_startup_kills_the_target`), so the
    /// window in which a startup-time descendant can grab a console cannot be
    /// closed from outside the process.
    ///
    /// `#[ignore]`d rather than deleted so the moment it starts passing is
    /// obvious.
    ///
    /// The previous version of this test was a false positive worth recording:
    /// it looked for `wbwpty-grandchild-ok` in the output, but an interactive
    /// `cmd.exe` *echoes the command line it was fed*, and that line contains
    /// the marker. It passed while descendants produced nothing at all. The
    /// marker is now assembled at runtime (`%i` in the `for` body expands to
    /// `NEU`, and the command line only ever shows the literal `%i`), so the
    /// command echo cannot produce it.
    #[test]
    #[ignore = "descendants get their own console; see the doc comment"]
    fn grandchild_output_reaches_the_pipe() {
        let marker = "NEU7Q2K5";
        let spec = ChildSpec::new("cmd.exe");
        let config = SessionConfig { shim: false, ..Default::default() };
        let session = Session::start(&spec, config).unwrap();
        session
            .report()
            .expect("payload must map before the descendant behaviour is meaningful");

        let _ = session
            .pipes
            .with(|p| {
                p.input()
                    .write_all(format!("cmd.exe /c for %i in (NEU) do @echo %i7Q2K5\r\n").as_bytes())
            })
            .expect("pipe write");

        let mut buf = [0u8; 4096];
        let mut saw_marker = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline && !saw_marker {
            match session.pipes.with(|p| p.output().read(&mut buf, 200)).unwrap() {
                Ok(ReadEvent::Data(n)) => {
                    for line in String::from_utf8_lossy(&buf[..n]).lines() {
                        if line.trim() == marker {
                            saw_marker = true;
                        }
                    }
                }
                Ok(ReadEvent::Eof) => break,
                Ok(ReadEvent::Timeout) => {}
                Err(e) => panic!("output read failed: {e:#}"),
            }
        }
        assert!(saw_marker, "descendant output never arrived as its own line");

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
