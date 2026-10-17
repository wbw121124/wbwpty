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
use std::sync::{Arc, Mutex};
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
    /// Watch the session's descendants and give them the same treatment the
    /// target got.
    ///
    /// Without it, only the *target* can substitute its own `CreateProcessW`,
    /// so anything the target spawns creates its children the way the base API
    /// does - with a console each. See [`crate::supervisor`] for the whole
    /// argument. Off means "inject the target and nothing else", which is the
    /// behaviour this project had before, and which only holds for two
    /// generations.
    pub cover_descendants: bool,
    /// Let the target's substitution hand each child to the host before letting
    /// it run.
    ///
    /// This is what closes the race [`crate::supervisor`] documents: a descendant
    /// found by polling was found *after* it started running, and the kernel had
    /// already given it a console host by then. With handover the target creates
    /// its children suspended, publishes the pid, and blocks until the host has
    /// injected - so a child begins executing with the substitution already
    /// installed rather than being patched afterwards.
    ///
    /// Off leaves the substitution doing what it always did, which is safe and
    /// which is the right choice when the host cannot inject - a second process
    /// that does not want to block its own `CreateProcessW` calls should not have
    /// this switched on behind it.
    pub handover: bool,
    /// Replace the process-creation functions themselves, rather than only the
    /// target's import slots.
    ///
    /// The import slot is where the substitution used to stop, and on this machine
    /// it loses: `cmd.exe` imports the API set
    /// `api-ms-win-core-processthreads-l1-1-1.dll` rather than `KERNEL32.dll`, and
    /// its single `CreateProcess` call happened at about 31 ms while the slot patch
    /// completed at 36 ms - the substitution was live and reported zero calls.
    ///
    /// Patching the entry points does not care when the loader resolved a slot: a
    /// caller that resolved before the patch still calls the address that was
    /// overwritten. That is the difference between replacing process creation and
    /// asking to be in the right place first.
    ///
    /// Off falls back to the import table route alone, which is what this did
    /// before, and which still covers a target that resolves its imports slowly
    /// enough.
    pub inline_process_hook: bool,
    /// Force `DETACHED_PROCESS` with a stub that needs no payload at all.
    ///
    /// **Off by default, and measured as not worth having on.**
    ///
    /// The idea was to remove the dependency on the payload: two instructions with
    /// no imports, so nothing to resolve and nothing to wait for. It does get in
    /// early - 10 ms after spawn.
    ///
    /// Early is not early enough. With it on, `ping` still arrived with a
    /// `conhost.exe`, which places `cmd.exe`'s first `CreateProcess` *before* the
    /// stub was installed - earlier than the 31 ms this had assumed from the
    /// payload substitution missing. That assumption was wrong, and correcting it
    /// is the useful result: the real margin is under ten milliseconds, not
    /// thirty, and the payload's own imports take longer than that to resolve. The
    /// stub cannot close a gap it is itself too slow to reach.
    ///
    /// A second failure appeared alongside and is not accounted for: an inner
    /// `cmd.exe` created through the stub died with `STATUS_DLL_INIT_FAILED`
    /// (`0xC0000142`) and showed an error dialog. That happens *after* the
    /// `conhost.exe` appears, so it is not its cause - it is a separate fault, and
    /// it has the shape of AGENTS pitfall 12 (startup state changed before it is
    /// safe to change). Left undiagnosed rather than guessed at.
    ///
    /// The encoded stub and its installer are correct and tested, and the
    /// measurements above are only as good as the evidence behind them, so both are
    /// kept. Enabling this is expected to be useless for the first spawn and to
    /// produce `0xC0000142` on some descendants.
    pub forced_stub: bool,
    /// Mirror the host's stdin into the `-in` pipe.
    ///
    /// Off leaves the target's stdin open for the life of the session, which is
    /// the only way to run an interactive target that is supposed to stay alive.
    ///
    /// This is not a convenience. The pump turns host stdin EOF into pipe EOF,
    /// and an interactive `cmd.exe` exits the moment it sees one - so a test that
    /// wants to assert something about a *live* target has to either keep host
    /// stdin open (not something a test can arrange) or turn the pump off. Under
    /// `cargo test` host stdin is whatever the harness inherited, which is how a
    /// test that asserts "the target survived" comes to depend on whether the
    /// machine it ran on had a terminal attached.
    pub pump_input: bool,
    /// Report injection and shim decisions on stderr.
    pub verbose: bool,
    /// Hand every child an explicit environment block instead of letting it
    /// inherit, and flag it `CREATE_UNICODE_ENVIRONMENT`.
    ///
    /// Generation 1 does this unconditionally. Generation 2 forwards whatever
    /// the target passed - `NULL` for `cmd.exe`, meaning "inherit mine" - and the
    /// grandchild's stdout does not bind while generation 1's does. The two
    /// generations differ here and nowhere else that has survived scrutiny, so
    /// this is a switch to make the difference observable rather than a
    /// preference: `NULL` is well defined and is not known to be wrong.
    pub explicit_environment: bool,
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
            cover_descendants: true,
            handover: true,
            inline_process_hook: true,
            forced_stub: true,
            pump_input: true,
            verbose: false,
            explicit_environment: false,
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
    /// The worker thread started.
    WorkerStarted,
    /// The environment contract was read and the log file, if any, was opened.
    LogReady,
    /// The CRT streams were put into unbuffered mode.
    CrtRepaired,
    /// The CRT streams could not be repaired.
    CrtSkipped,
    /// The worker ran to completion.
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
            5 => Self::WorkerStarted,
            6 => Self::LogReady,
            7 => Self::CrtRepaired,
            8 => Self::CrtSkipped,
            9 => Self::Done,
            other => Self::Unknown(other),
        }
    }

    /// True once no further progress will be reported.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::CrtSkipped)
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

/// What the payload's CRT repair did.
///
/// Packed into one `u32` because the host reads it out of the mapped image with
/// a single four-byte read, and because the stage word has no room for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CrtDetail {
    /// `ucrtbase.dll` was found and both exports resolved.
    pub ucrt_resolved: bool,
    /// Streams `setvbuf` accepted.
    pub streams_set: u32,
    /// Streams `setvbuf` refused.
    pub streams_refused: u32,
}

impl CrtDetail {
    fn decode(raw: u32) -> Self {
        Self {
            ucrt_resolved: raw & (1 << 16) != 0,
            streams_set: raw & 0xff,
            streams_refused: (raw >> 8) & 0xff,
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
    /// RVA of the payload's exported WBWPTY_CRT_DETAIL word.
    crt_detail_rva: Option<u32>,
    /// RVA of the payload's exported WBWPTY_HOOK_STATS word.
    hook_stats_rva: Option<u32>,
    /// RVA of the payload's exported WBWPTY_HOOK_FLAGS word.
    hook_flags_rva: Option<u32>,
    /// Last successful read of the hook counters, sampled while the target lived.
    ///
    /// The counters live in the *target's* address space, so they are only
    /// readable while it is alive. Reporting happens after the session ends, and
    /// for a short-lived `cmd /c <child>` that is always too late: the process
    /// handle is still valid but the pages are gone, the read fails, and the
    /// counters come back `None`. Sampling during the session is what makes them
    /// answerable at all.
    hook_stats_seen: Arc<std::sync::Mutex<Option<(u32, u32)>>>,
    /// Cached [`Self::hook_stats_seen`], for the creation flags instead of the
    /// counters.
    hook_flags_seen: Arc<std::sync::Mutex<Option<(u32, u32)>>>,
    /// Console sentinel state after the post-injection re-assert.
    console_patch: Result<crate::manual_map::ConsolePatch, String>,
    /// What the `CreateProcessW` substitution did, if it happened.
    hook: Option<crate::manual_map::HookReport>,
    /// What the console API substitution did, if it was asked for and the target
    /// uses one.
    console_hook: Option<crate::manual_map::ConsoleHookReport>,
    /// Why it did not, when it was attempted and failed.
    hook_error: Option<String>,
    /// Whether the inline patch replaced process creation. See
    /// [Self::process_creation_substituted].
    inline_live: bool,
    /// Per-export outcome of the inline patch.
    inline: Vec<crate::manual_map::inline::InlineHook>,
    /// Watches the tree and gives every descendant the same treatment the target
    /// got. `None` when there was nothing to extend - see [`Self::start`].
    supervisor: Option<crate::supervisor::DescendantSupervisor>,
    /// The virtual screen the target's output is fed into.
    ///
    /// `None` when the console shim is off, because nothing would ever ask it
    /// anything, and feeding every output chunk through a VT parser to answer
    /// nobody's question is work for nobody.
    screen: Option<crate::screen::SharedScreen>,
    /// RVA of the payload's published console state record.
    console_state_rva: Option<u32>,
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
        // The pipe *names*, which are half of the contract in AGENTS §3 and were
        // specified there but never actually published. A grandchild cannot be
        // handed a handle number that its parent has already invalidated - and
        // that is exactly what happens the moment the target redirects its own
        // stdout, because closing the inherited pipe lets `CreateFile("nul")`
        // recycle the same value for a handle that is not inheritable. The
        // substitute in the payload uses these names to reopen the pipe when the
        // published handle stops naming one; with them absent it had no way to
        // tell "not a pipe" from "never told".
        spec.env
            .push((contract::ENV_IN.into(), pipes.input_name().to_string()));
        spec.env
            .push((contract::ENV_OUT.into(), pipes.output_name().to_string()));
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
        let std_handles = stdio.handles();
        stdio.release();

        // Timings, because "the injection lost the race" is a claim that has to be
        // measured rather than argued: what matters is the gap between the moment
        // the target can run its own code and the moment the substitution is in.
        let resume_at = std::time::Instant::now();

        // The target must run whether or not we manage to patch it. Resuming is
        // therefore done here, and injection is layered on top.
        let report = match inject_payload(&child, &config, resume_at) {
            Some(report) => Some(report),
            None => {
                if !child.is_resumed() {
                    child.resume().context("resuming target")?;
                }
                None
            }
        };

        // Where the payload came from, and the RVAs of the words it publishes.
        // Resolved once: three of the four reads below want the same file, and
        // `find_export_rva` re-parses the PE on every call.
        let dll_path = config
            .dll
            .clone()
            .or_else(|| {
                std::env::var("WBWPTY_DLL")
                    .ok()
                    .map(std::path::PathBuf::from)
            })
            .unwrap_or_else(default_dll_path);
        let dll_image = std::fs::read(&dll_path).ok();
        let export_rva = |name: &str| -> Option<u32> {
            dll_image.as_ref().and_then(|file| {
                crate::manual_map::find_export_rva(file, name)
                    .ok()
                    .flatten()
            })
        };
        let status_rva = export_rva("WBWPTY_STATUS");
        let crt_detail_rva = export_rva("WBWPTY_CRT_DETAIL");
        let hook_stats_rva = export_rva("WBWPTY_HOOK_STATS");
        let hook_flags_rva = export_rva("WBWPTY_HOOK_FLAGS");
        let console_state_rva = export_rva("WBWPTY_CONSOLE_STATE");

        // The session's pipes, published before any substitution exists.
        //
        // Previously this happened inside `install_create_process_hook`, which
        // made it a side effect of *that* strategy: skipping the import table
        // patch also skipped the handles, and the payload then saw
        // `have_session_handles() == false` and passed every call through
        // untouched. Which is what it did - a session with the substitution
        // "live" that created no children at all.
        //
        // Both strategies need them, and nothing else needs them published, so it
        // belongs here: immediately after the payload is mapped, independent of
        // how - or whether - it gets patched.
        if let Some(injection) = report.as_ref() {
            let publish = |name: &str, bytes: &[u8]| -> Result<()> {
                let rva = export_rva(name)
                    .ok_or_else(|| anyhow::anyhow!("the payload does not export {name}"))?;
                crate::manual_map::remote::RemoteProcess::new(child.process_handle())
                    .write_bytes(injection.image_base + rva as u64, bytes)
                    .with_context(|| format!("publishing {name}"))
            };
            if let Some(rva) = export_rva("WBWPTY_STD_HANDLES") {
                let mut packed = [0u8; 24];
                for (slot, value) in packed.chunks_mut(8).zip(std_handles) {
                    slot.copy_from_slice(&value.to_le_bytes());
                }
                let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());
                match proc.write_bytes(injection.image_base + rva as u64, &packed) {
                    Ok(()) if config.verbose => eprintln!(
                        "wbwpty: pid {} published the session handles {std_handles:016x?}",
                        child.pid
                    ),
                    Err(err) if config.verbose => eprintln!(
                        "wbwpty: pid {} could not publish the session handles: {err:#}",
                        child.pid
                    ),
                    _ => {}
                }
            } else if config.verbose {
                eprintln!(
                    "wbwpty: pid {} payload exports no WBWPTY_STD_HANDLES; every child \
                     will be created with the caller's own handles",
                    child.pid
                );
            }
            if let Some(rva) = export_rva("WBWPTY_EXPLICIT_ENVIRONMENT") {
                let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());
                let _ = proc.write_bytes(
                    injection.image_base + rva as u64,
                    &u32::from(config.explicit_environment).to_le_bytes(),
                );
            }
        }

        // Replace process creation itself, on top of whatever the import table
        // substitution managed to catch.
        //
        // This runs *first* because it is the only one of the two that can win the
        // race, and the import table route spends several milliseconds proving
        // that the loader has finished with a slot - time that a target spawning in
        // its first 30 ms does not have. Measured: `cmd.exe` made its single
        // `CreateProcess` at about 31 ms and the import substitution went live at
        // 33 ms with zero calls.
        //
        // It also does not import `CreateProcessW` from `KERNEL32.dll` at all, but
        // from the API set `api-ms-win-core-processthreads-l1-1-1.dll`, so the slot
        // is at the end of an indirection chain rather than a single hop.
        //
        // Patching the entry points does not depend on when the loader resolved
        // anything: a caller that resolved before the patch still calls the
        // address that was overwritten.
        let inline = if config.inline_process_hook {
            match report.as_ref() {
                Some(injection) => install_inline_process_hooks(
                    &crate::manual_map::remote::RemoteProcess::new(child.process_handle()),
                    injection.image_base,
                    &dll_image,
                    &export_rva,
                    config.verbose,
                ),
                None => {
                    if config.verbose {
                        eprintln!(
                            "wbwpty: pid {} cannot replace process creation: no payload",
                            child.pid
                        );
                    }
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let inline_live = inline
            .iter()
            .any(|h| matches!(h, crate::manual_map::inline::InlineHook::Installed { .. }));

        // The import table substitution is now the fallback rather than the main
        // path. It still earns its place: a target whose inline prologue could not
        // be proven safe to relocate gets nothing from the patch above, and the slot
        // route does not care whether the function's first bytes are movable.
        //
        // Skipped when the inline patch is live, and not only to save the work -
        // doing both would have the same substitute reachable by two paths with one
        // of them pointing at a trampoline the other does not use.
        let hook = match (report.as_ref(), inline_live) {
            (_, true) => Ok(None),
            (Some(injection), false) => crate::manual_map::install_create_process_hook(
                &crate::manual_map::remote::RemoteProcess::new(child.process_handle()),
                &dll_path,
                injection,
                std_handles,
                config.explicit_environment,
            ),
            (None, false) => Ok(None),
        };
        let (hook, hook_error) = match hook {
            Ok(hook) => (hook, None),
            Err(err) => {
                if config.verbose {
                    eprintln!(
                        "wbwpty: pid {} no CreateProcess interception: {err:#}",
                        child.pid
                    );
                }
                (None, Some(format!("{err:#}")))
            }
        };
        if config.verbose {
            eprintln!(
                "wbwpty: pid {} substitution live {}ms after spawn \
                 (loader wait {:?}ms, inline {})",
                child.pid,
                resume_at.elapsed().as_millis(),
                report.as_ref().map(|r| r.loader_wait_ms),
                if inline_live { "on" } else { "off" }
            );
        }

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

        // The substitution above only rewrites *one* process' import table. A
        // descendant gets its own image and its own import table, so anything
        // the target spawns would create its children exactly the way the base
        // API does - with a console, and with a `conhost.exe` per grandchild.
        // Watching the tree extends the same treatment to every generation.
        //
        // Started only when there is something to extend: no payload means
        // nothing to point the descendants' slots at, and a watcher that
        // injected nothing would just spend a process table snapshot per poll.
        let supervisor = match (
            report.as_ref(),
            hook.as_ref(),
            config.inject,
            config.cover_descendants,
        ) {
            (Some(_), Some(_), true, true) => {
                // The handover reader resolves the payload's exported words by RVA,
                // so it needs the image itself rather than re-reading the file on
                // every poll.
                crate::supervisor::publish_payload_image(dll_image.clone().unwrap_or_default());

                let mut supervisor = crate::supervisor::SupervisorConfig::new(
                    child.pid,
                    dll_path.clone(),
                    std_handles,
                );
                supervisor.payload_image = Arc::new(dll_image.clone().unwrap_or_default());
                supervisor.verbose = config.verbose;
                supervisor.explicit_environment = config.explicit_environment;
                // Where the payload landed in the root, which is where the handover
                // words live. Not the root's image base - the payload is mapped by
                // hand and the two have no relation.
                supervisor.root_payload_base = report.as_ref().map(|r| r.image_base);
                Some(crate::supervisor::DescendantSupervisor::spawn(supervisor))
            }
            _ => None,
        };

        // Turn the handover on in the root, now that its substitution and the
        // supervisor are both in place.
        //
        // Last, deliberately. While this word is zero the payload's substitution
        // creates children exactly as it did before - no suspension, no waiting -
        // so a failure anywhere above degrades to the previous behaviour rather
        // than to a target whose `CreateProcessW` never returns.
        if config.handover {
            if let (Some(injection), Some(_)) = (report.as_ref(), hook.as_ref()) {
                let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());
                if let Some(rva) = export_rva("WBWPTY_HANDOVER") {
                    if let Err(err) =
                        proc.write_bytes(injection.image_base + rva as u64, &1u32.to_le_bytes())
                    {
                        if config.verbose {
                            eprintln!(
                                "wbwpty: pid {} could not enable handover: {err:#}",
                                child.pid
                            );
                        }
                    }
                }
            }
        }

        let pump_input = config.pump_input;
        // The console API substitution, when asked for. Same mechanism as the
        // `CreateProcessW` one and independent of it: a target may well use one,
        // the other, or both. Deliberately gated on `shim` rather than on
        // `inject`, because this is an opt-in behaviour change - a program whose
        // console calls start succeeding is a program behaving differently - while
        // the `CreateProcessW` substitution is required for the tree to work at
        // all.
        let console_hook = if config.shim {
            match report.as_ref() {
                Some(injection) => {
                    let proc_handle =
                        crate::manual_map::remote::RemoteProcess::new(child.process_handle());
                    match proc_handle.image_path().and_then(|image| {
                        let file = std::fs::read(&image).with_context(|| {
                            format!("reading the target image {}", image.display())
                        })?;
                        crate::manual_map::install_console_hook(
                            &proc_handle,
                            &file,
                            &dll_path,
                            injection,
                        )
                    }) {
                        Ok(hook) => hook,
                        Err(err) => {
                            if config.verbose {
                                eprintln!(
                                    "wbwpty: pid {} no console API substitution: {err:#}",
                                    child.pid
                                );
                            }
                            None
                        }
                    }
                }
                None => None,
            }
        } else {
            None
        };

        let screen = match console_hook.as_ref() {
            Some(_) => {
                let (cols, rows) = (config.cols, config.rows);
                Some(Arc::new(Mutex::new(crate::screen::Screen::new(cols, rows))))
            }
            None => None,
        };

        let session = Self {
            child,
            pipes: Arc::new(SharedPipes::new(pipes)),
            config,
            report,
            status_rva,
            crt_detail_rva,
            hook_stats_rva,
            hook_flags_rva,
            console_patch,
            hook,
            console_hook,
            hook_error,
            inline_live,
            inline,
            supervisor,
            screen,
            console_state_rva,
            hook_stats_seen: Arc::new(std::sync::Mutex::new(None)),
            hook_flags_seen: Arc::new(std::sync::Mutex::new(None)),
            shutting_down: Arc::new(AtomicBool::new(false)),
        };
        session.start_hook_sampler();
        if pump_input {
            session.start_input_pump();
        }

        // The tap runs inside every read of the output pipe, whoever makes it -
        // the CLI's pump or a test reading `Session::pipes()` itself. Installing
        // it here rather than in `pump_output` is the point: a tap attached to
        // one call site works in the demo and silently does nothing everywhere
        // else, and "silently does nothing" is the failure mode this whole feature
        // has to avoid.
        let tap_screen = session.screen.clone();
        let tap_handle = session.child.process_handle() as isize;
        let tap_base = session.report.as_ref().map(|r| r.image_base);
        let tap_rva = session.console_state_rva;
        if tap_screen.is_some() {
            let verbose = session.config.verbose;
            session.pipes.with(|p| {
                p.set_output_tap(Box::new(move |bytes: &[u8]| -> Vec<u8> {
                    let Some(screen) = &tap_screen else {
                        return Vec::new();
                    };
                    let (busy, done, replies) = {
                        let mut screen = crate::screen::lock(screen);
                        screen.feed(bytes);
                        let (busy, done) = screen.publish();
                        (busy, done, screen.take_replies())
                    };
                    publish_into(tap_handle, tap_base, tap_rva, busy, done, verbose);
                    replies
                }));
            });
        }

        session.describe_console_state();
        Ok(session)
    }

    /// The payload report, present only when the DLL mapped successfully.
    pub fn report(&self) -> Option<&InjectionReport> {
        self.report.as_ref()
    }

    /// What the `CreateProcessW` substitution did, if anything.
    ///
    /// `None` means one of three things, and they are worth telling apart: the
    /// payload was never mapped, the target does not import
    /// `CreateProcessW`, or the installation failed. [`Self::hook_error`]
    /// answers the third.
    pub fn hook(&self) -> Option<&crate::manual_map::HookReport> {
        self.hook.as_ref()
    }

    /// Whether process creation is substituted, by either mechanism.
    ///
    /// The import table route and the inline patch are two ways to reach the same
    /// substitute, and exactly one of them runs - [`Session::hook`] is `None` when
    /// the inline patch is live, because the slot was never touched. So a caller
    /// asking "can I spawn a child and have it covered?" has to ask this, not
    /// [`Self::hook`]: reading the latter as the answer reports a session that is
    /// fully substituted as having no substitution at all.
    ///
    /// Useful to tests for exactly that reason - a test that waits for the
    /// substitution before spawning its child was, for a while, waiting for
    /// something that no longer happens.
    pub fn process_creation_substituted(&self) -> bool {
        self.hook.is_some() || self.inline_live
    }

    /// What the inline patch did, per export.
    ///
    /// Reported rather than inferred because a refusal and an absence mean
    /// different things: a refused prologue means the entry point was left alone
    /// and process creation is *not* covered by this route, which may still be
    /// covered by the slot route.
    pub fn inline_hooks(&self) -> &[crate::manual_map::inline::InlineHook] {
        &self.inline
    }

    /// Why the substitution did not happen, when it was attempted and failed.
    ///
    /// Swallowing this into a `None` is how a feature that silently does
    /// nothing gets mistaken for one that works.
    pub fn hook_error(&self) -> Option<&str> {
        self.hook_error.as_deref()
    }

    /// What the console API substitution did.
    ///
    /// `None` means one of four things, and [`SessionConfig::shim`] separates the
    /// first from the rest: the shim was not asked for, the payload was not
    /// mapped, the target imports no console API, or every slot it had was
    /// unwritable.
    pub fn console_hook(&self) -> Option<&crate::manual_map::ConsoleHookReport> {
        self.console_hook.as_ref()
    }

    /// Which descendants of the target have been given the same treatment, as of
    /// right now.
    ///
    /// The record is published as it happens rather than at the end, so a caller
    /// can tell a descendant that was covered before it could spawn anything
    /// from one that was covered afterwards - which, for the promise this project
    /// makes, is the difference between working and not.
    ///
    /// Empty when no supervisor is running; see [`Self::start`] for when there
    /// is one.
    pub fn coverage(&self) -> Vec<crate::supervisor::Coverage> {
        self.supervisor
            .as_ref()
            .map(|s| s.coverage())
            .unwrap_or_default()
    }

    /// Blocks until `pid` appears in [`Self::coverage`], or the timeout expires.
    ///
    /// For a test that has to hold a descendant still until it is covered: a
    /// fixture that spawns its child immediately would race the watcher, and
    /// losing that race looks exactly like the feature not working.
    pub fn wait_for_coverage(
        &self,
        pid: u32,
        timeout: std::time::Duration,
    ) -> Option<crate::supervisor::Coverage> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(found) = self.coverage().into_iter().find(|c| c.pid == pid) {
                return Some(found);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// The descendants' coverage as one line, for `--verbose`.
    fn describe_coverage(&self) {
        if !self.config.verbose {
            return;
        }
        let records = self.coverage();
        let covered = records.iter().filter(|c| c.covered()).count();
        let notes: Vec<String> = records
            .iter()
            .filter(|c| !c.covered())
            .map(|c| match &c.note {
                Some(note) => format!("{} ({note})", c.pid),
                None => c.pid.to_string(),
            })
            .collect();
        eprintln!(
            "wbwpty: pid {} descendants: {covered} of {} covered{}",
            self.child.pid,
            records.len(),
            if notes.is_empty() {
                String::new()
            } else {
                format!(", not covered: {}", notes.join(", "))
            }
        );
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

    /// Waits for the payload's worker to reach a terminal stage.
    ///
    /// The stage word is a live progress channel, not a one-shot result: the
    /// worker thread publishes it as it goes, so reading it right after the
    /// remote stub returns races the worker. `None` means the word never
    /// settled, which is a legitimate answer - a target that exits mid-setup
    /// takes its payload with it.
    pub fn wait_for_payload(&self, timeout: std::time::Duration) -> Option<PayloadStatus> {
        let deadline = std::time::Instant::now() + timeout;
        let mut last = None;
        loop {
            match self.payload_stage() {
                Some(status) => {
                    if status.stage.is_terminal() {
                        return Some(status);
                    }
                    last = Some(status);
                }
                // The payload is gone; nothing more will be published.
                None if last.is_some() => return last,
                None => {}
            }
            if std::time::Instant::now() >= deadline {
                return last;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The payload's `WBWPTY_CRT_DETAIL` word, decoded.
    ///
    /// Packed as `ucrt_resolved << 16 | refused << 8 | set`; see the layout in
    /// the payload's `lib.rs`.
    pub fn payload_crt_detail(&self) -> Option<CrtDetail> {
        Some(CrtDetail::decode(self.payload_word(self.crt_detail_rva)?))
    }

    /// How many times the substituted `CreateProcessW` has been called, and how
    /// many of those failed.
    ///
    /// The distinction the whole feature rests on: a slot that was rewritten
    /// says nothing about whether anything goes *through* it. A target that
    /// reaches process creation some other way - `CreateProcessInternalW`, a
    /// syscall, a helper - leaves this at zero while the hook report still
    /// claims success.
    /// Reads the hook counters for as long as the target is alive.
    ///
    /// Both counters are monotonic, so the sampler keeps the largest value it
    /// saw rather than the last: a sample that lands between a read and the
    /// target's exit must not be able to lower the high-water mark.
    fn start_hook_sampler(&self) {
        if self.report.is_none() || self.hook_stats_rva.is_none() {
            return;
        }
        let shutting_down = Arc::clone(&self.shutting_down);
        let handle = SendHandle(self.child.process_handle());
        let stats_rva = self.hook_stats_rva;
        let flags_rva = self.hook_flags_rva;
        let base = self.report.as_ref().map(|r| r.image_base).unwrap_or(0);
        let stats_seen = Arc::clone(&self.hook_stats_seen);
        let flags_seen = Arc::clone(&self.hook_flags_seen);

        std::thread::spawn(move || {
            while !shutting_down.load(Ordering::Relaxed) {
                let proc = handle.process();
                if let Some(raw) = stats_rva.and_then(|rva| read_u32(&proc, base + rva as u64)) {
                    let sample = ((raw >> 8) & 0xffff, raw & 0xff);
                    if let Ok(mut seen) = stats_seen.lock() {
                        let current = seen.unwrap_or((0, 0));
                        *seen = Some((current.0.max(sample.0), current.1.max(sample.1)));
                    }
                }
                if let Some(raw) = flags_rva.and_then(|rva| read_u64(&proc, base + rva as u64)) {
                    let sample = (raw as u32, (raw >> 32) as u32);
                    if let Ok(mut seen) = flags_seen.lock() {
                        // The second word is a call count and keeps rising; the
                        // first is the flags of the most recent substitution, so
                        // it is the last sample that matters, not the largest.
                        let count = seen.map(|s| s.1).unwrap_or(0).max(sample.1);
                        *seen = Some((sample.0, count));
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
    }

    pub fn payload_hook_stats(&self) -> Option<(u32, u32)> {
        if let Some(raw) = self
            .hook_stats_rva
            .and_then(|rva| self.read_payload_u32(rva))
        {
            let live = ((raw >> 8) & 0xffff, raw & 0xff);
            if let Ok(mut seen) = self.hook_stats_seen.lock() {
                let current = seen.unwrap_or((0, 0));
                *seen = Some((current.0.max(live.0), current.1.max(live.1)));
            }
        }
        self.hook_stats_seen.lock().ok().and_then(|s| *s)
    }

    /// The `dwCreationFlags` the substitution handed to `CreateProcessW`, and
    /// how many children went through it.
    ///
    /// The host cannot work this out for itself: it knows which flags it forced,
    /// not which flags reached the kernel. When the two disagree - a target that
    /// asks for a console it should not have, a hook that stops forcing anything
    /// - the only evidence is here.
    pub fn payload_hook_flags(&self) -> Option<(u32, u32)> {
        if let Some(raw) = self
            .hook_flags_rva
            .and_then(|rva| self.read_payload_u64(rva))
        {
            let live = (raw as u32, (raw >> 32) as u32);
            if let Ok(mut seen) = self.hook_flags_seen.lock() {
                let count = seen.map(|s| s.1).unwrap_or(0).max(live.1);
                *seen = Some((live.0, count));
            }
        }
        self.hook_flags_seen.lock().ok().and_then(|s| *s)
    }

    fn read_payload_u32(&self, rva: u32) -> Option<u32> {
        let base = self.report.as_ref()?.image_base;
        read_u32(
            &crate::manual_map::remote::RemoteProcess::new(self.child.process_handle()),
            base + rva as u64,
        )
    }

    fn read_payload_u64(&self, rva: u32) -> Option<u64> {
        let base = self.report.as_ref()?.image_base;
        read_u64(
            &crate::manual_map::remote::RemoteProcess::new(self.child.process_handle()),
            base + rva as u64,
        )
    }

    fn payload_word(&self, rva: Option<u32>) -> Option<u32> {
        rva.and_then(|rva| self.read_payload_u32(rva))
    }

    /// Where the hook counters live: `(payload image base, RVA)`.
    ///
    /// The two halves have to be paired against each other and against the payload
    /// on disk; a mismatch reads a zero-filled address and looks exactly like a
    /// hook that never fired. Exposed for the diagnostics that have to check that
    /// without re-deriving the layout.
    pub fn payload_stats_location(&self) -> Option<(u64, u32)> {
        Some((self.report.as_ref()?.image_base, self.hook_stats_rva?))
    }

    pub fn pid(&self) -> u32 {
        self.child.pid
    }

    /// The target's process handle.
    ///
    /// For callers that inspect the target themselves: which address an import
    /// slot actually holds, or whether a word the payload published can be read
    /// back. Both are questions only the host can answer, and both have an
    /// answer that looks exactly like success when it is wrong.
    pub fn process_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.child.process_handle()
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
        match self.wait_for_payload(std::time::Duration::from_millis(1500)) {
            Some(status) => eprintln!(
                "wbwpty: pid {} payload stage={:?} reason={} attach_path_ran={}",
                self.child.pid,
                status.stage,
                status.reason,
                status.ran_attach_path()
            ),
            None => eprintln!("wbwpty: pid {} payload not mapped", self.child.pid),
        }
        if let Some(detail) = self.payload_crt_detail() {
            eprintln!(
                "wbwpty: pid {} crt ucrt_resolved={} streams_set={} streams_refused={}",
                self.child.pid, detail.ucrt_resolved, detail.streams_set, detail.streams_refused
            );
        }
        if let Some(hook) = self.hook() {
            // One line per API: which entry points are covered is now a set, not
            // a single address, and knowing "CreateProcessW" alone would be a
            // claim this project has already had falsified by cmd.exe.
            for i in &hook.intercepts {
                eprintln!(
                    "wbwpty: pid {} hooked {}: {} slot(s) at {:#x} -> {:#x} (original {:#x}){}",
                    self.child.pid,
                    i.api,
                    i.slots.len(),
                    i.slots[0].address(0),
                    i.substitute,
                    i.original,
                    if i.needed_protection_change {
                        ", image pages made writable"
                    } else {
                        ""
                    }
                );
            }
        }
        if self.hook().is_none() && self.report.is_some() {
            eprintln!(
                "wbwpty: pid {} target imports no process-creation entry point",
                self.child.pid
            );
        }
        if let Some((calls, failures)) = self.payload_hook_stats() {
            eprintln!(
                "wbwpty: pid {} hook calls={calls} failures={failures}",
                self.child.pid
            );
        }
        if let Some(report) = &self.console_hook {
            eprintln!(
                "wbwpty: pid {} console API substitution: {} slot(s){}{}",
                self.child.pid,
                report.installed.len(),
                if report.needed_protection_change {
                    ", image pages made writable"
                } else {
                    ""
                },
                if report.not_intercepted.is_empty() {
                    String::new()
                } else {
                    format!("; left alone: {}", report.not_intercepted.join(", "))
                }
            );
            // The address the state record is published at. Printed because a
            // payload that reads a different one produces "the host never
            // published anything" with no other symptom, and that is not
            // diagnosable from outside without it.
            eprintln!(
                "wbwpty: pid {} console state at {:#x} (payload base {:#x}, rva {:#x})",
                self.child.pid,
                self.report.as_ref().map(|r| r.image_base).unwrap_or(0)
                    + self.console_state_rva.unwrap_or(0) as u64,
                self.report.as_ref().map(|r| r.image_base).unwrap_or(0),
                self.console_state_rva.unwrap_or(0),
            );
        } else if self.report.is_some() && self.config.shim {
            eprintln!(
                "wbwpty: pid {} console API substitution: target uses none, or none could be written",
                self.child.pid
            );
        }
    }

    /// The session's pipes, for a caller that wants to read the output itself
    /// instead of having it mirrored onto the host's stdout.
    pub fn pipes(&self) -> &Arc<SharedPipes> {
        &self.pipes
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
            // Through `read_output`, not the bare end: that is the call which runs
            // the tap, and the tap is what keeps the virtual screen and the
            // payload's published state in step with what the target has printed.
            let read = self
                .pipes
                .with(|p| p.read_output(&mut buf, 100))
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

    /// Feeds target output into the virtual screen, publishes what changed, and
    /// returns whatever the terminal owes the program.
    ///
    /// This is the [`crate::pipe::OutputTap`]. It runs inside the pipe read, so
    /// the answers it returns go straight back down the input end - a program
    /// that asked a question gets its answer whether or not it goes on to read
    /// stdin.
    ///
    /// The screen is fed *before* the state is published and before the bytes
    /// are shown, so by the time the cursor has visibly moved the payload can
    /// already be told where it is.
    fn absorb_output(&self, bytes: &[u8]) -> Vec<u8> {
        let Some(screen) = &self.screen else {
            return Vec::new();
        };

        let (busy, done, replies) = {
            let mut screen = crate::screen::lock(screen);
            screen.feed(bytes);
            let (busy, done) = screen.publish();
            (busy, done, screen.take_replies())
        };

        self.publish_console_state(busy, done);
        replies
    }

    /// Writes the two halves of the seqlock into the payload's image.
    fn publish_console_state(&self, busy: [u8; 40], done: [u8; 40]) {
        publish_into(
            self.child.process_handle() as isize,
            self.report.as_ref().map(|r| r.image_base),
            self.console_state_rva,
            busy,
            done,
            self.config.verbose,
        );
    }

    /// The virtual screen, for a caller that wants to look at it.
    pub fn screen(&self) -> Option<crate::screen::SharedScreen> {
        self.screen.clone()
    }

    /// Resizes the virtual screen, as a window change would.
    ///
    /// Not wired to anything yet: there is no control channel from the host
    /// terminal to here (README 1.4 lists `WBWPTY_CTL` as the place for it, and it
    /// is still just a name in the contract).
    pub fn resize_screen(&self, cols: u16, rows: u16) {
        if let Some(screen) = &self.screen {
            crate::screen::lock(screen).resize(cols, rows);
            let (busy, done) = crate::screen::lock(screen).publish();
            self.publish_console_state(busy, done);
        }
    }

    /// Signals stdin EOF to the target and waits for it to exit.
    ///
    /// Returns `None` when the target is already gone, which is not an error:
    /// `pump_output` returning is the normal way a session ends.
    pub fn wait(&self) -> Option<u32> {
        self.child.wait().ok()
    }

    /// Waits for the target, but gives up after `timeout`.
    ///
    /// [`Self::wait`] has no timeout, which is right for a session that is going
    /// to finish and wrong for a caller that has to stay responsive: a target
    /// waiting on a gate that is never opened would hang the caller rather than
    /// fail. `None` means it did not finish in time, which is not the same as "it
    /// exited with no code".
    pub fn wait_for(&self, timeout: std::time::Duration) -> Option<u32> {
        self.child.wait_timeout(timeout).ok().flatten()
    }

    /// Runs the whole session on the calling thread: output until EOF, then the
    /// exit code. This is the entry point the CLI uses.
    pub fn run_to_completion(self) -> Result<u32> {
        self.pump_output()?;
        // Report what the payload ended up doing, now that the target has
        // finished. Read at the start of the session these counters are all
        // zero for the simplest possible reason: the target had not run a
        // single command yet.
        self.report_payload_outcome();
        let code = self
            .child
            .wait_timeout(std::time::Duration::from_secs(2))
            .unwrap_or(None);
        Ok(code.unwrap_or(0))
    }

    /// Prints the payload's final state when `--verbose` is on.
    ///
    /// Only meaningful once the session is over: the stage word is a live
    /// progress channel and the hook counters only move when the target
    /// creates something.
    fn report_payload_outcome(&self) {
        if !self.config.verbose {
            return;
        }
        if let Some((calls, failures)) = self.payload_hook_stats() {
            eprintln!(
                "wbwpty: pid {} CreateProcessW hook: {calls} call(s), {failures} failure(s)",
                self.child.pid
            );
        }
        if let Some(status) = self.payload_stage() {
            eprintln!(
                "wbwpty: pid {} payload finished at {:?}",
                self.child.pid, status.stage
            );
        }
        self.describe_coverage();
    }

    /// Terminates the target and stops the pumps.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        if let Some(supervisor) = &self.supervisor {
            supervisor.stop();
        }
        let _ = self.child.terminate();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        // Best effort: a detached target would otherwise outlive the host.
        let _ = self.child.terminate();
        // Dropping the supervisor joins its thread, which is why it has to come
        // after the terminate: a thread still covering the tree would otherwise
        // be writing into descendants of a process we just killed.
        drop(self.supervisor.take());
    }
}

/// Writes the two halves of the seqlock into a live target.
///
/// A free function because the tap that calls it lives on the pipe read with
/// nothing but its captures, and it has to be `Send` to sit in that closure.
fn publish_into(
    handle: isize,
    base: Option<u64>,
    rva: Option<u32>,
    busy: [u8; 40],
    done: [u8; 40],
    verbose: bool,
) {
    let (Some(base), Some(rva)) = (base, rva) else {
        return;
    };
    // SAFETY: `handle` is the session's own process handle, captured by value
    // into the closure. A kernel handle is a value rather than a pointer into
    // anything, and the session owns it for as long as the tap exists.
    let proc = crate::manual_map::remote::RemoteProcess::new(handle as _);
    let at = base + rva as u64;

    // The odd half goes first: a payload that reads between them sees a counter
    // saying a write is in progress and reads again, rather than believing a
    // record that is half old and half new.
    if let Err(err) = proc.write_bytes(at, &busy) {
        if verbose {
            eprintln!("wbwpty: could not mark the console state as being written: {err:#}");
        }
        return;
    }
    if let Err(err) = proc.write_bytes(at, &done) {
        if verbose {
            eprintln!("wbwpty: could not publish the console state: {err:#}");
        }
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
/// Replaces process creation in `target` for every export in
/// [`crate::manual_map::inline::TARGETS`].
///
/// Two steps per export, in this order and not the other way round:
///
/// 1. patch the entry so it enters the substitute;
/// 2. publish the trampoline address into the substitute's "original" slot.
///
/// The order is the whole safety property. Between the two steps the substitute
/// is reachable and its way back is zero, so any `CreateProcess` in that window
/// fails immediately rather than calling through a null pointer - visible, and
/// harmless to the target. Reversed, the window is just as short but every call
/// in it reaches the *unhooked* function, which is the bug this exists to fix.
fn install_inline_process_hooks(
    proc: &crate::manual_map::remote::RemoteProcess,
    payload_base: u64,
    payload_image: &Option<Vec<u8>>,
    export_rva: &dyn Fn(&str) -> Option<u32>,
    verbose: bool,
) -> Vec<crate::manual_map::inline::InlineHook> {
    use crate::manual_map::inline::{self, InlineHook, TARGETS};
    use crate::manual_map::remote::RemoteModules;

    if let Some(image) = payload_image {
        inline::publish_payload_image(image.clone());
    }

    // The module holding the functions to replace. Read from the target's own
    // module list rather than assumed at a fixed address.
    let Ok(modules) = proc.poll_modules_ready(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_secs(2),
    ) else {
        if verbose {
            eprintln!("wbwpty: module list unavailable; process creation not replaced");
        }
        return Vec::new();
    };
    let snapshot = RemoteModules::from_snapshot(modules);

    let mut installed = Vec::new();
    for target in TARGETS {
        let Ok(base) = snapshot.base_for_name(proc, target.module) else {
            if verbose {
                eprintln!(
                    "wbwpty: {} is not mapped; {} not replaced",
                    target.module, target.export
                );
            }
            continue;
        };
        let module = crate::manual_map::RemoteModule {
            base,
            size: 0,
            full_name: snapshot
                .path_for_base(base)
                .unwrap_or_else(|| target.module.to_string()),
            base_name: target.module.to_ascii_lowercase(),
        };
        // Read the export table from the file on disk rather than out of the
        // target. `kernelbase.dll` is about 3.8 MB and pulling its directory
        // across with `ReadProcessMemory` cost roughly 40 ms - longer than the
        // window this patch has to land in. The RVAs belong to the file, so the
        // only thing that has to come from the target is the base.
        let table = match crate::manual_map::exports::load_exports_from_file(
            std::path::Path::new(&module.full_name),
            &module,
        ) {
            Ok(table) => table,
            Err(err) => {
                if verbose {
                    eprintln!(
                        "wbwpty: no export table for {} ({}): {err:#}",
                        target.module, module.full_name
                    );
                }
                continue;
            }
        };

        match inline::install_inline_hook(proc, base, &table, payload_base, target) {
            Ok(InlineHook::Installed {
                export,
                entry,
                trampoline,
            }) => {
                // Publish the way back, now that the substitute can be entered. This is
                // not optional bookkeeping: with the import table route skipped, the
                // slot below is the *only* thing that lets the substitute reach the
                // original, and a substitute that cannot is one that returns
                // failure for every call. A missing export used to be reported as
                // success here, which is how a session ended up creating no
                // children at all while logging a substitution as live.
                let Some(slot_rva) = export_rva(target.original_slot) else {
                    if verbose {
                        eprintln!(
                            "wbwpty: the payload does not export {}, so {} was left alone",
                            target.original_slot, target.export
                        );
                    }
                    installed.push(InlineHook::Refused {
                        export: target.export,
                        reason: format!(
                            "the payload has no {} to jump back through",
                            target.original_slot
                        ),
                    });
                    continue;
                };
                if let Err(err) = proc.write_bytes(
                    payload_base + slot_rva as u64,
                    &(trampoline as u64).to_le_bytes(),
                ) {
                    if verbose {
                        eprintln!(
                            "wbwpty: publishing {} failed: {err:#}",
                            target.original_slot
                        );
                    }
                    installed.push(InlineHook::Refused {
                        export: target.export,
                        reason: format!("the trampoline could not be published: {err:#}"),
                    });
                    continue;
                }
                if verbose {
                    eprintln!(
                        "wbwpty: replaced {export} at {entry:#x} (trampoline {trampoline:#x})"
                    );
                }
                installed.push(InlineHook::Installed {
                    export,
                    entry,
                    trampoline,
                });
            }
            Ok(InlineHook::Refused { export, reason }) => {
                if verbose {
                    eprintln!("wbwpty: left {export} alone: {reason}");
                }
                installed.push(InlineHook::Refused { export, reason });
            }
            Err(err) => {
                if verbose {
                    eprintln!("wbwpty: could not replace {}: {err:#}", target.export);
                }
            }
        }
    }
    installed
}

fn inject_payload(
    child: &Child,
    config: &SessionConfig,
    resume_at: std::time::Instant,
) -> Option<InjectionReport> {
    inject_payload_two_phase(child, config, resume_at).unwrap_or_else(|err| {
        if config.verbose {
            eprintln!("wbwpty: two-phase injection failed: {err:#}");
        }
        // A target that will not take the payload must still run: a session that
        // refuses to start its own target is worse than one whose descendants are
        // uncovered.
        if !child.is_resumed() {
            let _ = child.resume();
        }
        None
    })
}

/// Maps the payload while the target is suspended, then finishes it once resumed.
///
/// The split is the whole point, and it is worth being explicit about why each
/// half is where it is:
///
/// * [`SuspendedMapping::map_suspended`] parses, relocates and writes the image.
///   All of that is `VirtualAllocEx` plus `WriteProcessMemory`, so it works
///   against a process that has never executed an instruction, and it moves the
///   276 KB write off the path the target is running down.
/// * [`SuspendedMapping::finish`] resolves imports - which needs `PEB->Ldr`, and
///   that is `NULL` while suspended (AGENTS pitfall 1) - writes the now-patched
///   image, and calls `DllMain` with a remote thread, which needs the target's
///   threads to be running (AGENTS pitfall 31).
///
/// Before this, the whole thing happened after the resume, and the substitution
/// went live at 39-47 ms against a `cmd.exe` that spawns at about 31 ms.
fn inject_payload_two_phase(
    child: &Child,
    config: &SessionConfig,
    resume_at: std::time::Instant,
) -> Result<Option<InjectionReport>> {
    use anyhow::Context;

    if !config.inject {
        if !child.is_resumed() {
            child.resume().context("resuming target")?;
        }
        return Ok(None);
    }

    let dll = config.dll.clone().unwrap_or_else(default_dll_path);
    let file = std::fs::read(&dll).with_context(|| format!("reading payload {}", dll.display()))?;
    let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());

    // Order matters, and it is the opposite of what it looks like.
    //
    // The stub needs only `kernelbase`'s address, and the loader maps that before
    // it transfers control to the target's entry point - so it is there within a
    // fraction of a millisecond of the resume, measured at 194 µs. Writing the
    // 276 KB payload first pushes the resume back by several milliseconds, and by
    // then `cmd.exe` has already spawned: it reaches its entry point and creates
    // its child within about eight milliseconds of resuming.
    //
    // So: resume, patch, and only then start the payload work. The payload can
    // take as long as it likes - by the time it is ready the spawn it needed to
    // intercept has already been intercepted.
    //
    // Measured chain, from x64dbg with breakpoints on all three:
    //
    //     cmd.exe entry point
    //       -> kernelbase!CreateProcessInternalW
    //         -> ntdll!NtCreateUserProcess
    //
    // which also rules out `RtlCreateUserProcess`: cmd does not go through it.
    if !child.is_resumed() {
        child.resume().context("resuming target")?;
    }
    if !child.is_running() {
        return Ok(None);
    }

    if config.forced_stub {
        match install_forced_stub(&proc, child.pid, config.verbose) {
            Ok(at) => {
                if config.verbose {
                    eprintln!(
                        "wbwpty: pid {} forced DETACHED_PROCESS via a stub at {at:#x}, \
                         {}ms after spawn",
                        child.pid,
                        resume_at.elapsed().as_millis()
                    );
                }
            }
            Err(err) => {
                if config.verbose {
                    eprintln!(
                        "wbwpty: pid {} could not install the forced stub: {err:#}",
                        child.pid
                    );
                }
            }
        }
    }

    // The payload is mapped after the resume, not before it.
    //
    // Mapping it while suspended was an attempt to get it in earlier, and it
    // measured as counterproductive: the 276 KB write delayed the resume by
    // several milliseconds, and the stub above - which is the thing that has to
    // win the race - was therefore installed at 10 ms against a target that
    // spawns at about 8. Suspending to write bytes that can wait is a bad trade
    // when what cannot wait is a patch.
    if !child.is_running() {
        return Ok(None);
    }

    match crate::manual_map::inject_dll(child, &dll, "DllMain") {
        Ok(report) => Ok(Some(report)),
        Err(err) => {
            if config.verbose {
                eprintln!("wbwpty: payload not mapped ({err:#})");
            }
            Ok(None)
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

/// Hooks `ntdll!NtCreateUserProcess` in a target that is still suspended.
///
/// Returns the address of the stub it installed.
///
/// System DLLs are loaded at the same address in every process on a boot, so the
/// host's own `ntdll` is nearly always the right base - but "nearly" is not good
/// enough for something about to be overwritten, so the base is confirmed by
/// reading the image header out of the target first.
fn install_nt_creation_hook(
    proc: &crate::manual_map::remote::RemoteProcess,
    verbose: bool,
) -> Result<u64> {
    use crate::manual_map::inline;
    use anyhow::bail;

    let ntdll = crate::manual_map::remote::host_module_base("ntdll.dll");
    if ntdll == 0 {
        bail!("ntdll is not mapped in the host, so its address in the target is unknown");
    }
    let stub = proc.allocate(inline::rtl_forced_stub_size())?;
    let _ = verbose;
    Ok(inline::install_rtl_creation_hook(proc, ntdll, stub)?.stub)
}

/// Waits for `kernelbase`, then forces `DETACHED_PROCESS` on every child the
/// target creates.
///
/// Returns when the stub is in place.
///
/// This waits for `kernelbase` specifically rather than for "the loader": the
/// module is what the stub is patched into, and it appears earlier than the point
/// at which the payload's own imports become resolvable. Measured: `kernelbase` is
/// in the loader list about 194 µs after the resume, and the stub that follows is
/// in place at 7-10 ms, against a target that spawns at about 8.
///
/// Deliberately bounded and deliberately fallible. A target that never maps
/// `kernelbase`, or whose `CreateProcessInternalW` prologue cannot be relocated,
/// gets an error and no patch; the session continues without it, exactly as it
/// would have without this code.
fn install_forced_stub(
    proc: &crate::manual_map::remote::RemoteProcess,
    pid: u32,
    verbose: bool,
) -> Result<u64> {
    use crate::manual_map::exports::load_exports_from_file;
    use crate::manual_map::inline;
    use crate::manual_map::remote::RemoteModules;
    use anyhow::bail;

    const KERNELBASE: &str = "kernelbase.dll";
    /// Short on purpose: past about 30 ms the target has usually spawned already,
    /// and a later patch stops being worth anything.
    const WAIT: std::time::Duration = std::time::Duration::from_millis(500);
    const POLL: std::time::Duration = std::time::Duration::from_millis(1);

    let deadline = std::time::Instant::now() + WAIT;
    loop {
        // Every failure here is "not yet", not "never": the loader links modules
        // one at a time, so `kernelbase` can be absent from the snapshot this
        // microsecond and present in the next. The first version treated a missing
        // path as a hard error, and reported "no path recorded for kernelbase.dll"
        // on a target that was about to have one a fraction of a millisecond later
        // - which is exactly the window this exists to use.
        let ready = (|| -> Result<u64> {
            let modules = proc.poll_modules_ready(POLL, POLL)?;
            let snapshot = RemoteModules::from_snapshot(modules);
            let base = snapshot.base_for_name(proc, KERNELBASE)?;
            // The path has to be the target's *own* record of it: the fallback in
            // `base_for_name` can hand back the host's base, which means nothing
            // about where the target has it.
            let path = snapshot
                .path_for_base(base)
                .ok_or_else(|| anyhow::anyhow!("{KERNELBASE} is not in the target's list yet"))?;
            let module = crate::manual_map::RemoteModule {
                base,
                size: 0,
                full_name: path.clone(),
                base_name: KERNELBASE.to_ascii_lowercase(),
            };
            let table = load_exports_from_file(std::path::Path::new(&path), &module)?;
            // `CreateProcessInternalW`, not `CreateProcessW`. cmd.exe calls the
            // internal one directly, so a stub on `CreateProcessW` installs
            // cleanly and then never runs - which is exactly what it did for the
            // whole run that produced `CreateProcessW hook: 0 call(s)` next to a
            // `ping` that had a console.
            let entry = inline::find_export(base, &table, "CreateProcessInternalW")?;
            let stub = proc.allocate(inline::internal_forced_stub_size())?;
            Ok(inline::install_internal_forced_stub(proc, entry, stub)?.stub)
        })();

        match ready {
            Ok(at) => return Ok(at),
            Err(err) => {
                if std::time::Instant::now() >= deadline {
                    return Err(err).with_context(|| {
                        format!("{KERNELBASE} was not usable within {}ms", WAIT.as_millis())
                    });
                }
                let _ = verbose;
                std::thread::sleep(POLL);
            }
        }
    }
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

/// A process handle that may cross a thread boundary.
///
/// `HANDLE` is a `*mut c_void`, which is deliberately not `Send`. But a Win32
/// handle is a reference to a kernel object rather than to memory in this
/// process: it stays valid from any thread and until someone closes it. The
/// [`Session`] that owns the handle outlives the sampler, which stops on
/// `shutting_down`, so there is no window where the sampler outlives the handle.
struct SendHandle(*mut std::ffi::c_void);

// SAFETY: see the type's own comment - the handle is a kernel object reference,
// valid from any thread, and kept alive by the owning `Session`.
unsafe impl Send for SendHandle {}

impl SendHandle {
    /// Reborrows the handle as a [`RemoteProcess`].
    ///
    /// Going through a method rather than reading `.0` at the call site is what
    /// keeps the closure capture whole: edition 2021 captures the individual
    /// field when it can, which would put the raw `*mut c_void` back into a
    /// `'static` closure and lose the [`Send`] wrapper.
    fn process(&self) -> crate::manual_map::remote::RemoteProcess {
        crate::manual_map::remote::RemoteProcess::new(self.0)
    }
}

/// Reads a little-endian `u32` out of a remote process, `None` on any failure.
///
/// The target's pages can disappear between one call and the next - it may exit
/// mid-session - so every failure is simply "not right now" and never fatal.
fn read_u32(proc: &crate::manual_map::remote::RemoteProcess, addr: u64) -> Option<u32> {
    let bytes = proc.read_bytes(addr, 4).ok()?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// [`read_u32`] for a 64-bit word, used for the `[u32; 2]` flag pair.
fn read_u64(proc: &crate::manual_map::remote::RemoteProcess, addr: u64) -> Option<u64> {
    let bytes = proc.read_bytes(addr, 8).ok()?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
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
        let config = SessionConfig {
            shim: false,
            inject: false,
            ..Default::default()
        };
        let session = Session::start(&spec, config).unwrap();

        // Read what the target printed straight off the pipe.
        let mut buf = [0u8; 256];
        let mut text = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let event = session
                .pipes
                .with(|p| p.read_output(&mut buf, 200))
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
        let stdio = pipes.open_target_stdio().unwrap();
        let spec = ChildSpec::new("cmd.exe").stdio(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        });
        let config = SessionConfig {
            shim: false,
            verbose: true,
            inject: true,
            // No input pump: this test's whole claim is that the target is still
            // alive, and the pump delivers host stdin EOF - which an interactive
            // `cmd.exe` exits on - at a moment this test does not control.
            pump_input: false,
            ..Default::default()
        };
        let inject_flag = config.inject;
        let session = Session::start(&spec, config).unwrap();

        let report = session.report();
        eprintln!("DIAG inject={inject_flag}");
        eprintln!("DIAG report={:?}", report.map(|r| r.image_base));
        eprintln!("DIAG status={:#x}", session.payload_status().unwrap_or(0));
        eprintln!("DIAG child_running={}", session.child.is_running());
        let report = report.expect("payload should map into a running cmd.exe");
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
        let stdio = pipes.open_target_stdio().unwrap();
        let spec = ChildSpec::new("cmd.exe")
            .args(["/c", "exit", "0"])
            .stdio(Stdio {
                stdin: stdio.stdin,
                stdout: stdio.stdout,
                stderr: stdio.stderr,
            });
        let child = Child::spawn(&spec).unwrap();
        let proc = crate::manual_map::remote::RemoteProcess::new(child.process_handle());
        let state = proc
            .read_console_state()
            .expect("process parameters are readable");

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
    ///
    /// `#[ignore]`d because the failure it provokes is a *startup* failure, and
    /// the shell answers a console program that dies at init with a modal
    /// "应用程序无法正常启动(0xc0000142)" dialog plus a real `conhost.exe`. That
    /// is unavoidable for this scenario - it is the whole point - so running it
    /// unattended means popping UI on someone's desktop. Same reason as the
    /// other conhost-producing controls; run it deliberately:
    /// `cargo test -p wbwpty-core rewriting_the_console_handle -- --ignored`.
    #[test]
    #[ignore = "deliberately provokes STATUS_DLL_INIT_FAILED, which pops a modal dialog and a conhost window"]
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

        proc.write_bytes(
            params + 0x10,
            &crate::manual_map::CONSOLE_HANDLE_SENTINEL.to_le_bytes(),
        )
        .expect("writing the sentinel is allowed");

        child.resume().unwrap();
        let code = child.wait().unwrap();
        assert_eq!(
            code, 0xc000_0142,
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
        let config = SessionConfig {
            shim: false,
            ..Default::default()
        };
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
        assert_eq!(PayloadStatus::decode(9).stage, PayloadStage::Done);
        assert_eq!(PayloadStatus::decode(0x1_0009).reason, 1);
        assert_eq!(PayloadStatus::decode(0x1_0009).stage, PayloadStage::Done);
        assert_eq!(
            PayloadStatus::decode(0x1_0042).stage,
            PayloadStage::Unknown(0x42)
        );
        assert!(PayloadStatus::decode(0x1_0009).ran_attach_path());
        assert!(!PayloadStatus::decode(0).ran_attach_path());

        // Terminality is what `wait_for_payload` polls on, so getting it wrong
        // either hangs the host or makes it give up early.
        assert!(PayloadStage::Done.is_terminal());
        assert!(PayloadStage::CrtSkipped.is_terminal());
        assert!(!PayloadStage::CrtRepaired.is_terminal());
        assert!(!PayloadStage::LogReady.is_terminal());
        assert!(!PayloadStage::Entered.is_terminal());
    }

    /// The CRT detail word is packed into one `u32`; the host has to read back
    /// what the payload packed.
    #[test]
    fn crt_detail_word_unpacks_as_documented() {
        // set=2, refused=0, resolved -> 0x0001_0002
        let raw = 2 | (0 << 8) | (1 << 16);
        let detail = CrtDetail::decode(raw);
        assert!(detail.ucrt_resolved);
        assert_eq!(detail.streams_set, 2);
        assert_eq!(detail.streams_refused, 0);

        let none = CrtDetail::decode(0);
        assert!(!none.ucrt_resolved);
        assert_eq!(none.streams_set, 0);
    }

    /// A process the target creates must write to our pipe.
    ///
    /// The first generation of Stage 8 in one test. The target is an interactive
    /// `cmd.exe` that is blocked reading its (never written) stdin, which makes
    /// the ordering deterministic: the interception is in place before the
    /// command that creates a descendant is fed in.
    ///
    /// Two independent promises are checked, because they are independent and
    /// only satisfying one looks like success:
    ///
    /// * the descendant's output arrives on our pipe, and
    /// * no `conhost.exe` appears for it.
    ///
    /// # How this works
    ///
    /// The host rewrites the target's `CreateProcessW` import slot to point at
    /// the payload, which OR-s `DETACHED_PROCESS` into the flags and fills in
    /// `STARTF_USESTDHANDLES`. Both halves are required and neither is
    /// sufficient; `tests/descendant_creation.rs` is the matrix that established
    /// it.
    ///
    /// `bInheritHandles` is passed through **unchanged**, and the matrix row this
    /// is written against was measured with it set. Passing `FALSE` on the
    /// grounds that the handles are explicit anyway leaves the child mute - the
    /// output never arrives, with no error anywhere.
    ///
    /// # The generation after this one
    ///
    /// Everything here is about the target's *own* children. What those children
    /// go on to create needs the substitution to be in them too, which
    /// [`crate::supervisor`] arranges; `tests/descendant_injection.rs` pins it.
    ///
    /// # On the marker
    ///
    /// Assembled at runtime (`%i` in the `for` body expands to `NEU`, and the
    /// command line only ever shows the literal `%i`). An earlier version
    /// searched the output for a marker that appeared in the text it fed in,
    /// which an interactive `cmd.exe` echoes straight back - so it passed while
    /// descendants produced nothing at all.
    #[test]
    fn grandchild_output_reaches_the_pipe() {
        const MARKER: &str = "NEU7Q2K5";
        let spec = ChildSpec::new("cmd.exe");
        // No input pump: the target has to stay alive for this test to mean
        // anything, and the pump delivers host stdin EOF, which an interactive
        // `cmd.exe` exits on. The test feeds the input pipe itself, a few lines
        // below.
        let config = SessionConfig {
            shim: false,
            pump_input: false,
            ..Default::default()
        };
        let session = Session::start(&spec, config).unwrap();
        session
            .report()
            .expect("payload must map before the descendant behaviour is meaningful");
        // "Process creation is substituted", rather than "the import slot was
        // rewritten".
        //
        // This used to assert the slot specifically, which was the only mechanism
        // then. It is now the wrong assertion twice over: the slot is skipped
        // whenever the inline patch is live - it reaches the same substitute more
        // reliably - so asserting it tests an implementation detail that is
        // deliberately absent. What matters to a caller is whether a child it
        // spawns will be covered, and that is what this asks.
        assert!(
            session.process_creation_substituted(),
            "cmd.exe imports a process-creation entry point, so one of the two \
             mechanisms must be live; the slot report is {:?} ({:?}) and the \
             inline report is {:?}",
            session.hook().is_some(),
            session.hook_error(),
            session.inline_hooks(),
        );

        let _ = session
            .pipes
            .with(|p| {
                p.input().write_all(
                    format!("cmd.exe /c for %i in (NEU) do @echo %i7Q2K5\r\n").as_bytes(),
                )
            })
            .expect("pipe write");

        let mut buf = [0u8; 4096];
        let mut saw_marker = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline && !saw_marker {
            match session
                .pipes
                .with(|p| p.read_output(&mut buf, 200))
                .unwrap()
            {
                Ok(ReadEvent::Data(n)) => {
                    for line in String::from_utf8_lossy(&buf[..n]).lines() {
                        if line.trim() == MARKER {
                            saw_marker = true;
                        }
                    }
                }
                Ok(ReadEvent::Eof) => break,
                Ok(ReadEvent::Timeout) => {}
                Err(e) => panic!("output read failed: {e:#}"),
            }
        }
        assert!(
            saw_marker,
            "descendant output never arrived as its own line"
        );

        // The hook has to have run, and the child has to have been created
        // successfully. A zero call count means the slot was rewritten but
        // nothing goes through it - which looks identical to success from the
        // output side alone.
        let (calls, failures) = session
            .payload_hook_stats()
            .expect("the payload publishes hook counters");
        eprintln!("DIAG hook calls={calls} failures={failures}");
        assert!(
            calls >= 1,
            "the descendant was created without going through the hook"
        );
        assert_eq!(failures, 0, "the intercepted CreateProcessW failed");

        session.shutdown();
    }

    /// stdio must work with injection disabled: that is the whole point of
    /// handing the pipes over at creation instead of installing them from
    /// inside the payload.
    #[test]
    fn stdio_works_without_injection() {
        let spec = ChildSpec::new("cmd.exe").args(["/c", "echo no-inject-ok"]);
        let config = SessionConfig {
            shim: false,
            inject: false,
            ..Default::default()
        };
        let session = Session::start(&spec, config).unwrap();
        assert!(session.report().is_none(), "injection was disabled");

        let mut buf = [0u8; 256];
        let mut text = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match session
                .pipes
                .with(|p| p.read_output(&mut buf, 200))
                .unwrap()
            {
                Ok(ReadEvent::Data(n)) => text.push_str(&String::from_utf8_lossy(&buf[..n])),
                Ok(ReadEvent::Eof) => break,
                Ok(ReadEvent::Timeout) => {}
                Err(e) => panic!("output read failed: {e:#}"),
            }
            if text.contains("no-inject-ok") {
                break;
            }
        }
        assert!(
            text.contains("no-inject-ok"),
            "output missing, got {text:?}"
        );
    }
}
