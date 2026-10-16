//! Does the interception actually keep a `conhost.exe` out of the target's tree?
//!
//! `tests/descendant_creation.rs` measured what a child's creation flags have to
//! be, using a fixture that sets them directly. That answers "which flags work",
//! not "does our code produce those flags" - the IAT substitution in
//! `manual_map::hook` is the only thing in this project that turns
//! `DETACHED_PROCESS` + `STARTF_USESTDHANDLES` from a measurement into a
//! promise, and until a test drives a *real* `cmd.exe` through it and looks at
//! the process tree, the promise is unpinned.
//!
//! ```text
//!   Session(inject = true)   -> target cmd.exe -> its own cmd.exe -> ?
//!   Session(inject = false)  -> target cmd.exe -> its own cmd.exe -> conhost.exe
//! ```
//!
//! Both halves are asserted, and that is the point. "No console host" passes for
//! free if the sampler is broken, if the descendant never started, or if it
//! exited before the first sample. Only a control that *must* show the console
//! host can tell those apart from the feature working. An earlier sibling test
//! passed while descendants produced nothing at all for exactly this reason.
//!
//! # These two tests provoke console hosts, so they are ignored by default
//!
//! Running either one puts a real `conhost.exe` window on the operator's
//! desktop - that is the behaviour under test, so there is no way to observe it
//! without producing it. They are `#[ignore]`d, which means
//! `cargo test --release -- --ignored descendant_conhost` runs them and nothing
//! else does.
//!
//! When they do run, [`TreeGuard`] takes the whole tree down again on the way
//! out, including on panic. A failing assertion used to skip cleanup entirely,
//! which left orphaned console hosts on the machine with no owner: their client
//! had exited, so nothing was left to reap them.
//!
//! # Current result
//!
//! An earlier version of this file said the substitution was not being reached at
//! all - `hook_calls = 0`, a rewritten slot nothing called. That was wrong, and
//! wrong for a reason worth keeping: x64dbg shows `cmd.exe` calling the very
//! slot that gets rewritten, and the payload counts the calls. The promise holds
//! for the generation that inherits the substitution, and only that one - a
//! process created by a *descendant* is created with whatever flags that
//! descendant chose.
//!
//! That gap is now closed by [`crate::supervisor`], which gives every
//! descendant the substitution as well; `tests/descendant_injection.rs` is where
//! that is pinned. What is left here is the measuring apparatus this project
//! needed to get there: ancestry-attributed console host detection, per-pid
//! cleanup, and a control that must show a console host or the other tests prove
//! nothing.

use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::inspect::{self, ProcessEntry};
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::session::{Session, SessionConfig};

/// Assembled at runtime so the command line the interactive target echoes back
/// can never contain it. `cmd` echoes what it is fed, so a marker that appears
/// in the fed text is found even when the descendant printed nothing.
const MARKER: &str = "NEU7Q2K5";

/// What the target's child is told to run.
///
/// The `& cmd.exe /c rem` is load bearing. `cmd /c "<single command>"` is
/// optimised: cmd runs the command itself instead of spawning a child, so the
/// process tree comes out one level shallower and the grandchild this file is
/// about never appears. The nested `cmd.exe` guarantees a real second
/// generation, and `ping` gives it a child of its own.
const DESCENDANT_COMMAND: &str =
    "ping -n 3 127.0.0.1 > nul & cmd.exe /c \"\"for %i in (NEU) do @echo %i7Q2K5\"\"\"";

/// Keeps the target alive for the whole observation window.
///
/// Without it the target reads EOF as soon as the harness's stdin is closed -
/// the input pump turns that into a pipe EOF - prints its prompt and exits. Then
/// every later read is made against a dead process, `image_base()` answers `0`,
/// and the measurement silently reports "nothing happened" for a run that in
/// fact did everything. The same fault made an earlier version of this file
/// read `None` for every published word.
const KEEP_AWAKE: &str = "ping -n 20 127.0.0.1 > nul";

/// Sampling window. The descendant lives about three seconds; the tail is slack
/// for a machine that is busy.
const OBSERVE: Duration = Duration::from_secs(8);
const SAMPLE: Duration = Duration::from_millis(20);

/// Takes down everything the session created, whether the test passed, failed
/// or panicked.
///
/// Three details, each of them learned the hard way:
///
/// * It runs on drop, so an assertion failure cannot skip it.
/// * Descendants die before ancestors. Killing a parent first reparents its
///   children to something else, and they then fall out of the ancestry walk
///   that finds them in the first place.
/// * Console hosts die first of all. One outlives the process that owned it -
///   its client exits, the host does not - so it has to be killed explicitly or
///   it stays on the machine as an orphan with nothing left to reap it.
struct TreeGuard {
    root: u32,
}

impl TreeGuard {
    /// One pass: kill hosts, then descendants deepest first, then the root.
    fn sweep(&self) -> usize {
        let Ok(table) = inspect::process_table() else {
            return 0;
        };
        let mine = inspect::descendants_of(&table, self.root);
        let alive = mine.len().saturating_sub(1);

        for host in inspect::descendant_console_hosts(&table, self.root) {
            eprintln!("cleanup: console host pid {}", host.pid);
            let _ = inspect::terminate(host.pid);
        }

        let mut by_depth: Vec<(usize, u32)> = mine
            .iter()
            .filter(|&&pid| pid != self.root)
            .map(|&pid| {
                (
                    inspect::ancestry_depth(&table, self.root, pid).unwrap_or(0),
                    pid,
                )
            })
            .collect();
        by_depth.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, pid) in by_depth {
            let _ = inspect::terminate(pid);
        }
        alive
    }
}

impl Drop for TreeGuard {
    fn drop(&mut self) {
        // The target itself goes through `Session`, but a tree can grow a
        // process after the target has exited, so keep sweeping until two
        // consecutive passes find nothing.
        for _ in 0..20 {
            if self.sweep() == 0 {
                if self.sweep() == 0 {
                    return;
                }
            }
            std::thread::sleep(SAMPLE);
        }
        eprintln!(
            "cleanup: pid {} still has processes; run `inspect::descendants_of` by hand",
            self.root
        );
    }
}

/// What one run observed.
#[derive(Debug)]
struct Observation {
    /// A `conhost.exe` attributable to the target's tree was seen.
    console_host: Option<ProcessEntry>,
    /// The descendant's own output arrived on our pipe, as its own line.
    output_reached_pipe: bool,
    /// Everything the target spawned, in the order it appeared.
    descendants: Vec<String>,
    /// How many times the substituted `CreateProcessW` ran.
    hook_calls: u32,
}

/// Runs a real `cmd.exe` session and watches what its children do.
///
/// `inject` decides whether the payload is mapped and the target's
/// `CreateProcessW` import slot is rewritten. `patch_descendants` decides
/// whether the console sentinel is also written into every process the target
/// spawns. Everything else is identical, so any difference in the result belongs
/// to one of those two and nothing else.
fn observe(inject: bool, patch_descendants: bool) -> Observation {
    let spec = ChildSpec::new("cmd.exe");
    let config = SessionConfig {
        shim: false,
        inject,
        ..Default::default()
    };
    let session = Session::start(&spec, config).expect("session");
    let guard = TreeGuard {
        root: session.pid(),
    };

    if inject {
        assert!(
            session.hook().is_some(),
            "the target imports CreateProcessW, so the slot must be rewritten; \
             it was not: {:?}",
            session.hook_error()
        );
    }

    // The target is interactive and blocked reading its stdin, so the
    // interception is in place before the command that creates a descendant is
    // fed in. Nothing here races with setup. The trailing keep-awake is what
    // stops the target from exiting on stdin EOF mid-measurement.
    let command = format!(
        "cmd.exe /c \"{DESCENDANT_COMMAND}\"\r\n{KEEP_AWAKE}\r\n"
    );
    // Two expects, because there are two failure modes and they are not the same
    // one: `with` yields an `Option` (the pipe lock is poisoned) and the write
    // itself yields an `io::Result`. Only the first was being handled, so a
    // failed write was silently discarded.
    session
        .pipes()
        .with(|p| p.input().write_all(command.as_bytes()))
        .expect("input pipe is gone")
        .expect("writing the command to the target");

    let proc = wbwpty_core::manual_map::remote::RemoteProcess::new(session.process_handle());
    let base = proc.image_base().unwrap_or(0);
    let slot_rva = wbwpty_core::manual_map::iat::find_imports(
        &std::fs::read("C:\\Windows\\System32\\cmd.exe").unwrap_or_default(),
        &["CreateProcessW"],
    )
    .ok()
    .and_then(|s| s.first().map(|x| x.iat_rva))
    .unwrap_or(0);
    let read_slot = |proc: &wbwpty_core::manual_map::remote::RemoteProcess| -> Option<u64> {
        let bytes = proc.read_bytes(base + slot_rva as u64, 8).ok()?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    };

    let mut buf = [0u8; 4096];
    let mut saw_marker = false;
    let mut console_host = None;
    let mut descendants = Vec::new();
    let mut slot_history = Vec::new();
    let mut patched: Vec<u32> = Vec::new();
    let mut stats_at_marker = None;
    let mut alive_at_end = false;
    let deadline = Instant::now() + OBSERVE;
    while Instant::now() < deadline {
        match session
            .pipes()
            .with(|p| p.read_output(&mut buf, 0))
        {
            Some(Ok(ReadEvent::Data(n))) => {
                for line in String::from_utf8_lossy(&buf[..n]).lines() {
                    if line.trim() == MARKER {
                        saw_marker = true;
                        stats_at_marker = session.payload_hook_stats();
                    }
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) | Some(Err(_)) => {}
        }

        let slot = read_slot(&proc);
        if slot_history.last().map(|&s| s) != slot {
            slot_history.push(slot.unwrap_or(0));
        }

        let table = inspect::process_table().expect("process table");
        if console_host.is_none() {
            console_host = inspect::descendant_console_hosts(&table, guard.root)
                .into_iter()
                .next();
        }
        let mine = inspect::descendants_of(&table, guard.root);
        for entry in table
            .iter()
            .filter(|e| e.pid != guard.root && mine.contains(&e.pid))
        {
            let line = format!("{} (pid {}, parent {})", entry.name, entry.pid, entry.parent);
            if !descendants.iter().any(|d: &String| *d == line) {
                descendants.push(line.clone());
            }
            // The console sentinel is written into every generation, not just
            // the target. `CreateProcess` reads the *parent's*
            // `ProcessParameters->ConsoleHandle` to decide whether the child
            // inherits a console or is allocated a fresh one - and a fresh
            // console is a `conhost.exe`.
            if patch_descendants && !patched.contains(&entry.pid) {
                patched.push(entry.pid);
                let tag = line.clone();
                match wbwpty_core::manual_map::remote::RemoteProcess::open(entry.pid) {
                    Ok(child_proc) => match child_proc.patch_console_state() {
                        Ok(patch) => eprintln!("patched {}: {:?}", tag, patch),
                        Err(err) => eprintln!("patch {} failed: {err:#}", tag),
                    },
                    Err(err) => eprintln!("open {} failed: {err:#}", tag),
                }
            }
        }
        alive_at_end = table.iter().any(|e| e.pid == guard.root);

        std::thread::sleep(SAMPLE);
    }

    let hook_calls = session.payload_hook_stats().map(|(calls, _)| calls).unwrap_or(0);
    eprintln!(
        "root={} alive={:?} image_base={:#x} slot_rva={:#x}\n\
         slot history (slot address -> value): {:?}\n\
         substitute={:?} original={:?}\n\
         stats_at_marker={:?} stats_now={:?} status={:?}\n\
         descendants={:?}",
        guard.root,
        alive_at_end,
        base,
        slot_rva,
        slot_history
            .iter()
            .map(|v| format!("{v:#018x}"))
            .collect::<Vec<_>>(),
        session.hook().map(|h| h.substitute),
        session.hook().map(|h| h.original),
        stats_at_marker,
        session.payload_hook_stats(),
        session.payload_status(),
        descendants,
    );
    session.shutdown();
    drop(guard);

    Observation {
        console_host,
        output_reached_pipe: saw_marker,
        descendants,
        hook_calls,
    }
}

/// The promise, with every generation given the console sentinel.
#[test]
#[ignore = "provokes a console host on the operator's desktop; run deliberately"]
fn the_intercepted_target_leaves_no_console_host_behind() {
    let seen = observe(true, true);

    eprintln!(
        "interception + per-generation sentinel: conhost={:?} output={} hook_calls={} descendants={:?}",
        seen.console_host.as_ref().map(|h| (h.pid, h.parent)),
        seen.output_reached_pipe,
        seen.hook_calls,
        seen.descendants
    );

    assert!(
        seen.hook_calls >= 1,
        "the descendant was created without going through the substitution; \
         a slot that is rewritten but never called is identical to no feature"
    );
    assert!(
        seen.output_reached_pipe,
        "the grandchild's output never arrived as its own line"
    );
    assert!(
        seen.console_host.is_none(),
        "a conhost.exe (pid {:?}, parent {:?}) appeared in the target's tree",
        seen.console_host.as_ref().map(|h| h.pid),
        seen.console_host.as_ref().map(|h| h.parent),
    );
}

/// Interception alone, with no sentinel beyond the target's own.
///
/// Recorded rather than asserted: this is the state the shipped code is in, and
/// it is what turned out to be a third of the problem. The substitution only
/// covers the target's own `CreateProcessW`, so everything the *descendant*
/// spawns is created with whatever flags the descendant chose.
#[test]
#[ignore = "records the current behaviour; provokes a console host"]
fn the_second_generation_is_not_covered_by_the_substitution() {
    let seen = observe(true, false);

    eprintln!(
        "interception only: conhost={:?} output={} hook_calls={} descendants={:?}",
        seen.console_host.as_ref().map(|h| (h.pid, h.parent)),
        seen.output_reached_pipe,
        seen.hook_calls,
        seen.descendants
    );

    assert!(
        seen.hook_calls >= 1,
        "the descendant must still go through the substitution"
    );
}

/// The control the other tests depend on.
///
/// Without the substitution the very same command produces a console host, and
/// the sampler finds it. If this ever stops being true they have stopped
/// measuring anything, and it is the assertion - not the feature - that is
/// broken.
///
/// Ignored permanently: it asserts the bug, so it can never be a gate, and it
/// flashes a console window on every run.
#[test]
#[ignore = "measures the absence of the feature; not a regression gate"]
fn without_the_interception_the_same_command_does_cause_a_console_host() {
    let seen = observe(false, false);

    eprintln!(
        "without interception: conhost={:?} output={} descendants={:?}",
        seen.console_host.as_ref().map(|h| (h.pid, h.parent)),
        seen.output_reached_pipe,
        seen.descendants
    );

    assert_eq!(
        seen.hook_calls, 0,
        "no payload, so nothing can be intercepted"
    );
    assert!(
        seen.console_host.is_some(),
        "the sampler has to be able to detect the console host this project \
         exists to prevent, or the other tests in this file prove nothing"
    );
}