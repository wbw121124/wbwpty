//! Does writing the console sentinel into a descendant keep *its* children from
//! getting a console?
//!
//! The chain is fixed by fixtures rather than by `cmd`'s parser, so it is the
//! same every run:
//!
//! ```text
//!   wbwpty (host)
//!     └─ probe#1              the session target; the substitution is in it
//!          └─ probe#2          created by probe#1, so DETACHED_PROCESS + our pipes
//!               └─ ping.exe     created by probe#2 with plain flags
//! ```
//!
//! probe#1's child is the generation the substitution covers, so probe#2 has no
//! console. probe#2 is the generation it does *not* cover, and `ping` is the
//! process whose console is in question. Each probe reports its child's pid
//! before waiting for it, so attribution is by pid and not by counting.
//!
//! Two variants, because the answer decides the design:
//!
//! * sentinel written into probe#2: if this is enough, one `CreateProcess` write
//!   per descendant replaces recursive injection entirely.
//! * nothing written: the baseline the substitution alone produces.
//!
//! # Superseded for the question it was built to answer
//!
//! Kept, because the two variants are still the only place the sentinel's
//! effect on an *uncovered* generation is measured side by side. But the
//! fixture has a fault that makes both runs measure something else: probe#1
//! spawns probe#2 in the first few milliseconds of its life, while injection is
//! still waiting for a loader to settle, so probe#2 is created *unsubstituted*
//! and already owns a console when the sentinel is written into it - which is why
//! `patch_console_state` reports `Unchanged` and the question stays unanswered.
//!
//! `tests/descendant_injection.rs` is the version that holds each generation
//! still until the previous one is covered, and it answers a different question
//! better: rather than whether the sentinel is enough on its own, whether
//! covering every generation is.

use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::inspect::{self, ProcessEntry};
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::manual_map::remote::ConsoleState;
use wbwpty_core::session::{Session, SessionConfig};

/// `ping -n 12` lives about eleven seconds; six is enough to notice a console
/// host without making the test wait for the whole thing.
const OBSERVE: Duration = Duration::from_secs(6);
const SAMPLE: Duration = Duration::from_millis(20);

struct TreeGuard {
    root: u32,
}

impl TreeGuard {
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
        for _ in 0..20 {
            if self.sweep() == 0 && self.sweep() == 0 {
                return;
            }
            std::thread::sleep(SAMPLE);
        }
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "wbwpty-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

struct Observation {
    console_host: Option<ProcessEntry>,
    tree: Vec<String>,
    output: Vec<String>,
    hook_calls: u32,
    /// The flags the payload actually handed to `CreateProcessW`.
    hook_flags: Option<(u32, u32)>,
    /// The child's own console bookkeeping, read while it was still alive.
    probe2_console: Option<ConsoleState>,
}

/// Runs the three-level chain and reports what happened.
///
/// `sentinel` decides whether the console sentinel is written into probe#2, the
/// one process whose children the substitution cannot reach.
fn observe(sentinel: bool) -> Observation {
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_wbwpty-spawn-probe"));
    let ping_pid = scratch("ping.pid");
    let _ = std::fs::remove_file(&ping_pid);

    // The probe takes everything after `--` as one command *line*, and the host
    // quotes an argument that contains spaces and escapes the quotes inside it.
    // So the nested invocation has to be a single argument that quotes *only* the
    // part that needs it - quoting the whole thing would make the probe see one
    // literal token starting with a quote, which it rejects as an unknown flag.
    // Both paths here are free of spaces, which is what lets them go unquoted.
    let inner = format!(
        "{} --pidfile {} -- \"ping -n 12 127.0.0.1\"",
        probe.display(),
        ping_pid.display()
    );
    eprintln!("nested command: {inner}");

    let config = SessionConfig {
        shim: false,
        inject: true,
        ..Default::default()
    };
    let session = Session::start(
        &ChildSpec::new(probe).arg("--").arg(inner.as_str()),
        config,
    )
    .expect("session");
    let guard = TreeGuard {
        root: session.pid(),
    };

    let mut buf = [0u8; 4096];
    let mut console_host = None;
    let mut tree: Vec<String> = Vec::new();
    let mut output: Vec<String> = Vec::new();
    let mut probe2 = None;
    let mut sentinel_written = None;
    let mut probe2_console = None;
    let deadline = Instant::now() + OBSERVE;
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 0)) {
            Some(Ok(ReadEvent::Data(n))) => {
                for line in String::from_utf8_lossy(&buf[..n]).lines() {
                    if !output.iter().any(|o| o == line) {
                        output.push(line.to_string());
                    }
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) | Some(Err(_)) => {}
        }

        if probe2.is_none() {
            // probe#2 is the target's only child; there is no shell in the way
            // to misparse the tree.
            probe2 = inspect::process_table()
                .ok()
                .and_then(|table| {
                    // The child of the target, by parentage. Selecting "some
                    // descendant" is not enough: the set comes back sorted by pid,
                    // and a console host in the tree can have a lower one than the
                    // process we mean - patching the console host teaches nothing
                    // about console hosts.
                    table
                        .iter()
                        .find(|e| e.parent == guard.root)
                        .map(|e| e.pid)
                });
            if let Some(pid) = probe2 {
                if let Ok(p) = wbwpty_core::manual_map::remote::RemoteProcess::open(pid) {
                    if probe2_console.is_none() {
                        probe2_console = p.read_console_state().ok();
                    }
                }
                if sentinel && sentinel_written.is_none() {
                    match wbwpty_core::manual_map::remote::RemoteProcess::open(pid) {
                        Ok(p) => {
                            sentinel_written = Some(p.patch_console_state().map_err(|e| e.to_string()))
                        }
                        Err(err) => sentinel_written = Some(Err(err.to_string())),
                    }
                }
            }
        }

        let table = inspect::process_table().expect("process table");
        if console_host.is_none() {
            console_host = inspect::descendant_console_hosts(&table, guard.root)
                .into_iter()
                .next();
        }
        let mine = inspect::descendants_of(&table, guard.root);
        for e in table
            .iter()
            .filter(|e| e.pid != guard.root && mine.contains(&e.pid))
        {
            let line = format!("{} (pid {}, parent {})", e.name, e.pid, e.parent);
            if !tree.contains(&line) {
                tree.push(line);
            }
        }
        std::thread::sleep(SAMPLE);
    }

    let ping: Option<u32> = std::fs::read_to_string(&ping_pid)
        .ok()
        .and_then(|t| t.trim().parse().ok());
    let _ = std::fs::remove_file(&ping_pid);
    // Read *after* the observation, not right after `Session::start`: these
    // counters only move when the target creates something. An earlier version
    // read them up front and reported zero for a run in which the substitution
    // had in fact been reached, which is what made both tests in this file fail
    // for a reason that had nothing to do with the sentinel.
    let (calls, _) = session.payload_hook_stats().unwrap_or((0, 0));
    session.shutdown();
    drop(guard);

    let hook_flags = session.payload_hook_flags();
    eprintln!(
        "probe2={probe2:?} ping={ping:?} hook_flags={:?} (creation_flags, calls)\n\
         sentinel={sentinel_written:?}\n\
         probe2_console={probe2_console:?}\n\
         console_host={:?}\ntree:\n  {}\noutput:\n  {}",
        console_host.as_ref().map(|h| (h.pid, h.parent)),
        hook_flags,
        tree.join("\n  "),
        output.join("\n  ")
    );

    Observation {
        console_host,
        tree,
        output,
        hook_calls: calls,
        hook_flags: session.payload_hook_flags(),
        probe2_console,
    }
}

#[test]
#[ignore = "deliberately causes a console host; run only when told"]
fn baseline_substitution_alone() {
    let seen = observe(false);
    eprintln!(
        "baseline: console_host={:?} hook_flags={:?} probe2_console={:?} output={:?}",
        seen.console_host.as_ref().map(|h| (h.pid, h.parent)),
        seen.hook_flags,
        seen.probe2_console,
        seen.output
    );
    assert!(seen.hook_calls >= 1, "probe#2 must go through the substitution");
    assert_eq!(seen.tree.len(), 2, "expected probe#2 and ping, got {:?}", seen.tree);
}

#[test]
#[ignore = "deliberately causes a console host; run only when told"]
fn sentinel_in_the_uncovered_generation() {
    let seen = observe(true);
    eprintln!(
        "sentinel: console_host={:?} hook_flags={:?} probe2_console={:?} output={:?}",
        seen.console_host.as_ref().map(|h| (h.pid, h.parent)),
        seen.hook_flags,
        seen.probe2_console,
        seen.output
    );
    assert!(seen.hook_calls >= 1, "probe#2 must go through the substitution");
    assert_eq!(seen.tree.len(), 2, "expected probe#2 and ping, got {:?}", seen.tree);
}