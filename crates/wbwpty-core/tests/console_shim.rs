//! Does the console API substitution actually let a program write?
//!
//! A program whose stdout is a pipe is fine as long as it writes with
//! `WriteFile`, `printf` or `println!`. Plenty of programs do not: they ask for a
//! console and use `WriteConsoleW`, which on a pipe is `ERROR_INVALID_HANDLE`
//! and produces nothing. Worse, the usual reaction to that is to turn the
//! output off.
//!
//! So the question this file answers is not "is the hook installed" - that is
//! checkable by reading a slot - but **"does a program's `WriteConsoleW` output
//! reach the pipe, and does it not without the shim"**.
//!
//! ```text
//!   wbwpty → wbwpty-spawn-probe --console-write <text>
//! ```
//!
//! # Why the fixture gates
//!
//! The probe waits for a file before it does anything. Injection cannot complete
//! before the target's loader settles, which takes on the order of a hundred
//! milliseconds, and this probe exits the instant it is released. Without the
//! gate the test would mostly be measuring that race - see AGENTS pitfall 27,
//! which is what an earlier version of this repository measured by accident.
//!
//! # The pair, and why both halves are asserted
//!
//! "The text arrived" is worth nothing on its own: it would also pass if the
//! payload wrote to the pipe by some other route, or if the probe wrote with
//! something other than `WriteConsoleW`. So the same fixture is run with the shim
//! off, where the text must **not** arrive and the probe must report failure.
//! Only the pair distinguishes "the substitution works" from "the fixture was not
//! a subject at all".
//!
//! Nothing here can provoke a console host: the probe is the only process, and it
//! creates nothing.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::session::{Session, SessionConfig};

/// Long enough for an injection and a write, short enough to fail fast.
const DEADLINE: Duration = Duration::from_secs(30);

/// What one run observed.
#[derive(Debug)]
struct Observed {
    /// Everything that arrived on the pipe.
    output: String,
    /// The probe's own verdict line, if it got that far.
    verdict: Option<String>,
    /// The target's exit code.
    code: Option<u32>,
}

/// Runs the fixture once, with the shim on or off.
fn observe(shim: bool, text: &str) -> Observed {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_wbwpty-spawn-probe"));
    let gate = scratch(&format!("gate-{}", shim));

    let config = SessionConfig {
        shim,
        inject: true,
        // The probe never reads stdin, and the pump would deliver host stdin EOF
        // at a moment this test does not control.
        pump_input: false,
        ..Default::default()
    };
    let session = Session::start(
        &ChildSpec::new(&probe)
            .arg("--gate")
            .arg(&gate)
            .arg("--console-write")
            .arg(text),
        config,
    )
    .expect("session");

    if shim {
        // Asserted here rather than in the caller: if the substitution is not
        // installed, the text below is absent and the test would fail on the
        // symptom instead of on the cause.
        let report = session
            .console_hook()
            .expect("the probe imports WriteConsoleW, so a slot must have been rewritten")
            .clone();
        eprintln!("console substitution: {:?}", report.installed);
        assert!(
            report
                .installed
                .iter()
                .any(|(name, _)| name == "WriteConsoleW"),
            "WriteConsoleW was not among the rewritten slots: {:?}",
            report.installed
        );
    } else {
        assert!(
            session.console_hook().is_none(),
            "the shim is off, so nothing may have been substituted"
        );
    }

    // Release it only now, so the substitution is in place first.
    //
    // The gate file is cleaned up *after* the run, not straight away: a probe
    // that has not reached its gate yet would find nothing to wait for and sit
    // there forever, which is how the first version of this test hung.
    std::fs::write(&gate, b"go").expect("opening the gate");

    let mut buf = [0u8; 4096];
    let mut output = String::new();
    let deadline = Instant::now() + DEADLINE;
    // Read to EOF rather than to a marker. A verdict line is longer than one
    // read's worth often enough to matter, and a test that stops at a marker it
    // saw half of will parse half a line - which is how "ok=" came to be read as
    // a verdict.
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 200)) {
            Some(Ok(ReadEvent::Data(n))) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            // EOF is the reliable end: the probe has exited and closed its end of
            // the pipe, so nothing more is coming.
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) => {}
            Some(Err(err)) => panic!("output read failed: {err:#}"),
        }
    }

    let verdict = output
        .lines()
        .find(|line| line.contains("console-write"))
        .map(|line| line.to_string());

    // Waiting is bounded by what was actually observed. The probe is short lived
    // and gated, so a run that never got as far as the verdict line has a probe
    // that may still be waiting on its gate - and `Session::wait` has no timeout,
    // so calling it there is how a fixture bug becomes a hung suite.
    let code = if verdict.is_some() {
        session.wait()
    } else {
        session.shutdown();
        None
    };
    let _ = std::fs::remove_file(&gate);

    eprintln!("shim={shim} code={code:?}\noutput:\n  {output}");
    Observed {
        output,
        verdict,
        code,
    }
}

/// The promise: a program's `WriteConsoleW` output reaches the pipe.
#[test]
fn a_console_write_reaches_the_pipe_with_the_shim() {
    // Built at run time so the text the fixture was given is never a substring of
    // what it is asserted to produce, which is how an echo-based test passes
    // against a feature that produced nothing (AGENTS pitfall 15).
    let text = format!("{}{}", "NEU", "7Q2K5");

    let seen = observe(true, &text);

    assert!(
        seen.output.contains(&text),
        "the target wrote {text:?} through WriteConsoleW and it never arrived; \
         the pipe carried:\n  {}",
        seen.output
    );

    let verdict = seen.verdict.unwrap_or_else(|| {
        panic!(
            "the probe never reported a verdict; got:\n  {}",
            seen.output
        )
    });
    assert!(
        verdict.contains("ok=true"),
        "the substitute did not report success: {verdict:?}"
    );

    assert_eq!(
        seen.code,
        Some(0),
        "the probe exited non-zero, so it did not consider the write complete"
    );
}

/// The control, and the half that makes the other test mean anything.
///
/// Without the shim the same call is `ERROR_INVALID_HANDLE` on a pipe, the probe
/// writes nothing, and it exits `0x41`. If this ever stops being true the other
/// test is not measuring the substitution.
#[test]
fn without_the_shim_a_console_write_goes_nowhere() {
    let text = format!("{}{}", "NEU", "7Q2K5");

    let seen = observe(false, &text);

    assert!(
        !seen.output.contains(&text),
        "the text arrived without the shim, so the other test is not measuring \
         the substitution; the pipe carried:\n  {}",
        seen.output
    );

    let verdict = seen.verdict.unwrap_or_else(|| {
        panic!(
            "the probe never reported a verdict; got:\n  {}",
            seen.output
        )
    });
    assert!(
        verdict.contains("ok=false"),
        "WriteConsoleW on a pipe should have failed, but the probe reported: {verdict:?}"
    );
    assert_eq!(
        seen.code,
        Some(0x41),
        "the probe should have reported the console write as failed"
    );
}

fn scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "wbwpty-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}
