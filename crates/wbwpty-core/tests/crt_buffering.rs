//! Is the payload's stdio actually block buffered, and does `setvbuf` fix it?
//!
//! A CRT that block-buffers a pipe holds output until its buffer fills. That is
//! what makes a long-running program look hung under wbwpty: the host sees
//! nothing for 4 KiB worth of output. Stage 7 wants to put the target's streams
//! into line-buffered mode, and before building that two things have to be
//! settled by measurement rather than by reading a header:
//!
//! 1. **`_IOLBF` is a macro, not an export**, so it cannot be read out of
//!    `ucrtbase.dll`. MSVC's UCRT and mingw's msvcrt disagree about its value,
//!    and targets are built against either.
//! 2. **Whether `setvbuf` does anything to a stream that has already been
//!    written to.** The C standard says the call is undefined once I/O has
//!    started, and by the time the payload can be mapped the target's CRT has
//!    long since initialised stdio.
//!
//! `wbwpty-crt-probe` writes through ucrtbase's own `FILE *` - buffered exactly
//! the way a ucrt program's would be - and this measures when those bytes reach
//! the pipe. Line-buffered streams flush on a newline, so the probe writes one.

use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::session::{Session, SessionConfig};

/// How long the probe stays alive after writing. Long enough that "arrived
/// during the sleep" and "arrived at exit" cannot be confused, short enough to
/// keep the sweep quick.
const SLEEP: Duration = Duration::from_millis(700);

fn probe_path() -> std::ffi::OsString {
    std::ffi::OsString::from(env!("CARGO_BIN_EXE_wbwpty-crt-probe"))
}

/// What the probe's single write actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Held back until the process exited: block buffered.
    Buffered,
    /// Reached the pipe while the process was still running.
    Immediate,
    /// The process ended before the sleep elapsed and never wrote. `setvbuf`
    /// rejects a mode it does not recognise by running the invalid parameter
    /// handler, which aborts - so this is "not a mode", not "a mode that
    /// buffers".
    Died,
    /// Nothing came down the pipe at all.
    Silent,
}

#[derive(Debug)]
struct Measurement {
    mode: Option<i32>,
    outcome: Outcome,
    first_payload_ms: u128,
}

impl Measurement {
    fn is_valid_mode(&self) -> bool {
        !matches!(self.outcome, Outcome::Died)
    }
}

/// Runs the probe and classifies what its payload did.
///
/// The probe writes one newline-terminated line and then sleeps, so the three
/// interesting cases are distinguishable by *when* the bytes arrive rather than
/// by whether they arrive at all.
fn measure(mode: Option<i32>) -> Measurement {
    measure_with(mode, false)
}

/// Same as [`measure`], but optionally mapping the payload.
///
/// The `inject` flag is the whole point of the second half of this file: the
/// same probe, the same pipe, the only difference being whether our payload is
/// in the process.
fn measure_with(mode: Option<i32>, inject: bool) -> Measurement {
    let mut args = vec![
        std::ffi::OsString::from("--bytes"),
        std::ffi::OsString::from("64"),
        std::ffi::OsString::from("--newline"),
        std::ffi::OsString::from("--sleep-ms"),
        std::ffi::OsString::from(SLEEP.as_millis().to_string()),
    ];
    if let Some(m) = mode {
        args.push(std::ffi::OsString::from("--setvbuf"));
        args.push(std::ffi::OsString::from(m.to_string()));
    }

    let config = SessionConfig {
        shim: false,
        inject,
        ..Default::default()
    };
    let session = Session::start(&ChildSpec::new(probe_path()).args(args), config).expect("session");

    // When the payload is mapped, wait for its worker to finish before timing:
    // otherwise the measurement races the repair and can record the broken
    // behaviour even though the payload is about to fix it.
    if inject {
        session.wait_for_payload(std::time::Duration::from_millis(2000));
    }

    let started = Instant::now();
    let mut buf = [0u8; 4096];
    let mut text = String::new();
    let mut first_payload = None;
    let mut saw_eof = false;
    let deadline = started + SLEEP * 4;

    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 50)) {
            Some(Ok(ReadEvent::Data(n))) => {
                text.push_str(&String::from_utf8_lossy(&buf[..n]));
                if first_payload.is_none() && text.contains("AAAAAAAA") {
                    first_payload = Some(started.elapsed());
                }
            }
            Some(Ok(ReadEvent::Eof)) => {
                saw_eof = true;
                break;
            }
            Some(Ok(ReadEvent::Timeout)) => {}
            Some(Err(err)) => panic!("reading the session pipe failed: {err:#}"),
            None => break,
        }
    }
    session.shutdown();

    let elapsed = first_payload.unwrap_or(started.elapsed());
    // "During the run" has to mean comfortably before the probe's own sleep
    // ended; anything at or after it was flushed by exit, not by buffering.
    let arrived_early = first_payload.is_some() && elapsed < SLEEP / 2;
    let outcome = match (first_payload, saw_eof) {
        (None, true) => Outcome::Died,
        (None, false) => Outcome::Silent,
        (Some(_), _) if arrived_early => Outcome::Immediate,
        (Some(_), _) => Outcome::Buffered,
    };

    Measurement {
        mode,
        outcome,
        first_payload_ms: elapsed.as_millis(),
    }
}

/// What buffering mode does a stream over a pipe actually get?
///
/// This is the baseline everything else is compared against: if the default is
/// not block buffered there is no latency problem for Stage 7 to solve.
#[test]
fn a_pipe_gets_block_buffered_stdio_by_default() {
    let m = measure(None);
    eprintln!("\ndefault: {m:?} (probe sleeps {SLEEP:?} after writing)");
    assert_eq!(
        m.outcome,
        Outcome::Buffered,
        "the default must hold the write back until exit, otherwise Stage 7 has \
         nothing to fix"
    );
}

/// Which integers `setvbuf` accepts, and what each one actually does.
///
/// Swept rather than looked up: `_IOFBF` / `_IOLBF` / `_IONBF` are macros, not
/// exports, so the only source of truth is what ucrtbase does with the number.
/// A value it does not recognise runs the invalid parameter handler and aborts
/// the process, which is itself the answer - "not a mode".
#[test]
fn setvbuf_accepts_exactly_three_modes_and_only_one_of_them_flushes() {
    let mut rows = Vec::new();
    for mode in [0i32, 1, 2, 3, 4, 8, 0x20, 0x40, 0x80] {
        let m = measure(Some(mode));
        eprintln!("  mode {mode:#5}: {:?} at {}ms", m.outcome, m.first_payload_ms);
        rows.push(m);
    }

    let valid: Vec<i32> = rows.iter().filter(|m| m.is_valid_mode()).map(|m| m.mode.unwrap()).collect();
    let immediate: Vec<i32> = rows
        .iter()
        .filter(|m| m.outcome == Outcome::Immediate)
        .map(|m| m.mode.unwrap())
        .collect();

    eprintln!("\nvalid modes: {valid:?}");
    eprintln!("modes that flushed during the run: {immediate:?}");

    assert_eq!(
        valid,
        vec![0, 4, 0x40],
        "ucrtbase should accept exactly _IOFBF, _IONBF and _IOLBF"
    );
    assert_eq!(
        immediate,
        vec![4],
        "only _IONBF should push a newline-terminated write straight out; if \
         _IOLBF (0x40) turns up here the assumption behind the payload is wrong"
    );
}

/// The payload actually removes the latency.
///
/// This is the test that says whether Stage 7 works. Same probe, same pipe,
/// same write; the only difference is whether our payload is mapped into the
/// target, which puts its stdout and stderr into `_IONBF`.
#[test]
fn the_payload_makes_the_targets_stdio_unbuffered() {
    let without = measure_with(None, false);
    let with = measure_with(None, true);

    eprintln!(
        "\nno payload : {:?} at {}ms\nwith payload: {:?} at {}ms",
        without.outcome, without.first_payload_ms, with.outcome, with.first_payload_ms
    );

    assert_eq!(
        without.outcome,
        Outcome::Buffered,
        "baseline: without the payload the target block buffers"
    );
    assert_eq!(
        with.outcome,
        Outcome::Immediate,
        "the payload must make the target's write reach the pipe while it is \
         still running; it was {:?} at {}ms",
        with.outcome,
        with.first_payload_ms
    );
}

/// The payload has to report what it managed to do, or a silent failure looks
/// exactly like success.
#[test]
fn the_payload_reports_what_it_repaired() {
    let config = SessionConfig {
        shim: false,
        inject: true,
        ..Default::default()
    };
    let args = [
        std::ffi::OsString::from("--bytes"),
        std::ffi::OsString::from("8"),
        std::ffi::OsString::from("--newline"),
        std::ffi::OsString::from("--sleep-ms"),
        std::ffi::OsString::from(SLEEP.as_millis().to_string()),
    ];
    let session = Session::start(&ChildSpec::new(probe_path()).args(args), config).expect("session");

    let stage = session
        .wait_for_payload(std::time::Duration::from_millis(3000))
        .expect("payload should publish a stage");
    eprintln!("\nstage={:?} reason={}", stage.stage, stage.reason);

    let detail = session
        .payload_crt_detail()
        .expect("the payload should publish its CRT detail");
    eprintln!(
        "crt: ucrt_resolved={} streams_set={} streams_refused={}",
        detail.ucrt_resolved, detail.streams_set, detail.streams_refused
    );

    assert!(stage.ran_attach_path(), "DllMain was entered with reason {:#x}", stage.reason);
    assert!(
        detail.ucrt_resolved,
        "ucrtbase should resolve: this fixture writes through it"
    );
    assert_eq!(
        detail.streams_set, 2,
        "stdout and stderr should both be repaired, got {detail:?}"
    );
    assert_eq!(detail.streams_refused, 0, "no stream should be refused: {detail:?}");

    session.shutdown();
}