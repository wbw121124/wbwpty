//! Does the target get the *host's* screen state, or just a plausible-looking one?
//!
//! `tests/console_shim.rs` proves a program can write. This file is about asking:
//! `GetConsoleScreenBufferInfo` has to answer with where the cursor really is and
//! how big the window really is, because programs use both - a full-screen program
//! redraws from the cursor, and `ReadConsoleOutputCharacter` style loops stop when
//! the window is zero rows.
//!
//! ```text
//!   wbwpty → wbwpty-spawn-probe --console-info
//! ```
//!
//! The probe writes three characters, asks where the cursor is, waits for the
//! answer to catch up, and reports the numbers.
//!
//! # What makes this decisive
//!
//! Two things are asserted that a "returns something plausible" substitute would
//! fail:
//!
//! * the cursor is at **3** - the number of characters the probe wrote, so the
//!   answer came from a screen that saw them rather than from a default;
//! * the geometry is **100x30**, which is what this test asked for and is not
//!   anything any default would be, on either axis.
//!
//! # Why the probe waits
//!
//! Because the state is published, not fetched: the host writes it when it
//! processes the output, which is after the write left the pipe. The first query
//! legitimately sees the position from before the write. The property worth
//! asserting is that the state converges, so the probe polls for it - see
//! `wbwpty-spawn-probe --console-info`.
//!
//! Nothing here can provoke a console host: the probe is the only process and it
//! creates nothing.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::session::{Session, SessionConfig};

/// Long enough for an injection, a write, and the state to come back.
const DEADLINE: Duration = Duration::from_secs(40);

/// Runs the fixture and returns everything it said.
fn observe() -> (String, Option<u32>) {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_wbwpty-spawn-probe"));
    let gate = scratch("gate");

    let config = SessionConfig {
        shim: true,
        inject: true,
        pump_input: false,
        // Distinct from every default, so an answer that came from the payload's
        // fallback cannot pass for one that came from the host's screen.
        cols: PROBE_COLS,
        rows: PROBE_ROWS,
        ..Default::default()
    };
    let session = Session::start(
        &ChildSpec::new(&probe).arg("--gate").arg(&gate).arg("--console-info"),
        config,
    )
    .expect("session");

    let report = session
        .console_hook()
        .expect("the probe imports GetConsoleScreenBufferInfo, so a slot must exist")
        .clone();
    eprintln!("console substitution: {:?}", report.installed);
    assert!(
        report
            .installed
            .iter()
            .any(|(name, _)| name == "GetConsoleScreenBufferInfo"),
        "GetConsoleScreenBufferInfo was not among the rewritten slots: {:?}",
        report.installed
    );

    std::fs::write(&gate, b"go").expect("opening the gate");

    let mut buf = [0u8; 4096];
    let mut output = String::new();
    let deadline = Instant::now() + DEADLINE;
    // To EOF rather than to a marker: the report is longer than one read's worth
    // often enough to matter, and stopping at half a line parses half a line.
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 200)) {
            Some(Ok(ReadEvent::Data(n))) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) => {}
            Some(Err(err)) => panic!("output read failed: {err:#}"),
        }
    }

    // Bounded by what was observed: the probe is gated and short lived, and
    // `Session::wait` has no timeout, so waiting on a fixture that never got as
    // far as its report is how a test bug becomes a hung suite.
    let code = if output.contains("info:") {
        session.wait()
    } else {
        session.shutdown();
        None
    };
    let _ = std::fs::remove_file(&gate);

    eprintln!("code={code:?}\noutput:\n  {output}");
    (output, code)
}

/// Pulls one `key=value` out of the probe's report line.
fn field<'a>(report: &'a str, key: &str) -> Option<&'a str> {
    report
        .split(|c: char| c == ',' || c.is_whitespace())
        .find_map(|part| part.strip_prefix(key)?.split_once('=').map(|(_, v)| v))
}

/// The promise: the target asks, and the answer is the host's screen.
#[test]
fn the_target_sees_the_hosts_screen_state() {
    let (output, code) = observe();

    let report = output
        .lines()
        .find(|line| line.contains("info:"))
        .unwrap_or_else(|| panic!("the probe never reported; the pipe carried:\n  {output}"));

    assert_eq!(
        field(report, "delta"),
        Some("3"),
        "the cursor should have moved by exactly the three characters the probe \
         wrote; the report said {report:?}"
    );
    assert_eq!(
        field(report, "cols"),
        Some(&*PROBE_COLS.to_string()),
        "the window width should be what the session was configured with; \
         the report said {report:?}"
    );
    assert_eq!(
        field(report, "rows"),
        Some(&*PROBE_ROWS.to_string()),
        "the window height should be what the session was configured with; \
         the report said {report:?}"
    );
    assert_eq!(
        field(report, "baseline"),
        Some("true"),
        "the probe never saw the host's geometry, so every other number it \
         reported is the payload's fallback; the report said {report:?}"
    );
    assert_eq!(
        field(report, "settled"),
        Some("true"),
        "the published state never caught up with the probe's write; \
         the report said {report:?}"
    );
    assert_eq!(
        code,
        Some(0),
        "the probe exits non-zero when the state never caught up with its write, \
         which means the published state is not reaching the target"
    );
}

const PROBE_COLS: u16 = 100;
const PROBE_ROWS: u16 = 30;

fn scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "wbwpty-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}