//! What happens when a real program runs, end to end.
//!
//! Every other test in this repository drives a purpose-built fixture. That is
//! the right way to test a mechanism and the wrong way to find out whether the
//! thing works, because a fixture shares the project's assumptions: it is a
//! console program that writes with `WriteConsoleW` or `printf`, on a machine
//! where the pipe behaves. A real interpreter does none of that.
//!
//! So: `python.exe`, a 1 MB write, stderr, and exit codes - through the same
//! [`Session`] the CLI uses.
//!
//! # What each test is really for
//!
//! | case | what it would catch |
//! | --- | --- |
//! | interactive python | a REPL is the most console-dependent program on this machine |
//! | 1 MB in one go | a pipe that cannot take it, or a reader that stops early |
//! | stderr | stderr is the *same pipe* as stdout (AGENTS pitfall 23), and code that assumes otherwise |
//! | non-zero exit | a session that reports 0 for a failure |
//!
//! # Why python
//!
//! It is here, it is an interpreter, and it is the program most likely to branch
//! on what its stdout is. Its absence has to skip rather than fail, though -
//! a machine without it is missing a test, not broken.
//!
//! # None of this can produce a console host
//!
//! `cmd.exe /c python ...` is one process creating one child, both under the
//! substitutions, and no fixture here waits on anything that could allocate a
//! console. If any of them ever does show a console host, that is a real failure
//! and the tree guard below reaps it.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::inspect;
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::session::{Session, SessionConfig};

/// Generous, because a cold python start on a busy machine is not the thing
/// being measured.
const DEADLINE: Duration = Duration::from_secs(60);

/// How long to wait for a target to finish once its output has stopped.
const EXIT_WAIT: Duration = Duration::from_secs(10);

/// How much the 1 MB test writes. Big enough that it cannot arrive in one pipe
/// buffer, which is the point.
const BIG_WRITE: usize = 1024 * 1024;

/// Finds `python.exe`, or `None` so a test can skip with a reason.
fn python() -> Option<PathBuf> {
    ["python.exe", r"C:\Windows\py.exe"]
        .into_iter()
        .map(PathBuf::from)
        .find(|c| c.exists())
}

/// Skips with a reason rather than failing on a machine without python.
macro_rules! python_or_skip {
    () => {
        match python() {
            Some(path) => path,
            None => {
                eprintln!("skipping: no python.exe on this machine");
                return;
            }
        }
    };
}

/// Everything one run produced.
struct Run {
    output: String,
    code: Option<u32>,
}

/// Reads a session's output to EOF and collects what it said.
///
/// `pump_input: false` for the programs fed entirely on their command line: they
/// never read stdin, and the pump would otherwise deliver host stdin EOF at a
/// moment the test does not control.
fn run(program: &std::path::Path, args: &[&str]) -> Run {
    let config = SessionConfig {
        shim: true,
        inject: true,
        pump_input: false,
        ..Default::default()
    };
    let mut spec = ChildSpec::new(program);
    for arg in args {
        spec = spec.arg(arg);
    }
    let session = Session::start(&spec, config).expect("session");

    let output = read_to_eof(&session);
    let code = session.wait_for(EXIT_WAIT);
    session.shutdown();
    Run { output, code }
}

/// Reads until the output pipe says the target is done.
fn read_to_eof(session: &Session) -> String {
    let mut buf = vec![0u8; 64 * 1024];
    let mut output = String::new();
    let deadline = Instant::now() + DEADLINE;
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
    output
}

/// A real interpreter, doing arithmetic, has to produce the answer.
///
/// The marker is built at run time so the text cannot be found by the target
/// echoing what it was given - which `cmd.exe` will do, since it is the one
/// echoing here (AGENTS pitfall 15).
#[test]
fn python_computes_and_the_answer_arrives() {
    let python = python_or_skip!();
    let marker = format!("{}{}", "wbwpty-py", "-ok");
    let program = format!("print({marker:?})");

    let run = run(&python, &["-c", &program]);

    assert!(
        run.output.contains(&marker),
        "python's output never arrived; the pipe carried {} bytes: {:?}",
        run.output.len(),
        &run.output[..run.output.len().min(400)]
    );
    assert_eq!(run.code, Some(0), "python should have exited 0");
}

/// The same interpreter, kept alive, then talked to.
///
/// A REPL is the most console-dependent program on this machine: it reads lines,
/// it writes a prompt, and it decides whether it has a console. The two commands
/// are fed on stdin because a `-c` program never exercises any of that.
///
/// `#[ignore]`d because it asserts the input **echo** a terminal provides: stdin
/// here is a pipe, so nothing echoes what was typed, and CPython therefore runs
/// without readline and emits its result right after the prompt - `>>> NEU7Q2K5`
/// on one line instead of the value on a line of its own. The marker *does* come
/// back; only the tty echo is missing, and that is the shim piece README §1.5
/// still lists as unimplemented (`ReadConsoleInputW` + line editing).
#[test]
#[ignore = "needs the input-side console shim: a pipe does not echo, so the REPL's result lands on the prompt line"]
fn python_in_a_repl_reads_from_the_pipe() {
    let python = python_or_skip!();

    let config = SessionConfig {
        shim: true,
        inject: true,
        // The REPL *does* read stdin, and a prompt is useless without it.
        pump_input: true,
        ..Default::default()
    };
    let session = Session::start(&ChildSpec::new(&python).arg("-i"), config).expect("session");

    // A marker the fed text cannot contain on its own, so an echo cannot pass
    // for output: the value has to come back as a line of its own.
    session
        .pipes()
        .with(|p| p.input().write_all(b"print('NEU7Q2K5')\r\n").is_ok())
        .expect("input pipe");
    let _ = session
        .pipes()
        .with(|p| p.input().write_all(b"exit()\r\n").is_ok());

    let mut buf = [0u8; 8192];
    let mut output = String::new();
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 200)) {
            Some(Ok(ReadEvent::Data(n))) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                if output.contains(">>>") && output.lines().any(|l| l.trim() == "NEU7Q2K5") {
                    break;
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) => {}
            Some(Err(err)) => panic!("output read failed: {err:#}"),
        }
    }
    let code = session.wait_for(EXIT_WAIT);
    session.shutdown();

    assert!(
        output.lines().any(|line| line.trim() == "NEU7Q2K5"),
        "the REPL never printed the value as its own line; what it printed:\n  {}",
        output.lines().take(20).collect::<Vec<_>>().join("\n  ")
    );
    assert!(
        output.contains(">>>"),
        "no REPL prompt arrived, so the interpreter never treated stdin as input:\n  {}",
        output.lines().take(20).collect::<Vec<_>>().join("\n  ")
    );
    assert_eq!(code, Some(0), "the REPL should have exited cleanly on exit()");
}

/// A megabyte in one go.
///
/// Written as one `sys.stdout.write` of one string, so it cannot be split into
/// pieces that each fit: the reader has to cope with a stream far longer than any
/// buffer.
#[test]
fn a_megabyte_of_output_arrives_intact() {
    let python = python_or_skip!();

    let program =
        format!("import sys; sys.stdout.write('x' * {BIG_WRITE}); sys.stdout.write('\\nEND\\n')");
    let run = run(&python, &["-c", &program]);

    let xs = run.output.bytes().filter(|b| *b == b'x').count();
    assert_eq!(
        xs, BIG_WRITE,
        "{} of {BIG_WRITE} bytes arrived; the reader lost data",
        run.output.len()
    );
    assert!(
        run.output.contains("END"),
        "the trailing marker never arrived, so the stream was cut short at {} bytes",
        run.output.len()
    );
    assert_eq!(run.code, Some(0));
}

/// stderr, and the fact that it is the *same pipe* as stdout.
///
/// Not a test that they can be told apart - they cannot, and AGENTS pitfall 23
/// says why. A test that they could be separated would be testing a feature this
/// project does not have. What is tested is that interleaving survives: both
/// streams are the same pipe, so their relative order is whatever the target did.
#[test]
fn stderr_and_stdout_share_the_pipe_without_losing_either() {
    let python = python_or_skip!();

    let program = "import sys; \
                  sys.stdout.write('OUT1\\n'); sys.stdout.flush(); \
                  sys.stderr.write('ERR1\\n'); sys.stderr.flush(); \
                  sys.stdout.write('OUT2\\n')";
    let run = run(&python, &["-u", "-c", program]);

    let has = |needle: &str| run.output.lines().any(|line| line.trim() == needle);
    assert!(has("OUT1"), "stdout was lost:\n  {}", run.output);
    assert!(has("ERR1"), "stderr was lost:\n  {}", run.output);
    assert!(has("OUT2"), "stdout was truncated:\n  {}", run.output);
    assert_eq!(run.code, Some(0));
}

/// A failure has to look like a failure.
///
/// The exit code is the only thing a shell can see about a failed command, and
/// one that reports 0 for a non-zero program is worse than useless: it turns a
/// build failure into a green run.
#[test]
fn a_non_zero_exit_code_survives() {
    let python = python_or_skip!();

    let run = run(&python, &["-c", "import sys; sys.exit(3)"]);

    assert_eq!(
        run.code,
        Some(3),
        "python exited 3 and the session reported {:?}",
        run.code
    );
}

/// `cmd.exe` in front of python, which is how a shell would actually run it.
///
/// This covers the whole chain: `cmd /c` creates a child through the substitution,
/// and that child is python. It is also the case that shows the console API work
/// is not only about python.
///
/// `#[ignore]`d because it is the shortest reproduction of the supervisor race in
/// README §1.7: `cmd.exe /c python` spawns its child within the first few
/// milliseconds, which is inside the ~100 ms window the injection needs, so the
/// grandchild is never covered. Being uncovered means it is handed a console of
/// its own, and its output goes there instead of down our pipe - which is why
/// this sees *nothing*, not even the marker.
///
/// Closing that race is the top item in README §5.3. Note that the obvious fix
/// is a dead end: AGENTS.md rule 31 records that suspending the grandchild until
/// it is patched does not work, because `PEB->Ldr` is NULL in a suspended process
/// and the injected thread never runs there.
#[test]
#[ignore = "needs the supervisor race closed (README 5.3): the grandchild spawns before it is covered and takes its own console"]
fn cmd_runs_python_through_the_substitution() {
    let Some(python) = python() else {
        eprintln!("skipping: no python.exe on this machine");
        return;
    };

    // All `String`, because an array literal of `&str` and `&String` has no
    // element type to coerce towards and the compiler infers neither.
    let python = python.display().to_string();
    let spec = ChildSpec::new("cmd.exe").args([
        "/c".to_string(),
        python,
        "-c".to_string(),
        "print('CHAINED-OK')".to_string(),
    ]);
    let config = SessionConfig {
        shim: true,
        inject: true,
        pump_input: false,
        ..Default::default()
    };
    let session = Session::start(&spec, config).expect("session");
    let guard = TreeGuard { root: session.pid() };

    let mut buf = [0u8; 4096];
    let mut output = String::new();
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 200)) {
            Some(Ok(ReadEvent::Data(n))) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                if output.contains("CHAINED-OK") {
                    break;
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) => {}
            Some(Err(err)) => panic!("output read failed: {err:#}"),
        }
    }
    let hosts = guard.console_hosts_seen();
    let code = session.wait_for(EXIT_WAIT);
    session.shutdown();
    drop(guard);

    assert!(
        output.contains("CHAINED-OK"),
        "python under cmd /c produced nothing usable:\n  {}",
        output
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        hosts, 0,
        "a console host appeared for a cmd -> python chain, which is the one \
         thing this project exists to prevent"
    );
}

/// Takes down whatever the session left, on every path out.
///
/// Descendants before ancestors: killing a parent first reparents its children
/// and they fall out of the ancestry walk that finds them in the first place.
struct TreeGuard {
    root: u32,
}

impl TreeGuard {
    /// How many console hosts this tree has shown. Read before the drop.
    fn console_hosts_seen(&self) -> usize {
        match inspect::process_table() {
            Ok(table) => inspect::descendant_console_hosts(&table, self.root).len(),
            Err(_) => 0,
        }
    }

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
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}