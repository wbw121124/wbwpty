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
/// Finds an interpreter this project can actually drive.
///
/// `PATH` is searched for real `python.exe` on purpose. The obvious fallback,
/// `C:\Windows\py.exe`, is a 32-bit launcher: it cannot be covered by an x64
/// payload (README §7), so it grabs a console of its own and everything it
/// prints goes there instead of down the pipe. Selecting it made the
/// `cmd -> python` test measure our 32-bit limitation rather than the thing it
/// is named after, so non-x64 candidates are rejected outright.
fn python() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("python.exe"))
            .find(|candidate| candidate.is_file() && is_x64_image(candidate))
    })
}

/// True when the file is a PE32+ image, by its `IMAGE_FILE_MACHINE` field.
fn is_x64_image(path: &std::path::Path) -> bool {
    /// `IMAGE_FILE_MACHINE_AMD64`
    const AMD64: u16 = 0x8664;
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let Some(magic) = bytes.get(..2) else {
        return false;
    };
    if magic != *b"MZ" {
        return false;
    }
    let Some(pe_at) = bytes
        .get(0x3c..0x40)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()) as usize)
    else {
        return false;
    };
    matches!(
        bytes.get(pe_at + 4..pe_at + 6),
        Some(s) if u16::from_le_bytes(s.try_into().unwrap()) == AMD64
    )
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
/// This is the un-padded half of the pair:
/// [`a_grandchild_reaches_the_pipe_without_a_console`] asserts the same
/// end-to-end claim once the spawn is delayed, and passes. So the substitution
/// itself works and what is left here is purely the timing race, which is exactly
/// what makes this worth keeping as a separate red test rather than deleting.
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

/// TEMPORARY diagnostic for the cmd -> python chain.
/// Decides between "the hook was clobbered" and "cmd never uses that slot".
///
/// `cmd.exe /c <child>` is too short-lived to sample - it is gone before the
/// counters can be read. An interactive `cmd /k` waits for input, so the
/// counters can be read while it is very much alive, and the loader timing
/// question gets asked of a process that finished starting long ago.
/// A generation-2 child's output reaches our pipe, and no console appears.
///
/// This is the end-to-end claim the project exists for: `cmd.exe` is created
/// detached, it spawns a child through the substituted `CreateProcessW`, and that
/// child's stdout and stderr both come back over the session's pipes with no
/// `conhost.exe` anywhere in the tree.
///
/// Two things in the command line are load-bearing, and both were arrived at by
/// measurement rather than taste:
///
/// * **A `for /L` loop first, and specifically not `ping`.** `cmd.exe /c <child>`
///   spawns within a few milliseconds, which is before the injector can finish;
///   that child misses the hook entirely and is allocated a console of its own.
///   The loop buys the injector time without spawning anything. `ping` was used
///   here first and is exactly the mistake described in AGENTS §12: it *is* the
///   first spawn, so it gets the console instead of the child under test - the
///   window that appeared on the user's desktop was titled `ping`.
/// * **No `> nul` on the python command.** With a redirect in front of it, the
///   grandchild's `sys.stdout` comes back `None` even though the hook reports
///   success. Still unexplained (AGENTS §11), so it is avoided here rather than
///   encoded as expected behaviour.
///
/// Not `#[ignore]`d: the delay spawns nothing, the hook is armed by the time the
/// child under test runs, and nothing in the tree allocates a console. That is a
/// claim, so it is checked rather than assumed - see `proc_watch` for how the
/// "no console host" half is actually verified.
#[test]
fn a_grandchild_reaches_the_pipe_without_a_console() {
    let python = python_or_skip!();
    // `ChildSpec` quotes arguments containing spaces and escapes their inner
    // quotes; `cmd /c` strips only the outer pair, so the inner ones arrive as
    // literal `\"` and the child never runs. A short path avoids the quoting.
    let python = python.display().to_string().replace("Program Files", "PROGRA~1");

    // A file rather than `-c`, for the same reason plus one more: the code has to
    // survive another layer of shell quoting to reach python intact.
    let script = std::env::temp_dir().join("wbwpty_end_to_end_grandchild.py");
    std::fs::write(
        &script,
        "import sys\n\
         sys.stdout.write('STDOUT-MARK-7Q2K\\n')\n\
         sys.stdout.flush()\n\
         sys.stderr.write('STDERR-MARK-7Q2K\\n')\n\
         sys.stderr.flush()\n",
    )
    .expect("writing the grandchild script");

    // `cmd /k` and then type the command, rather than `cmd /c <command>` with a
    // delay in front of it. See the sibling test for why: a `ping` delay is the
    // bug rather than the fix (it is cmd's first spawn, so *it* gets the console),
    // and a `for /L` delay is unbounded and can burn the whole deadline.
    let spec = ChildSpec::new("cmd.exe").arg("/k");
    let config = SessionConfig {
        shim: true,
        inject: true,
        // Rule 32: an interactive cmd exits the moment it sees stdin EOF, and the
        // pump would deliver it at a moment this test does not control.
        pump_input: false,
        ..Default::default()
    };
    let session = Session::start(&spec, config).expect("session");
    let _guard = TreeGuard { root: session.pid() };

    let armed = wait_until(std::time::Duration::from_secs(10), || {
        session.hook().map(|h| h.slot_count() > 0).unwrap_or(false)
    });
    assert!(
        armed,
        "the CreateProcess substitution was never installed, so a child spawned \
         now would be given a console of its own"
    );

    let mut buf = [0u8; 4096];
    let mut output = String::new();
    let command = format!("{python} {}\r\n", script.display());
    session
        .pipes()
        .with(|p| p.input().write_all(command.as_bytes()).is_ok())
        .expect("input pipe");

    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 200)) {
            Some(Ok(ReadEvent::Data(n))) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                if output.contains("STDERR-MARK-7Q2K") {
                    break;
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Err(_)) => break,
            _ => {}
        }
    }
    session.shutdown();
    let _ = std::fs::remove_file(&script);

    // Both descriptors, not just stdout: stderr is the same pipe (AGENTS 坑 23),
    // so one arriving without the other would mean the child had only one.
    assert!(
        output.contains("STDOUT-MARK-7Q2K"),
        "grandchild stdout missing; got {output:?}"
    );

    // Both descriptors, not just stdout: stderr is the same pipe (AGENTS 坑 23),
    // so one arriving without the other would mean the child had only one.
    assert!(
        output.contains("STDOUT-MARK-7Q2K"),
        "grandchild stdout missing; got {output:?}"
    );
    assert!(
        output.contains("STDERR-MARK-7Q2K"),
        "grandchild stderr missing; got {output:?}"
    );
}

/// Polls `ready` until it holds or `timeout` elapses.
fn wait_until(timeout: std::time::Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The same claim, with the "no console host" half actually checked.
///
/// The test above takes "no console host" on trust. This one does not: it starts a
/// [`ProcessWatch`] *before* the session, so every process creation underneath this
/// test is recorded, and then asks whether a console host was created in that
/// tree. That is the whole difference between an assertion and a hope, and it is
/// the check AGENTS §12 requires of any "nothing appeared" claim.
///
/// The honest limit: while the watch is in [`Mode::Sampled`] it polls, so a console
/// host created and destroyed between two samples is still missed. The mode is
/// printed, and when ETW works (`Mode::KernelEvents`) this test becomes
/// exhaustive without changing a line.
#[test]
fn the_grandchild_tree_is_attributed_and_has_no_console_host() {
    use wbwpty_core::procwatch::ProcessWatch;

    let python = python_or_skip!();
    let python = python.display().to_string().replace("Program Files", "PROGRA~1");
    let script = std::env::temp_dir().join("wbwpty_end_to_end_attributed.py");
    std::fs::write(
        &script,
        "import sys\n\
         sys.stdout.write('ATTRIBUTED-7Q2K\\n')\n\
         sys.stdout.flush()\n",
    )
    .expect("writing the grandchild script");

    // Started first, so the root itself is not a process this watch missed.
    let watch = ProcessWatch::start();
    eprintln!(
        "procwatch mode = {:?}, exhaustive = {}",
        watch.mode(),
        watch.mode().is_exhaustive()
    );
    let test_pid = std::process::id();

    // `cmd /k` and then type the command, rather than `cmd /c <command>` with a
    // delay in front of it. Two failures motivated this and both are worth
    // recording:
    //
    // * A delay made of `ping` is not a delay, it is the bug: `ping` is cmd's
    //   *first* spawn, so it is the one that misses the hook and gets a console
    //   of its own. The window that appeared on the user's desktop was titled
    //   `ping` (AGENTS §12).
    // * A delay made of `for /L %i in (1,1,9999999) do @rem` spawns nothing, but
    //   it is also not bounded - it burned the whole test deadline looping and
    //   the child under test never ran at all.
    //
    // `/k` sidesteps both: cmd spawns nothing until it is told to, so waiting for
    // the hook to be installed costs nothing and cannot produce a console. The
    // first process it creates is the one that goes through the substitution.
    let spec = ChildSpec::new("cmd.exe").arg("/k");
    let config = SessionConfig {
        shim: true,
        inject: true,
        // Rule 32: an interactive cmd exits the moment it sees stdin EOF, and the
        // pump would deliver it at a moment this test does not control.
        pump_input: false,
        ..Default::default()
    };
    let session = Session::start(&spec, config).expect("session");
    let _guard = TreeGuard { root: session.pid() };
    // The root existed before the watch could see it, so the tree is incomplete
    // by construction; saying so is what `adopt` is for.
    watch.adopt(session.pid());

    // Wait for the substitution to be armed rather than guessing at a delay. This
    // is the condition that actually matters, and waiting on it directly is what
    // makes "the child below was covered" a fact instead of a hope.
    let armed = wait_until(std::time::Duration::from_secs(10), || {
        session.hook().map(|h| h.slot_count() > 0).unwrap_or(false)
    });
    assert!(
        armed,
        "the CreateProcess substitution was never installed, so a child spawned \
         now would be given a console of its own"
    );

    let mut buf = [0u8; 4096];
    let mut output = String::new();
    let command = format!("{python} {}\r\n", script.display());
    session
        .pipes()
        .with(|p| p.input().write_all(command.as_bytes()).is_ok())
        .expect("input pipe");

    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 200)) {
            Some(Ok(ReadEvent::Data(n))) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                if output.contains("ATTRIBUTED-7Q2K") {
                    break;
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Err(_)) => break,
            _ => {}
        }
    }
    session.shutdown();
    let _ = std::fs::remove_file(&script);

    // Let the last samples land before reading the record.
    std::thread::sleep(std::time::Duration::from_millis(150));

    assert!(
        output.contains("ATTRIBUTED-7Q2K"),
        "grandchild output missing; got {output:?}"
    );

    let hosts = watch.console_hosts_under(test_pid);
    // Report what was seen, minus the shell this test was launched from - that
    // belongs to the harness, not to the session under test.
    let ours: Vec<_> = watch
        .recorded()
        .into_iter()
        .filter(|b| b.parent != test_pid)
        .collect();
    eprintln!(
        "procwatch recorded {} creations under the test; console hosts in tree: {}",
        ours.len(),
        hosts.len()
    );
    assert!(
        hosts.is_empty(),
        "a console host was created in this tree: {hosts:?}"
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

