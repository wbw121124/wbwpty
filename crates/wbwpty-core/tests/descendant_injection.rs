//! Does a *descendant* of the target get the same treatment the target did?
//!
//! `session::tests::grandchild_output_reaches_the_pipe` pins the first half of
//! the promise: the target's own children are created with
//! `DETACHED_PROCESS` + `STARTF_USESTDHANDLES`, so their output arrives and no
//! console host appears. That works because the substitution rewrote the
//! *target's* import table.
//!
//! An import table belongs to the image it was loaded with. A descendant has its
//! own, and nothing in it, so the generation after that was created with
//! whatever flags the descendant chose - and a CUI program whose parent has no
//! console is allocated one, which is a `conhost.exe`. The fix is
//! [`wbwpty_core::supervisor`]: give every descendant the same substitution, and
//! the property is inherited by induction.
//!
//! ```text
//!   wbwpty (host)
//!     └─ probe#1              the session target; substitution installed by Session::start
//!          └─ probe#2          created by probe#1 through the substitution
//!               └─ ping.exe    created by probe#2 through *its* substitution
//! ```
//!
//! # Why the fixture gates
//!
//! Each probe waits for a file to appear before spawning (`--gate`). Without it
//! the measurement is not about the feature: injection cannot happen until a
//! loader settles, which takes on the order of a hundred milliseconds, and a
//! probe that spawns in its first few milliseconds does so *before* any
//! substitution is installed. An earlier version of this experiment had exactly
//! that bug, and it produced a `conhost.exe` that looked like the supervisor not
//! working.
//!
//! So the test releases each generation itself, and before releasing probe#2 it
//! waits until the supervisor reports it covered. The assertion is about what
//! the covered generation did, not about what happened to appear on screen.
//!
//! # Nothing here may flash a window
//!
//! With the supervisor on, this test must not produce a `conhost.exe` - that is
//! what it asserts. The control that proves the sampler can see one is
//! [`without_the_supervisor_the_third_generation_gets_a_console_host`], and it
//! is `#[ignore]`d for the same reason every other deliberately-provoked console
//! host in this repository is.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use wbwpty_core::child::ChildSpec;
use wbwpty_core::inspect::{self, ProcessEntry};
use wbwpty_core::manual_map::remote::RemoteProcess;
use wbwpty_core::pipe::ReadEvent;
use wbwpty_core::session::{Session, SessionConfig};
use wbwpty_core::supervisor::Coverage;

/// `ping -n 6` lives about five seconds. The sampling window covers that with
/// room to spare for a busy machine.
const OBSERVE: Duration = Duration::from_secs(8);
const SAMPLE: Duration = Duration::from_millis(20);
/// How long to wait for the supervisor to report a generation covered. The
/// watchdog's own timeout is the better report if this is far too short.
const COVER_TIMEOUT: Duration = Duration::from_secs(15);

/// What the session's target runs, and what its child runs in turn.
///
/// The inner probe takes everything after `--` as one command *line*, and the
/// host quotes an argument that contains spaces while escaping the quotes inside
/// it, so the nested invocation has to be a single argument that quotes only the
/// part that needs it. Both paths here are free of spaces, which is what lets
/// them go unquoted.
fn inner_command(probe: &PathBuf, gate: &PathBuf, ping_pidfile: &PathBuf) -> String {
    format!(
        "{} --gate {} --pidfile {} -- \"ping -n 6 127.0.0.1\"",
        probe.display(),
        gate.display(),
        ping_pidfile.display()
    )
}

/// Whether probe#2 is ever allowed to spawn anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    /// The second gate is never opened, so nothing below probe#2 ever exists.
    Never,
    /// The second gate opens once probe#2 is covered.
    Second,
}

/// What one run of the three-generation chain observed.
///
/// Hand-written `Default` because `Result` has none, and "released" defaults to
/// "nothing stopped it" rather than to a failure nobody reported.
#[derive(Debug)]
struct Observation {
    /// The child of the target, i.e. the generation the supervisor had to reach.
    probe2: Option<u32>,
    /// What the supervisor did about it.
    probe2_coverage: Option<Coverage>,
    /// `ping`, as reported by probe#2 before it waited for it.
    ping: Option<u32>,
    /// A console host attributable to the target's tree was seen.
    console_host: Option<ProcessEntry>,
    /// Everything the tree contained, in the order it appeared.
    tree: Vec<String>,
    /// Lines that arrived on our pipe.
    output: Vec<String>,
    /// Every record the supervisor published, for the failure message.
    coverage: Vec<Coverage>,
    /// What probe#2's own `CreateProcessW` import slot held.
    ///
    /// Read while probe#2 was still alive and still holding at its gate - which
    /// is the only moment it can be read, and also the only moment at which
    /// reading it proves anything: the slot is rewritten once, at injection, and
    /// nothing afterwards depends on the process still existing.
    probe2_slot: Option<u64>,
    /// Where the payload's substitute lives inside probe#2.
    substitute: Option<u64>,
    /// `(dwCreationFlags, calls)` published by probe#2's payload.
    hook_flags: Option<(u32, u32)>,
    /// `WBWPTY_ORIGINAL_CREATE_PROCESS` as probe#2's payload sees it.
    original: Option<u64>,
    /// `WBWPTY_STD_HANDLES` as probe#2's payload sees it.
    published_handles: Option<[u64; 3]>,
    /// Whether probe#2 was allowed to spawn at all, and why not if it was not.
    released: Result<(), String>,
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            probe2: None,
            probe2_coverage: None,
            ping: None,
            console_host: None,
            tree: Vec::new(),
            output: Vec::new(),
            coverage: Vec::new(),
            probe2_slot: None,
            substitute: None,
            hook_flags: None,
            original: None,
            published_handles: None,
            released: Ok(()),
        }
    }
}

/// Runs the chain and watches what it does.
///
/// `cover_descendants` is the switch under test. Everything else is identical
/// between the two runs, so any difference in the result belongs to the
/// supervisor and to nothing else.
///
/// `release` decides whether probe#2 is ever let spawn. Leaving it closed is how
/// the covering can be asserted without anything downstream of it ever running -
/// see [`the_supervisor_covers_a_descendant_while_it_is_still_holding_still`].
fn observe(cover_descendants: bool, release: Release) -> Observation {
    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_wbwpty-spawn-probe"));
    let scratch = scratch("descendant-injection");
    let gate1 = scratch.join("gate1");
    let gate2 = scratch.join("gate2");
    let ping_pidfile = scratch.join("ping.pid");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch directory");

    let config = SessionConfig {
        shim: false,
        inject: true,
        cover_descendants,
        // Neither probe reads stdin, and the pump would deliver host stdin EOF
        // at a moment the fixture does not control. The gates are what decide
        // when these processes act, and stdin EOF is not on that list.
        pump_input: false,
        ..Default::default()
    };
    let session = Session::start(
        &ChildSpec::new(&probe)
            .arg("--gate")
            .arg(&gate1)
            .arg("--")
            .arg(inner_command(&probe, &gate2, &ping_pidfile)),
        config,
    )
    .expect("session");

    // Drops on every path out of here, including a panic: a fixture that waits on
    // a file it is never given leaves a process behind that nothing owns.
    let guard = TreeGuard {
        root: session.pid(),
    };

    assert!(
        session.hook().is_some(),
        "the target imports CreateProcessW, so the slot must be rewritten before \
         anything is released; it was not: {:?}",
        session.hook_error()
    );

    // Generation 1 -> 2. The substitution is installed by `Session::start`, so
    // this is the one spawn that cannot race the injector.
    std::fs::write(&gate1, b"go").expect("opening the first gate");
    let probe2 = wait_for_child_of(session.pid(), COVER_TIMEOUT);

    // Generation 2 is the one only the supervisor can reach. Hold it there until
    // it is covered, or the measurement is of a race.
    let probe2_coverage = probe2
        .and_then(|pid| session.wait_for_coverage(pid, COVER_TIMEOUT));
    if cover_descendants && probe2.is_some() && probe2_coverage.is_none() {
        eprintln!(
            "probe2={probe2:?} was never covered; records so far: {:#?}",
            session.coverage()
        );
    }

    // Read probe#2's import slot now, while it is still holding at its gate and
    // therefore still alive. This is the one thing that has to be observed from
    // the outside *before* anything downstream runs: the slot is rewritten at
    // injection time and the process does not outlive the teardown below.
    let mut probe2_slot = None;
    let mut substitute = None;
    let mut original = None;
    let mut published_handles = None;
    let mut released = Ok(());
    if let (Some(pid), Some(record)) = (probe2, probe2_coverage.as_ref()) {
        let base = record.payload_base.map(|base| {
            base + create_process_w_rva().expect("the payload exports create_process_w") as u64
        });
        substitute = base;
        probe2_slot = RemoteProcess::open(pid)
            .ok()
            .zip(base)
            .and_then(|(proc, substitute)| live_import_slot(&proc).map(|slot| (slot, substitute)))
            .map(|(slot, _)| slot);
        if let Some(base) = record.payload_base {
            if let Ok(proc) = RemoteProcess::open(pid) {
                original = read_published_u64(&proc, base, "WBWPTY_ORIGINAL_CREATE_PROCESS");
                published_handles = read_published_handles(&proc, base);
            }
        }
        eprintln!(
            "probe#2 slot={probe2_slot:?} substitute={substitute:?} original={original:?} \
             handles={published_handles:?}"
        );
    }

    if release == Release::Second {
        // The safety gate, and the reason this fixture is ordered the way it is.
        //
        // Releasing probe#2 is the only moment in this file where a console host
        // could appear. It cannot appear if probe#2's substitution refuses to act,
        // and the substitution refuses to act in exactly two situations:
        //
        // * `WBWPTY_ORIGINAL_CREATE_PROCESS` is zero - the hook returns FALSE and
        //   creates nothing at all;
        // * `WBWPTY_STD_HANDLES[1]` is zero - the hook deliberately passes the
        //   creation through untouched, because removing a child's console
        //   without giving it a way to write is worse than leaving it alone.
        //
        // So both are read out of probe#2's payload while it is still holding at
        // its gate, and the gate is only opened if they say the substitution will
        // do its job. A test that cannot tell whether the feature works should not
        // be the thing that puts a window on someone's desktop while finding out.
        //
        // The control inverts all of this on purpose: its whole point is to run an
        // uncovered generation, so it releases probe#2 whatever it finds.
        let blocked = if cover_descendants {
            if probe2_slot != substitute {
                Some(format!(
                    "import slot is {:?}, not the substitute {substitute:?}: the \
                     substitution is not in place, so probe#2 would create its \
                     child with its own flags",
                    probe2_slot
                ))
            } else if original.unwrap_or(0) == 0 {
                Some(
                    "WBWPTY_ORIGINAL_CREATE_PROCESS is zero: the substitution \
                     would refuse to create anything"
                        .to_string(),
                )
            } else if published_handles.map(|h| h[1]).unwrap_or(0) == 0 {
                Some(format!(
                    "WBWPTY_STD_HANDLES is {published_handles:?}: with no stdout \
                     the substitution passes the creation through untouched, and \
                     probe#2's own child would be allocated a console"
                ))
            } else {
                None
            }
        } else {
            None
        };

        match blocked {
            Some(reason) => released = Err(reason),
            None => {
                std::fs::write(&gate2, b"go").expect("opening the second gate");
            }
        }
    }

    let mut seen = Observation {
        probe2,
        probe2_coverage,
        probe2_slot,
        substitute,
        original,
        published_handles,
        released,
        ..Default::default()
    };

    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + OBSERVE;
    while Instant::now() < deadline {
        match session.pipes().with(|p| p.read_output(&mut buf, 0)) {
            Some(Ok(ReadEvent::Data(n))) => {
                for line in String::from_utf8_lossy(&buf[..n]).lines() {
                    let line = line.trim_end().to_string();
                    if !line.is_empty() && !seen.output.contains(&line) {
                        seen.output.push(line);
                    }
                }
            }
            Some(Ok(ReadEvent::Eof)) | None => break,
            Some(Ok(ReadEvent::Timeout)) | Some(Err(_)) => {}
        }

        if seen.ping.is_none() {
            seen.ping = std::fs::read_to_string(&ping_pidfile)
                .ok()
                .and_then(|t| t.trim().parse().ok());
        }

        // The flags probe#2's substitution handed to the kernel, read out of the
        // payload it published - the difference between "ping happened not to get
        // a console" and "ping was created the way this project requires".
        if seen.hook_flags.is_none() {
            if let Some(base) = seen.probe2_coverage.as_ref().and_then(|c| c.payload_base) {
                seen.hook_flags = seen
                    .probe2
                    .and_then(|pid| published_creation_flags(pid, base))
                    .filter(|&(_, calls)| calls >= 1);
            }
        }

        let table = inspect::process_table().expect("process table");
        if seen.console_host.is_none() {
            seen.console_host = inspect::descendant_console_hosts(&table, guard.root)
                .into_iter()
                .next();
        }
        let mine = inspect::descendants_of(&table, guard.root);
        for entry in table.iter().filter(|e| mine.contains(&e.pid) && e.pid != guard.root) {
            let line = format!("{} (pid {}, parent {})", entry.name, entry.pid, entry.parent);
            if !seen.tree.contains(&line) {
                seen.tree.push(line);
            }
        }
        std::thread::sleep(SAMPLE);
    }

    seen.coverage = session.coverage();
    eprintln!(
        "\ncover_descendants={cover_descendants} released={:?}\n\
         probe2={:?} ping={:?} original={:?} published_handles={:?}\n\
         probe2 coverage: {:#?}\n\
         console_host={:?}\n\
         tree:\n  {}\n\
         output:\n  {}",
        seen.released,
        seen.probe2,
        seen.ping,
        seen.original,
        seen.published_handles,
        seen.probe2_coverage,
        seen.console_host.as_ref().map(|h| (h.pid, h.parent)),
        seen.tree.join("\n  "),
        seen.output.join("\n  "),
    );

    session.shutdown();
    drop(guard);
    let _ = std::fs::remove_dir_all(&scratch);
    seen
}

/// A `u64` the payload published for the host, read out of the target.
///
/// `None` when the word cannot be found or read, which is a legitimate answer
/// for a payload that is not mapped: every one of these is only meaningful next
/// to a live image.
fn read_published_u64(proc: &RemoteProcess, payload_base: u64, export: &str) -> Option<u64> {
    let image = std::fs::read(payload_dll_path()?).ok()?;
    let rva = wbwpty_core::manual_map::find_export_rva(&image, export)
        .ok()
        .flatten()?;
    let bytes = proc.read_bytes(payload_base + rva as u64, 8).ok()?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// `WBWPTY_STD_HANDLES`, three words wide.
fn read_published_handles(proc: &RemoteProcess, payload_base: u64) -> Option<[u64; 3]> {
    let image = std::fs::read(payload_dll_path()?).ok()?;
    let rva = wbwpty_core::manual_map::find_export_rva(&image, "WBWPTY_STD_HANDLES")
        .ok()
        .flatten()?;
    let bytes = proc.read_bytes(payload_base + rva as u64, 24).ok()?;
    let mut handles = [0u64; 3];
    for (slot, chunk) in handles.iter_mut().zip(bytes.chunks_exact(8)) {
        *slot = u64::from_le_bytes(chunk.try_into().ok()?);
    }
    Some(handles)
}

/// The target's only child, by pid.
///
/// Selected by parentage rather than as "some descendant": the console host that
/// shows up in a failing run is also a descendant, and picking the wrong entry
/// would have the test measuring the console host instead of the generation the
/// supervisor exists to cover.
fn wait_for_child_of(root: u32, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(table) = inspect::process_table() {
            if let Some(entry) = table.iter().find(|e| e.parent == root) {
                return Some(entry.pid);
            }
        }
        std::thread::sleep(SAMPLE);
    }
    None
}

/// The whole promise, in one run.
///
/// Four independent things have to be true, and only satisfying some of them
/// looks like success:
///
/// 1. probe#2 is covered by the supervisor - the substitution is really in it;
/// 2. probe#2's substitution forced `DETACHED_PROCESS` on the child it created,
///    read out of the payload's own published word rather than inferred;
/// 3. `ping`'s output arrives on our pipe, as its own output and nobody's echo;
/// 4. no `conhost.exe` appears anywhere in the tree.
#[test]
fn a_three_generation_tree_keeps_every_generation_off_the_console() {
    let seen = observe(true, Release::Second);

    // The safety gate is asserted before anything downstream: if the substitution
    // was not going to act, probe#2 was never released and there is nothing to
    // look at.
    seen
        .released
        .clone()
        .expect("probe#2 should have been released");

    let probe2 = seen.probe2.expect("the target must have created probe#2");
    let coverage = seen
        .probe2_coverage
        .expect("the supervisor must report the generation it covered");
    assert!(
        coverage.injected,
        "probe#2 ({probe2}) was never injected: {:?}",
        coverage.note
    );
    assert!(
        coverage.hooked,
        "probe#2 ({probe2}) has no CreateProcessW substitution: {:?}",
        coverage.note
    );
    assert_eq!(
        coverage.depth, 1,
        "probe#2 is the target's direct child; a depth of {} means the ancestry \
         walk is wrong",
        coverage.depth
    );

    // The slot in probe#2's own memory has to hold the payload's substitute.
    // Everything below this line is a consequence of it.
    let substitute = seen
        .substitute
        .expect("a covered generation has a mapped payload and an exported substitute");
    assert_eq!(
        seen.probe2_slot,
        Some(substitute),
        "probe#2's CreateProcessW import slot does not point at the payload's \
         substitute, so the child it creates was not created by us"
    );

    // The flags probe#2's substitution actually handed to the kernel.
    let (creation_flags, calls) = seen
        .hook_flags
        .expect("probe#2's payload publishes WBWPTY_HOOK_FLAGS once it has run");
    assert!(
        calls >= 1,
        "probe#2's substitution never ran, so its child was not created by it"
    );
    assert_ne!(
        creation_flags & windows_sys::Win32::System::Threading::DETACHED_PROCESS,
        0,
        "probe#2 handed dwCreationFlags {creation_flags:#x} to the kernel, which \
         does not include DETACHED_PROCESS: its child will be allocated a console"
    );
    assert_eq!(
        creation_flags & windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE,
        0,
        "probe#2 handed CREATE_NEW_CONSOLE to the kernel alongside DETACHED_PROCESS; \
         the combination is undefined and a console host is the likely outcome"
    );

    let ping = seen.ping.expect("probe#2 must have reported the pid it created");
    // Locale-independent on purpose. `ping.exe` on this machine is the Chinese
    // build, so its output arrives in the OEM code page and every word of it is
    // mojibake when the pipe is read as UTF-8 - an assertion on "Pinging" fails
    // against a working feature. The address is ASCII in every localisation, and
    // the fixture cannot have produced it by echo: a probe never prints what it
    // was asked to run (AGENTS pitfall 15 is about `cmd`, which does).
    let from_ping: Vec<&String> = seen
        .output
        .iter()
        .filter(|line| line.contains("127.0.0.1"))
        .collect();
    assert!(
        from_ping.len() >= 2,
        "ping ({ping}) was created but its output never arrived on our pipe; \
         only {} line(s) carried its address, out of {:?}",
        from_ping.len(),
        seen.output
    );

    assert!(
        seen.console_host.is_none(),
        "a conhost.exe (pid {:?}, parent {:?}) appeared in the target's tree:\n  {}",
        seen.console_host.as_ref().map(|h| h.pid),
        seen.console_host.as_ref().map(|h| h.parent),
        seen.tree.join("\n  "),
    );
}

/// The supervisor really reaches a process the host did not create.
///
/// This is the whole mechanism in one assertion, and it is the part that can be
/// checked without letting anything downstream happen: probe#2 is left holding
/// at its gate forever, so it never spawns and there is no third generation that
/// could be given a console by mistake. That makes this test safe to run on a
/// machine where a stray `conhost.exe` window is not acceptable - which is every
/// machine, but most of all the one this test runs on.
///
/// What it proves:
///
/// * a descendant is discovered from a process table snapshot and injected,
/// * its `CreateProcessW` import slot really points at the payload - read out of
///   its own memory, not taken from the supervisor's word for it,
/// * and it is the target's *direct* child, so the ancestry walk agrees.
#[test]
fn the_supervisor_covers_a_descendant_while_it_is_still_holding_still() {
    let seen = observe(true, Release::Never);

    let probe2 = seen.probe2.expect("the target must have created probe#2");
    let coverage = seen.probe2_coverage.unwrap_or_else(|| {
        panic!(
            "the supervisor never reported pid {probe2}: {:#?}",
            seen.coverage
        )
    });

    assert!(coverage.injected, "probe#2 was not injected: {:?}", coverage.note);
    assert!(
        coverage.hooked,
        "probe#2 has no CreateProcessW substitution: {:?}",
        coverage.note
    );
    assert_eq!(coverage.depth, 1, "probe#2 is the target's direct child");

    // The slot in probe#2's own import table, read out of its memory: the call
    // site cannot reach the base API without going through it, and no amount of
    // the supervisor saying so would prove that.
    let substitute = seen
        .substitute
        .expect("a covered generation has a mapped payload and an exported substitute");
    assert_eq!(
        seen.probe2_slot,
        Some(substitute),
        "probe#2's CreateProcessW slot does not hold the payload's substitute \
         {substitute:#x}; the substitution is not in place, and the generation \
         below it would be created with whatever flags probe#2 picks"
    );

    // Nothing below probe#2 exists, which is the property that makes this test
    // safe to run unattended.
    assert!(
        !seen.tree.iter().any(|line| line.contains("ping")),
        "ping should not exist while the second gate is closed, but the tree was \
        :\n  {}",
        seen.tree.join("\n  ")
    );
    assert!(
        seen.console_host.is_none(),
        "a console host appeared with nothing below probe#2 to have caused one: \
         {:?}",
        seen.console_host.as_ref().map(|h| (h.pid, h.parent))
    );
}

/// The `CreateProcessW` import slot as it stands in a live process.
///
/// Both halves can fail and neither failure is interesting: an image that does
/// not import the function has nothing to substitute, and a process whose
/// headers cannot be read is not one this test can say anything about.
fn live_import_slot(proc: &RemoteProcess) -> Option<u64> {
    let image = std::fs::read(proc.image_path().ok()?).ok()?;
    let slots = wbwpty_core::manual_map::iat::find_imports(&image, &["CreateProcessW"]).ok()?;
    let slot = slots.first()?.address(proc.image_base().ok()?);
    let live = proc.read_bytes(slot, 8).ok()?;
    Some(u64::from_le_bytes(live.try_into().ok()?))
}

/// RVA of the payload's substitute for `CreateProcessW`.
fn create_process_w_rva() -> Option<u32> {
    let image = std::fs::read(payload_dll_path()?).ok()?;
    wbwpty_core::manual_map::find_export_rva(&image, "create_process_w")
        .ok()
        .flatten()
}

/// The control the other test depends on.
///
/// Without the supervisor, probe#2 has no substitution of its own, so the child
/// *it* creates is allocated a console by the base API - and the sampler finds
/// it. If this ever stops being true the test above has stopped measuring
/// anything, and it is the assertion rather than the feature that is broken.
///
/// Ignored permanently: it asserts the bug, so it can never be a gate, and it
/// puts a console window on the operator's desktop every time it runs.
#[test]
#[ignore = "measures the absence of the supervisor; not a regression gate"]
fn without_the_supervisor_the_third_generation_gets_a_console_host() {
    let seen = observe(false, Release::Second);

    let probe2 = seen.probe2.expect("the target must have created probe#2");
    assert!(
        session_coverage_is_empty(&seen),
        "with the supervisor off nothing should have been covered, but {:?} was",
        probe2
    );

    assert!(
        seen.console_host.is_some(),
        "the sampler has to be able to detect the console host this project exists \
         to prevent, or the test above proves nothing; the tree was:\n  {}",
        seen.tree.join("\n  "),
    );
}

fn session_coverage_is_empty(seen: &Observation) -> bool {
    seen.coverage.is_empty()
}

/// `(dwCreationFlags, calls)` from the payload mapped into `pid`.
///
/// The payload publishes this word specifically so a host can tell "the
/// substitution is installed and forced `DETACHED_PROCESS`" from "the
/// substitution is installed and something downstream changed the flags" -
/// those two look identical from outside, right down to the console appearing
/// anyway.
fn published_creation_flags(pid: u32, payload_base: u64) -> Option<(u32, u32)> {
    let image = std::fs::read(payload_dll_path()?).ok()?;
    let rva = wbwpty_core::manual_map::find_export_rva(&image, "WBWPTY_HOOK_FLAGS")
        .ok()
        .flatten()?;
    let proc = RemoteProcess::open(pid).ok()?;
    let bytes = proc.read_bytes(payload_base + rva as u64, 8).ok()?;
    let raw = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    let calls = u32::from_le_bytes(bytes[4..].try_into().ok()?);
    Some((raw, calls))
}

/// `wbwpty_redirect.dll` as the session under test loaded it.
///
/// The same two candidates the crate's own tests use: the test binary lives in
/// `target/release/deps`, the payload in `target/release`.
fn payload_dll_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    [
        exe.with_file_name("wbwpty_redirect.dll"),
        exe.parent()?.join("..").join("wbwpty_redirect.dll"),
    ]
    .into_iter()
    .find(|c| c.is_file())
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

/// Takes down everything the session created, whether the test passed, failed or
/// panicked.
///
/// Descendants die before ancestors: killing a parent first reparents its
/// children to something else, and they then fall out of the ancestry walk that
/// finds them. Console hosts die first of all - one outlives the process that
/// owned it, its client exits and the host does not - so they are killed
/// explicitly, even though with the supervisor on there should not be any.
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
        // The target itself goes through `Session`, but a tree can grow a process
        // after the target has exited, so keep sweeping until two consecutive
        // passes find nothing.
        for _ in 0..20 {
            if self.sweep() == 0 && self.sweep() == 0 {
                return;
            }
            std::thread::sleep(SAMPLE);
        }
        eprintln!(
            "cleanup: pid {} still has processes; inspect::descendants_of by hand",
            self.root
        );
    }
}