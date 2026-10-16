//! Proves the watcher watches, rather than trusting that it does.
//!
//! Every test here runs `cmd.exe` with `DETACHED_PROCESS` and a child that
//! spawns nothing, so the process under observation cannot allocate a console
//! and no window can appear on the user's desktop (AGENTS §12). A test that
//! needed a descendant would be testing the wrong thing *and* would pop one.

use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant};

use wbwpty_core::procwatch::{Mode, ProcessWatch};

/// `DETACHED_PROCESS`, `winbase.h`.
///
/// Used instead of `CREATE_NO_WINDOW` deliberately: AGENTS rule 2 forbids the
/// latter for the product, and a test that quietly used the forbidden flag to keep
/// a window off the screen would be hiding the same problem rather than avoiding
/// it. With this, the process is genuinely console-less.
const DETACHED_PROCESS: u32 = 0x0000_0008;

/// Spawns a console-less process that stays alive until killed.
///
/// Long-lived on purpose. The first version of this test used `cmd /c exit 0`,
/// which lives for a few milliseconds - shorter than one pass of the sampler's
/// `process_table()`, which walks every process on the machine. So the watcher
/// missed it, and `Mode::Sampled` missing it is *correct behaviour* (AGENTS §12):
/// that is exactly why the mode reports `is_exhaustive() == false`. A test that
/// expects a poller to catch a process shorter than its own poll period is asking
/// for a fluke. What is actually worth asserting is that a process which is still
/// running *does* show up.
fn spawn_console_less() -> std::process::Child {
    std::process::Command::new("cmd.exe")
        .args(["/k"])
        .creation_flags(DETACHED_PROCESS)
        .spawn()
        .expect("spawning the observed process")
}

fn wait_for<F: Fn() -> bool>(done: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

/// A watcher that starts and stops cleanly, which is the whole basis of trusting
/// anything else it reports.
///
/// Cheap and side-effect free: no target is launched, so nothing can appear on
/// the desktop.
#[test]
fn a_watcher_starts_and_stops() {
    let watch = ProcessWatch::start();
    // Dropping has to stop the session and join the consumer thread; if `stop`
    // did not unblock `ProcessTrace`, this test would hang rather than pass.
    drop(watch);
}

/// The watcher records a process this test started.
///
/// This is what separates a watcher from a silent no-op. `start` already fails
/// loudly when the provider cannot be enabled, but a session can enable the
/// provider and still deliver nothing - so the claim being checked is that a
/// creation the test caused shows up in the record.
#[test]
fn a_started_process_is_recorded() {
    let watch = ProcessWatch::start();

    // Settle first. `before` has to be taken *after* the first snapshot lands,
    // otherwise "the record grew" is satisfied by the ~250 processes the watcher
    // discovers on its own first poll and tells us nothing about the spawn below.
    let baseline = wait_for(|| watch.recorded().len() > 100, Duration::from_secs(5));
    assert!(baseline, "the watcher recorded no processes at all to start from");
    let before = watch.recorded().len();

    let mut child = spawn_console_less();
    let grew = wait_for(
        || watch.recorded().len() > before,
        Duration::from_secs(5),
    );
    let recorded = watch.recorded();
    // Killed whether or not the assertions below hold, so a failure here cannot
    // leave an orphaned cmd.exe behind.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        grew,
        "a process was created but the watcher recorded none of the {} \
         creations it had already seen",
        recorded.len()
    );
    assert!(
        recorded.iter().any(|b| b.name.as_deref() == Some("cmd.exe")),
        "cmd.exe was started but not named in the record: {recorded:?}"
    );
}

/// A tree with no console host is reported as empty, and the tree is complete.
///
/// The negative half matters as much as the positive one: a watcher that
/// recorded nothing at all would also return an empty list, which is why
/// `is_complete` and the naming test above exist.
#[test]
fn no_console_host_is_reported_under_this_process() {
    let watch = ProcessWatch::start();
    let self_pid = std::process::id();

let mut child = spawn_console_less();
    let _ = wait_for(|| !watch.recorded().is_empty(), Duration::from_secs(5));

    let hosts = watch.console_hosts_under(self_pid);
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        hosts.is_empty(),
        "a console host was created under the test process: {hosts:?}"
    );
}

/// Which mode the watch ended up in, reported rather than assumed.
///
/// This exists because the two modes are not interchangeable, and a suite that
/// passed in the sampled mode while looking like it tested kernel events would be
/// the exact failure this module was written to prevent. The mode is printed so
/// that whichever one a run took is visible in the output, and asserted only to
/// be one of the two - asserting `KernelEvents` here would turn a known gap into
/// a permanently red test instead of a documented one.
///
/// As of 2026-10-16 `StartTraceW` on this machine rejects the session with
/// `ERROR_INVALID_PARAMETER` even with the `LogFileMode` (`0x800100`) that a
/// session built by PowerShell's `New-EtwTraceSession` reports, so this normally
/// takes [`Mode::Sampled`]. See AGENTS §11 for what has been ruled out.
#[test]
fn the_watch_says_which_mode_it_is_in() {
    let watch = ProcessWatch::start();
    let mode = watch.mode();
    eprintln!("procwatch mode = {mode:?}, exhaustive = {}", mode.is_exhaustive());
    assert!(
        matches!(mode, Mode::KernelEvents | Mode::Sampled),
        "a watch must be in one of its two modes, not {mode:?}"
    );
}

/// A watch started after the root existed says so, instead of reporting clean.
///
/// The failure this guards is a watcher that silently sees nothing and whose
/// empty answer is then read as proof.
#[test]
fn an_adopted_process_makes_the_tree_incomplete() {
    let watch = ProcessWatch::start();
    let ghost = 0x7FFF_FFFE; // never a live pid on Windows
    assert!(
        watch.is_complete(ghost),
        "a pid that was never observed cannot make its own tree incomplete"
    );
    watch.adopt(ghost);
    assert!(
        !watch.is_complete(ghost),
        "adopting a process must make its tree incomplete"
    );
}
