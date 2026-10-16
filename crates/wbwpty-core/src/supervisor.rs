//! Covering every generation of the session's process tree.
//!
//! # The gap this closes
//!
//! The `CreateProcessW` substitution (see [`crate::manual_map::hook`]) rewrites
//! **one** process' import table: the session's target. That is enough to make
//! the target's own children correct - `DETACHED_PROCESS` plus
//! `STARTF_USESTDHANDLES`, no console host, output on our pipes - and it is
//! pinned by `session::tests::grandchild_output_reaches_the_pipe`.
//!
//! It is not enough for the generation after that. An import table belongs to
//! the image it was loaded with; a child process has its own, and it has no
//! payload in it at all. So a process the target spawns will create its children
//! with whatever flags *it* chose, and the base API allocates a console for each
//! of them - a `conhost.exe` per grandchild, which is the exact thing this
//! project exists to prevent.
//!
//! The fix is structural rather than clever: give every descendant the same
//! treatment the target gets. A process that can substitute its own
//! `CreateProcessW` creates *its* children correctly, so the property is
//! inherited by induction down the whole tree.
//!
//! # Why the host does it
//!
//! The alternative is having the payload inject itself into its children, which
//! means reimplementing the entire injector (PE mapping, relocations, import
//! resolution against the child's loader state, a remote thread) inside a
//! `no_std` DLL that must not touch the heap. The host already has all of it,
//! and it can already reach a descendant: everything in the tree runs as the
//! same user, so `RemoteProcess::open` succeeds - `tests/descendant_conhost.rs`
//! has been writing the console sentinel into descendants from here all along.
//!
//! # What it does *not* do
//!
//! It polls. A descendant is discovered after it exists, so a descendant that
//! spawns its own child in the first few milliseconds can beat the poll. That
//! race is real and is not hidden here: [`Coverage`] is published as it happens
//! so a caller can see exactly which processes were covered and which were not.
//! Closing it needs the child to be created suspended and handed to the host -
//! a separate change, with its own failure modes.
//!
//! # Cost
//!
//! One process table snapshot every [`SupervisorConfig::poll`], and for each new
//! pid one injection. A session that spawns a thousand processes pays a thousand
//! injections; a session that spawns none pays one snapshot per poll.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::inspect;
use crate::manual_map::{self, remote::ConsolePatch, remote::RemoteProcess};

/// What the supervisor did to one descendant.
///
/// Published as it happens rather than only at the end: "which processes in the
/// tree are covered" is the question this module exists to answer, and a caller
/// that has to wait for the session to finish cannot tell a descendant that was
/// covered in time from one that was covered too late to matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// The descendant.
    pub pid: u32,
    /// Generations below the session's target; 1 is its direct child.
    pub depth: usize,
    /// The image it runs, as the kernel reported it.
    pub image: String,
    /// The payload is mapped and its `DllMain` ran.
    pub injected: bool,
    /// Its `CreateProcessW` import slot now points at the payload.
    ///
    /// False for a target that does not import `CreateProcessW` at all, which is
    /// a legitimate outcome and not a failure: it has nothing to substitute.
    pub hooked: bool,
    /// The console sentinel went in, meaning its `ConsoleHandle` was null.
    ///
    /// Recorded rather than assumed. Measured on this machine, the sentinel does
    /// *not* stop the base API allocating a console for the children of a
    /// console-less process (README 1.2); the substitution is what stops it.
    pub sentinel: bool,
    /// Where the payload landed, when it landed.
    ///
    /// The published words the payload writes (`WBWPTY_HOOK_STATS`,
    /// `WBWPTY_HOOK_FLAGS`) are at fixed offsets from this, so a caller that
    /// wants to check what the substitution actually did has to read them out of
    /// the target, and needs this to do it.
    pub payload_base: Option<u64>,
    /// Why this process is not covered, when it is not.
    pub note: Option<String>,
}

impl Coverage {
    /// True when the process' own children will be created the way the project
    /// needs them.
    pub fn covered(&self) -> bool {
        self.injected && self.hooked
    }
}

/// Everything the supervisor needs, decided once by [`crate::session::Session`].
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// The session's target. The tree is everything whose ancestry reaches it.
    pub root_pid: u32,
    /// The payload on disk, used to find the published words to write.
    pub payload_path: PathBuf,
    /// The same payload, already read. Re-reading it per descendant would be the
    /// single most expensive thing this thread does.
    pub payload_image: Arc<Vec<u8>>,
    /// `stdin`, `stdout`, `stderr` as this session sees them. The same three
    /// numbers the target's own substitution was given: inherited handle values
    /// are identical on both sides of a `CreateProcess`.
    pub std_handles: [u64; 3],
    /// How often to look for new processes.
    ///
    /// This is the other half of the race in README §1.7: even with injection
    /// down to single-digit milliseconds, a descendant that is discovered late
    /// has already had a chance to spawn an uncovered child of its own. Polling
    /// at 15 ms put that window at tens of milliseconds.
    pub poll: Duration,
    /// How long to wait for one descendant's loader before giving up on this
    /// attempt. Short on purpose - see [`Self::max_attempts`].
    pub loader_wait: Duration,
    /// How often the injector re-checks a descendant while waiting for it to
    /// finish loading. Not a settle interval: readiness is decided by the real
    /// precondition (every imported module mapped), so this only paces retries.
    pub inject_poll: Duration,
    /// How many polls a descendant gets before it is written off.
    pub max_attempts: u32,
    /// Report per-descendant outcomes on stderr.
    pub verbose: bool,
}

impl SupervisorConfig {
    /// Defaults tuned for a shell session.
    ///
    /// The loader wait is 150 ms rather than the session target's 10 s: a
    /// descendant is often short lived, and blocking for ten seconds on one
    /// would stall every other descendant behind it. A process that has not
    /// settled simply comes back on the next poll.
    pub fn new(root_pid: u32, payload_path: PathBuf, std_handles: [u64; 3]) -> Self {
        Self {
            root_pid,
            payload_path,
            payload_image: Arc::new(Vec::new()),
            std_handles,
            poll: Duration::from_millis(3),
            loader_wait: Duration::from_millis(150),
            inject_poll: Duration::from_millis(1),
            max_attempts: 25,
            verbose: false,
        }
    }
}

/// The watcher thread.
pub struct DescendantSupervisor {
    stop: Arc<AtomicBool>,
    coverage: Arc<Mutex<Vec<Coverage>>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl DescendantSupervisor {
    /// Starts watching. Returns immediately; the thread does the work.
    pub fn spawn(config: SupervisorConfig) -> Self {
        let coverage: Arc<Mutex<Vec<Coverage>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_coverage = Arc::clone(&coverage);
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("wbwpty-descendants".into())
            .spawn(move || run(config, thread_coverage, thread_stop))
            .expect("spawning the descendant supervisor");
        Self {
            stop,
            coverage,
            join: Some(join),
        }
    }

    /// Asks the thread to finish. Does not wait for it.
    ///
    /// [`Drop`] does the waiting, because the thread has to be joinable from a
    /// place that owns it and shutdown cannot: a thread left running after the
    /// target is gone would keep writing into processes this session no longer
    /// has anything to do with.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// A snapshot of what has been covered so far, in the order it happened.
    pub fn coverage(&self) -> Vec<Coverage> {
        // A panic inside the thread would poison the lock, and losing the record
        // of what it had already done is worse than the poison.
        lock(&self.coverage).clone()
    }
}

impl Drop for DescendantSupervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// A `ProcessTreeSnapshot` is cheap to take and the loop is the only place that
/// takes one, so the helper exists to keep the poison handling in one place.
fn lock(shared: &Mutex<Vec<Coverage>>) -> MutexGuard<'_, Vec<Coverage>> {
    shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Upper bound on the record, so a session that churns through a very long
/// process list cannot grow it without limit.
const MAX_COVERED: usize = 4096;

/// The loop.
fn run(config: SupervisorConfig, coverage: Arc<Mutex<Vec<Coverage>>>, stop: Arc<AtomicBool>) {
    let mut pending: BTreeMap<u32, usize> = BTreeMap::new();
    let mut attempts: BTreeMap<u32, u32> = BTreeMap::new();
    let mut finished: HashSet<u32> = HashSet::new();
    finished.insert(config.root_pid);

    while !stop.load(Ordering::Relaxed) {
        let Ok(table) = inspect::process_table() else {
            nap(&stop, config.poll);
            continue;
        };

        // The session is over when the target is gone. Descendants may outlive
        // it, but they are no longer this session's business, and covering them
        // would mean writing into processes nothing owns any more.
        if !table.iter().any(|e| e.pid == config.root_pid) {
            return;
        }

        for pid in inspect::descendants_of(&table, config.root_pid) {
            if finished.contains(&pid) || pending.contains_key(&pid) {
                continue;
            }
            let depth = inspect::ancestry_depth(&table, config.root_pid, pid).unwrap_or(1);
            pending.insert(pid, depth);
            attempts.insert(pid, 0);
        }

        // Shallowest first. Not because a child needs its parent patched first -
        // every injection is independent - but because a descendant that gets
        // covered early is more likely to be covered before it spawns anything
        // of its own, and the ancestors are the ones doing the spawning.
        let mut batch: Vec<(u32, usize)> = pending.iter().map(|(&pid, &depth)| (pid, depth)).collect();
        batch.sort_by_key(|&(_, depth)| depth);

        for (pid, depth) in batch {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let seen = attempts.entry(pid).or_insert(0);
            *seen += 1;
            match attempt(&config, pid, depth, *seen) {
                Outcome::Done(record) => {
                    if config.verbose {
                        eprintln!(
                            "wbwpty: descendant {} ({}) depth {}: injected={} hooked={} \
                             sentinel={}{}",
                            record.pid,
                            record.image,
                            record.depth,
                            record.injected,
                            record.hooked,
                            record.sentinel,
                            record.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default(),
                        );
                    }
                    finished.insert(pid);
                    pending.remove(&pid);
                    push(&coverage, record);
                }
                Outcome::Retry(reason) => {
                    let give_up = *seen >= config.max_attempts;
                    if give_up {
                        finished.insert(pid);
                        pending.remove(&pid);
                        push(
                            &coverage,
                            Coverage {
                                pid,
                                depth,
                                image: String::new(),
                                injected: false,
                                hooked: false,
                                sentinel: false,
                                payload_base: None,
                                note: Some(reason),
                            },
                        );
                    } else if config.verbose {
                        eprintln!("wbwpty: descendant {pid} not ready yet: {reason}");
                    }
                }
            }
        }

        nap(&stop, config.poll);
    }
}

/// Appends a record, up to [`MAX_COVERED`].
fn push(shared: &Mutex<Vec<Coverage>>, record: Coverage) {
    let mut records = lock(shared);
    if records.len() < MAX_COVERED {
        records.push(record);
    }
}

enum Outcome {
    Done(Coverage),
    /// Not ready yet. The next poll tries again, until `max_attempts`.
    Retry(String),
}

/// One pass at one descendant.
///
/// The handle is held for the whole call on purpose: an open handle keeps the
/// process object alive, and a pid on its own can be reused the moment the
/// process exits. Writing a payload into whatever inherited that pid would be
/// about the worst bug available here.
fn attempt(config: &SupervisorConfig, pid: u32, depth: usize, attempt_no: u32) -> Outcome {
    let proc = match RemoteProcess::open(pid) {
        Ok(proc) => proc,
        Err(err) => {
            // Gone, or beyond our rights. Either way it will never become
            // coverable, so it is not a "try again".
            return Outcome::Done(Coverage {
                pid,
                depth,
                image: String::new(),
                injected: false,
                hooked: false,
                sentinel: false,
                payload_base: None,
                note: Some(format!("open failed: {err:#}")),
            });
        }
    };

    // A 32-bit descendant is out of reach, and saying so is much better than
    // writing an x64 image into a WOW64 address space. See
    // [`RemoteProcess::is_x64_image`].
    match proc.is_x64_image() {
        Ok(true) => {}
        Ok(false) => {
            return Outcome::Done(Coverage {
                pid,
                depth,
                image: proc.image_path().map(|p| p.display().to_string()).unwrap_or_default(),
                injected: false,
                hooked: false,
                sentinel: false,
                payload_base: None,
                note: Some("not an x64 image; the payload is x64 only".to_string()),
            });
        }
        Err(err) => {
            return Outcome::Retry(format!("reading the image header: {err:#}"));
        }
    }

    let image = proc.image_path().map(|p| p.display().to_string());

    // The loader has to have finished before imports can be resolved. This is
    // the one failure worth retrying, and the reason `max_attempts` exists.
    let report = match manual_map::inject_bytes_with(
        &proc,
        pid,
        &config.payload_image,
        "DllMain",
        config.loader_wait,
        config.inject_poll,
    ) {
        Ok(report) => report,
        // Either the process is gone - in which case the next poll will not find
        // it and the record is moot - or its loader has not mapped what the
        // payload imports yet. Both are the caller's problem to count, and
        // neither is worth distinguishing here: the loop gives up either way.
        Err(err) => return Outcome::Retry(format!("attempt {attempt_no}: {err:#}")),
    };

    // From here on the payload is mapped exactly once. A retry would map a
    // second copy into the same process, so every remaining failure is recorded
    // rather than retried.
    let (hooked, mut note) = match manual_map::install_create_process_hook(
        &proc,
        &config.payload_path,
        &report,
        config.std_handles,
    ) {
        Ok(Some(_)) => (true, None),
        Ok(None) => (
            false,
            Some("does not import CreateProcessW; nothing to substitute".to_string()),
        ),
        Err(err) => (false, Some(format!("{err:#}"))),
    };

    let patch = proc.patch_console_state();

    Outcome::Done(Coverage {
        pid,
        depth,
        image: image.unwrap_or_default(),
        injected: true,
        hooked,
        sentinel: matches!(patch, Ok(ConsolePatch::Written(_))),
        payload_base: Some(report.image_base),
        note: match (note.take(), patch.err()) {
            (Some(n), _) => Some(n),
            (None, Some(err)) => Some(format!("console sentinel: {err:#}")),
            (None, None) => None,
        },
    })
}

/// Sleeps in slices so a shutdown is noticed promptly.
///
/// The loop's work per iteration is bounded by one loader wait, which is 150 ms
/// by default; sleeping the whole interval in one call would add the same again
/// before the thread reacts.
fn nap(stop: &AtomicBool, total: Duration) {
    const SLICE: Duration = Duration::from_millis(5);
    let mut left = total;
    while !left.is_zero() && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(SLICE.min(left));
        left = left.saturating_sub(SLICE);
    }
}