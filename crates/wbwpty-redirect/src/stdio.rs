//! What the payload does once it is running inside the target.
//!
//! The standard handles are **not** installed from here: the host hands the
//! real pipe handles to the child at creation time through
//! `STARTF_USESTDHANDLES`, so `ucrtbase` captures them on its very first
//! `GetStdHandle` call. Doing it again from inside the payload would only add a
//! race to lose.
//!
//! What is left is the console *semantics* the target cannot work without:
//!
//! * [`crate::peb::patch_console_state`] - make the target believe it has a
//!   console, so anything it spawns inherits the session pipes instead of being
//!   allocated one (which is what would spawn `conhost.exe`).

use crate::dlog;
use crate::peb::{self, PatchOutcome};

/// Runs the payload's attach path. Safe to call more than once.
pub fn install() {
    match peb::patch_console_state() {
        PatchOutcome::Patched => dlog!("stdio: console state faked"),
        PatchOutcome::AlreadySet => dlog!("stdio: console handle already set"),
        PatchOutcome::Skipped => dlog!("stdio: console state left untouched"),
    }
}