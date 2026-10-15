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
//!   console, so anything it spawns is not allocated one (which is what would
//!   spawn `conhost.exe`).

use crate::peb::{self, PatchOutcome};
use crate::stage;

/// What [`install`] managed to do, mapped onto the stage word the host reads.
///
/// Returning it rather than logging it is deliberate: the payload has no way to
/// report an error to anyone, and a patch that silently does nothing is
/// indistinguishable from one that worked unless something outside can see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachOutcome {
    patch: PatchOutcome,
}

impl AttachOutcome {
    /// The `WBWPTY_STATUS` stage describing this outcome.
    pub fn stage(self) -> u32 {
        match self.patch {
            PatchOutcome::Patched => stage::CONSOLE_PATCHED,
            PatchOutcome::AlreadySet => stage::CONSOLE_ALREADY_SET,
            PatchOutcome::Skipped => stage::CONSOLE_SKIPPED,
        }
    }
}

/// Runs the payload's attach path. Safe to call more than once.
///
/// `dlog!` is deliberately absent from this function: its formatting code reads
/// PEB offsets beyond `RTL_USER_PROCESS_PARAMETERS`, which faults under the
/// loader lock. The outcome travels to the host through the status word instead.
pub fn install() -> AttachOutcome {
    let patch = peb::patch_console_state();
    AttachOutcome { patch }
}