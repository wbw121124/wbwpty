//! Pointing the target's `CreateProcessW` at the payload.
//!
//! This is the host half of the interception described in the payload's
//! `hook.rs`: find the import slot, hand the payload the real address and our
//! pipe handles, then rewrite the slot.
//!
//! # Why an IAT slot
//!
//! Not an inline trampoline. `cmd.exe` is a Control Flow Guard image
//! (`DllCharacteristics = 0xc160`), and an indirect branch to an address that is
//! not a registered call target is exactly what CFG exists to reject. An IAT
//! slot is data; the guard never instruments it. There is also no instruction
//! boundary to find and no displaced bytes to relocate, which is where hand
//! written x64 hooks usually go wrong.
//!
//! # Ordering, which is the whole of the risk
//!
//! 1. Publish `WBWPTY_ORIGINAL_CREATE_PROCESS` and `WBWPTY_STD_HANDLES`.
//! 2. Only then rewrite the slot.
//!
//! A target whose thread calls the hook between those two steps would find a
//! zero original and return `FALSE`. Every write is a single aligned `u64` that
//! this process performs while the target is free-running, so there is no lock
//! to take - but the order is not arbitrary, and the payload checks the value
//! it reads for exactly this reason.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::manual_map::iat::{self, ImportSlot};
use crate::manual_map::remote::RemoteProcess;
use crate::manual_map::{InjectionReport, PeImage};

/// One intercepted API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intercept {
    /// The name as it appears in the target's import table.
    pub api: &'static str,
    /// Where the host published the real address for this API.
    pub original_export: &'static str,
    /// The payload export the slot now points at.
    pub substitute_export: &'static str,
    /// The slots that were rewritten.
    pub slots: Vec<ImportSlot>,
    /// The address the slot held before, which is the real API.
    pub original: u64,
    /// Where the payload's substitute lives inside the target.
    pub substitute: u64,
    /// True when the target's image pages had to be made writable first.
    pub needed_protection_change: bool,
}

/// What the interception did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookReport {
    /// Every API that was intercepted, in [`TARGETS`] order.
    ///
    /// A list rather than one entry because a target picks its own route to
    /// process creation. `cmd.exe` imports three, and which one it calls depends
    /// on how it was driven: the same command reaches `CreateProcessW` from an
    /// interactive prompt and reaches something else entirely under `/c`.
    pub intercepts: Vec<Intercept>,
}

impl HookReport {
    /// Number of call sites now going through the payload, across all APIs.
    pub fn slot_count(&self) -> usize {
        self.intercepts.iter().map(|i| i.slots.len()).sum()
    }

    /// The names actually intercepted, for reporting.
    pub fn apis(&self) -> Vec<&'static str> {
        self.intercepts.iter().map(|i| i.api).collect()
    }

    /// The `CreateProcessW` intercept, if that one was installed.
    pub fn primary(&self) -> Option<&Intercept> {
        self.intercepts.iter().find(|i| i.api == "CreateProcessW")
    }
}

/// One API to intercept, and where the payload keeps the real address.
struct Target {
    /// Name in the target's import table.
    api: &'static str,
    /// Export the host publishes the real address into.
    original_export: &'static str,
    /// Export the rewritten slot points at.
    substitute_export: &'static str,
}

/// Every process-creation entry point the payload can stand in for.
///
/// `cmd.exe` imports `CreateProcessW`, `CreateProcessAsUserW` and
/// `CreateProcessA`, and does **not** import `CreateProcessInternalW` (checked
/// against the shipped binary's import names). Intercepting only the first
/// looks like it works: the install reports one rewritten slot and no error,
/// and an interactive `cmd /k` does route its children through it. Under `/c`
/// the same command produces *zero* hook calls, which is what finally showed
/// that the substitution was installed and simply never entered.
const TARGETS: &[Target] = &[
    Target {
        api: "CreateProcessW",
        original_export: "WBWPTY_ORIGINAL_CREATE_PROCESS",
        substitute_export: "create_process_w",
    },
    Target {
        api: "CreateProcessAsUserW",
        original_export: "WBWPTY_ORIGINAL_CREATE_PROCESS_AS_USER_W",
        substitute_export: "create_process_as_user_w",
    },
    Target {
        api: "CreateProcessA",
        original_export: "WBWPTY_ORIGINAL_CREATE_PROCESS_A",
        substitute_export: "create_process_a",
    },
];

/// Substitutes the payload for the target's `CreateProcessW`.
///
/// Returns `Ok(None)` when the target does not import it at all, which is a
/// legitimate answer and not a failure: an API the target never calls needs no
/// interception, and a target that reaches `CreateProcess` by some other route
/// is a separate problem to diagnose rather than to paper over.
///
/// `proc` rather than a `&Child`, because this has to work on a process the host
/// did not create. The descendant supervisor has only a pid and a handle; the
/// target image to parse and the pid to report both come from that handle.
pub fn install_create_process_hook(
    proc: &RemoteProcess,
    payload_dll: &Path,
    report: &InjectionReport,
    std_handles: [u64; 3],
    explicit_environment: bool,
) -> Result<Option<HookReport>> {
    let pid = proc.pid().unwrap_or(0);
    let image_path = proc.image_path()?;
    let target_image = std::fs::read(&image_path)
        .with_context(|| format!("reading the target image {}", image_path.display()))?;

    // Which of the APIs this target actually imports decides whether there is
    // anything to do at all. Looked up first so a target that reaches process
    // creation some other way returns `Ok(None)` rather than an error.
    let wanted: Vec<&str> = TARGETS
        .iter()
        .map(|t| t.api)
        .filter(|api| {
            iat::find_imports(&target_image, &[api])
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        })
        .collect();
    if wanted.is_empty() {
        return Ok(None);
    }

    // The payload's own layout, so each published word can be found. The path
    // comes from the caller because this runs under a test binary whose working
    // directory is the package root, not the workspace root.
    let payload = std::fs::read(payload_dll)
        .with_context(|| format!("reading the payload {}", payload_dll.display()))?;
    let rva = |name: &str| -> Result<u32> {
        crate::manual_map::find_export_rva(&payload, name)
            .with_context(|| format!("the payload must export {name}"))?
            .with_context(|| format!("the payload does not export {name}"))
    };

    // The session's pipes go out before *any* slot is rewritten, not once per
    // API. A substitute entered with no handles published takes the early
    // "nothing to force" return, so the order is the whole of the risk - see the
    // module docs.
    let handles_rva = rva("WBWPTY_STD_HANDLES")?;
    let mut packed = [0u8; 24];
    for (slot, value) in packed.chunks_mut(8).zip(std_handles) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    proc.write_bytes(report.image_base + handles_rva as u64, &packed)
        .context("publishing the session standard handles")?;

    // Whether the substitute should hand the child an explicit environment
    // block. Generation 1 always does; generation 2 currently forwards the
    // target's `NULL`. The grandchild's stdout does not bind and the two
    // generations differ here, so it is a switch rather than an assumption.
    let env_rva = rva("WBWPTY_EXPLICIT_ENVIRONMENT")?;
    proc.write_bytes(
        report.image_base + env_rva as u64,
        &u32::from(explicit_environment).to_le_bytes(),
    )
    .context("publishing the explicit-environment choice")?;

    let mut intercepts = Vec::new();
    for t in TARGETS {
        if !wanted.contains(&t.api) {
            continue;
        }
        let slots = iat::find_imports(&target_image, &[t.api])
            .with_context(|| format!("walking the target's import table for {}", t.api))?;

        let target_base = proc.image_base()?;
        let first = slots[0].address(target_base);

        // Wait for the loader to have actually resolved this slot *before*
        // trusting what is in it, and before writing over it.
        //
        // Until it does, an IAT slot holds a pointer to an
        // `IMAGE_IMPORT_BY_NAME`, which lives inside the image itself; once it
        // does, the slot holds the real API address, which lives in another
        // module entirely. That difference is directly observable - the value
        // is inside `[base, base + SizeOfImage)` or it is not - and it is the
        // whole synchronisation problem.
        //
        // Skipping this is not a small mistake. Reading a hint/name pointer,
        // treating it as the resolved address and patching over it produces a
        // hook that installs cleanly, reports no error, holds the substituted
        // pointer for as long as anyone looks, and is then silently resolved
        // back to the real `CreateProcessW` by the loader moments later. The
        // only symptom is a payload counter that never moves - which is exactly
        // what a `cmd.exe /c` target shows.
        let size_of_image = PeImage::parse(&target_image)?.info.size_of_image as u64;
        let image_end = target_base.saturating_add(size_of_image);
        let gap = std::time::Duration::from_millis(2);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let original = loop {
            let bound = proc
                .read_bytes(first, 8)
                .with_context(|| format!("reading the bound {} slot in pid {pid}", t.api))?;
            let value = u64::from_le_bytes(bound.try_into().expect("read 8"));
            if value != 0 && !(target_base..image_end).contains(&value) {
                break value;
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "the loader never resolved the {} slot at {first:#x} in pid {pid} \
                     (last read {value:#x})",
                    t.api
                );
            }
            std::thread::sleep(gap);
        };

        // 1. Tell the payload what it is standing in for.
        let original_rva = rva(t.original_export)?;
        proc.write_bytes(
            report.image_base + original_rva as u64,
            &original.to_le_bytes(),
        )
        .with_context(|| format!("publishing the original {}", t.api))?;

        // 2. Only now may the slot point at us.
        let substitute = report.image_base + rva(t.substitute_export)? as u64;
        let needed_protection_change = match proc.write_bytes(first, &substitute.to_le_bytes()) {
            Ok(()) => false,
            Err(err) => {
                // An image's `.idata` is writable in practice, but not by contract.
                proc.protect(first, 8, windows_sys::Win32::System::Memory::PAGE_READWRITE)
                    .with_context(|| format!("making the {} slot writable: {err:#}", t.api))?;
                proc.write_bytes(first, &substitute.to_le_bytes())
                    .with_context(|| format!("writing the substituted {} slot", t.api))?;
                true
            }
        };

        // Reading the slot straight back proves only that we can write to it. It
        // does not prove the loader is finished with it: the image's own imports
        // are resolved *after* the process becomes visible to us, so a slot
        // patched a moment earlier gets resolved straight back to the real API.
        //
        // So wait for the slot to read back as ours *twice in a row*. A loader
        // still working clobbers the write, the mismatch repairs it, and a
        // loader that is already done passes on the first check - which keeps
        // the common case down to one extra read instead of a fixed settle.
        let mut consecutive = 0u32;
        loop {
            let read = proc
                .read_bytes(first, 8)
                .with_context(|| format!("reading back the {} slot in pid {pid}", t.api))?;
            let last = u64::from_le_bytes(read.try_into().expect("read 8"));
            if last == substitute {
                consecutive += 1;
                if consecutive >= 2 {
                    break;
                }
            } else {
                consecutive = 0;
                // Either the loader resolved it back, or the write did not land.
                // Put our pointer back and keep watching.
                proc.write_bytes(first, &substitute.to_le_bytes())
                    .with_context(|| format!("re-writing the substituted {} slot", t.api))?;
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "the {} slot never held {substitute:#x} in pid {pid} \
                     (last read {last:#x}): the loader is still rewriting it",
                    t.api
                );
            }
            std::thread::sleep(gap);
        }

        // The remaining slots for this API. The first one is the one a
        // single-import target uses and the one whose settling was just
        // verified; the rest are rewritten best effort, because a secondary slot
        // that resists should not discard an interception that is already live.
        for slot in &slots[1..] {
            let addr = slot.address(target_base);
            if proc.write_bytes(addr, &substitute.to_le_bytes()).is_err() {
                let _ = proc.protect(addr, 8, windows_sys::Win32::System::Memory::PAGE_READWRITE);
                proc.write_bytes(addr, &substitute.to_le_bytes())
                    .with_context(|| format!("writing a secondary {} slot", t.api))?;
            }
        }

        intercepts.push(Intercept {
            api: t.api,
            original_export: t.original_export,
            substitute_export: t.substitute_export,
            slots,
            original,
            substitute,
            needed_protection_change,
        });
    }

    Ok(Some(HookReport { intercepts }))
}
