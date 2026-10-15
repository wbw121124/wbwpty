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

use crate::child::Child;
use crate::manual_map::iat::{self, ImportSlot};
use crate::manual_map::remote::RemoteProcess;
use crate::manual_map::InjectionReport;

/// What the interception did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookReport {
    /// The slots that were rewritten.
    pub slots: Vec<ImportSlot>,
    /// The address the slot held before, which is the real `CreateProcessW`.
    pub original: u64,
    /// Where the payload's substitute now lives inside the target.
    pub substitute: u64,
    /// True when the target's image pages had to be made writable first.
    pub needed_protection_change: bool,
}

impl HookReport {
    /// Number of call sites now going through the payload.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

/// Substitutes the payload for the target's `CreateProcessW`.
///
/// Returns `Ok(None)` when the target does not import it at all, which is a
/// legitimate answer and not a failure: an API the target never calls needs no
/// interception, and a target that reaches `CreateProcess` by some other route
/// is a separate problem to diagnose rather than to paper over.
pub fn install_create_process_hook(
    child: &Child,
    payload_dll: &Path,
    report: &InjectionReport,
    std_handles: [u64; 3],
) -> Result<Option<HookReport>> {
    let proc = RemoteProcess::new(child.process_handle());
    let target_image = std::fs::read(&child.image)
        .with_context(|| format!("reading the target image {}", child.image.display()))?;
    let slots = iat::find_imports(&target_image, &["CreateProcessW"])
        .context("walking the target's import table")?;
    if slots.is_empty() {
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
    let original_rva = rva("WBWPTY_ORIGINAL_CREATE_PROCESS")?;
    let handles_rva = rva("WBWPTY_STD_HANDLES")?;
    let hook_rva = rva("create_process_w")?;

    let target_base = proc.image_base()?;
    let first = slots[0].address(target_base);
    let original = proc
        .read_bytes(first, 8)
        .context("reading the bound import slot")?;
    let original = u64::from_le_bytes(original.try_into().expect("read 8"));
    if original == 0 {
        bail!("the loader left {:#x} unbound, so there is nothing to intercept", first);
    }

    // 1. Tell the payload what it is standing in for and whose pipes to hand on.
    proc.write_bytes(
        report.image_base + original_rva as u64,
        &original.to_le_bytes(),
    )
    .context("publishing the original CreateProcessW")?;

    let mut packed = [0u8; 24];
    for (slot, value) in packed.chunks_mut(8).zip(std_handles) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    proc.write_bytes(report.image_base + handles_rva as u64, &packed)
        .context("publishing the session standard handles")?;

    // 2. Only now the slot may point at us.
    let substitute = report.image_base + hook_rva as u64;
    let needed_protection_change = match proc.write_bytes(first, &substitute.to_le_bytes()) {
        Ok(()) => false,
        Err(err) => {
            // An image's `.idata` is writable in practice, but not by contract.
            proc.protect(first, 8, windows_sys::Win32::System::Memory::PAGE_READWRITE)
                .with_context(|| format!("making the import slot writable: {err:#}"))?;
            proc.write_bytes(first, &substitute.to_le_bytes())
                .context("writing the substituted import slot")?;
            true
        }
    };

    let verify = proc.read_bytes(first, 8)?;
    let verify = u64::from_le_bytes(verify.try_into().expect("read 8"));
    if verify != substitute {
        bail!(
            "the import slot did not take: wrote {substitute:#x}, read back {verify:#x}"
        );
    }

    Ok(Some(HookReport {
        slots,
        original,
        substitute,
        needed_protection_change,
    }))
}