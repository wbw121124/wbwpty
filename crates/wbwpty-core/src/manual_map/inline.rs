//! Replacing process creation by patching the function itself, not the IAT.
//!
//! # Why not the IAT slot
//!
//! The first version of this project substituted the target's `CreateProcessW`
//! import *slot*. That works, and it loses a race it can never win:
//!
//! ```text
//!   0 ms   CreateProcessW(cmd.exe, DETACHED_PROCESS | CREATE_SUSPENDED)
//!  ~30 ms   cmd's own loader finishes; cmd's entry point runs
//!  ~31 ms   cmd calls CreateProcessW                  <- the slot is live here
//!  ~36 ms   we finish patching the slot               <- far too late
//! ```
//!
//! The substitution was installed at 36 ms and reported `hook calls = 0`: cmd's
//! only spawn happened before it existed. Measured, not inferred.
//!
//! Three things made that gap unfixable by tuning:
//!
//! * the slot cannot be trusted until the loader has resolved it, and the test
//!   that proves it is the same thing being waited for (a slot that is not yet
//!   resolved holds an `IMAGE_IMPORT_BY_NAME` pointer *inside the image*, so
//!   writing over it looks like it worked and is then silently resolved back);
//! * most of the wait is the target's own startup, not ours;
//! * `cmd.exe` does not even import from `KERNEL32.dll`. It imports the API set
//!   `api-ms-win-core-processthreads-l1-1-1.dll`, which the loader maps through
//!   the API set schema, which forwards again. So there was never one obvious
//!   slot - there was a chain.
//!
//! # What this does instead
//!
//! Patches the entry point of `kernelbase!CreateProcessInternalW` in the target.
//! Every process-creation path lands there: `CreateProcessW`,
//! `CreateProcessAsUserW` and `CreateProcessA` all resolve to it, and the API set
//! indirection is above it, not around it.
//!
//! This makes the timing question disappear rather than harder. The IAT slot is
//! whatever the loader wrote whenever it got round to it; the *code* at the
//! target of every one of those writes is ours from the moment we patch it. A
//! caller that resolved its slot before we patched still calls into the hook,
//! because the address it resolved is the address we overwrote.
//!
//! # The one subtlety: relocating the prologue
//!
//! Overwriting the first bytes of a function destroys its prologue, so the
//! original instructions have to be replayed. They go in a trampoline that the
//! payload's substitute jumps to *after* it returns, which is safe precisely
//! because at that point the stack is back where the caller left it - the
//! relocated `push`es then behave exactly as they would have without a hook.
//!
//! Relocation is only valid for instructions whose encoding does not depend on
//! where they sit. A RIP-relative operand or a relative branch would point at the
//! wrong place once copied. That is checked with a real decoder
//! ([`is_relocatable`]) rather than by pattern-matching the bytes, and a
//! prologue that cannot be proven safe is refused rather than guessed at - the
//! fallback is the existing IAT patch, which is slower but correct.

use anyhow::{bail, Context, Result};

use crate::manual_map::exports::ExportTable;
use crate::manual_map::remote::RemoteProcess;

/// One export to replace, and the payload symbol that replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineTarget {
    /// Module that exports it, matched against the target's own module list.
    pub module: &'static str,
    /// Export name.
    pub export: &'static str,
    /// Export in the payload that takes over.
    pub substitute: &'static str,
    /// Export in the payload that receives the trampoline address, so its
    /// substitute has a way back into the original.
    pub original_slot: &'static str,
}

/// The exports to replace, and why these and not something else.
///
/// `CreateProcessInternalW` would be the ideal single point - every path funnels
/// through it - but it is an internal function: absent from the Windows SDK, and
/// its argument order could not be established from this machine. Two attempts to
/// read it off a live call disagreed with each other, and guessing wrong means
/// corrupting the stack of a process this project does not own. These two are
/// documented in `winbase.h`, so their signatures are known rather than inferred,
/// and the substitutes in the payload already exist for the IAT path.
///
/// Both are needed. `kernelbase!CreateProcessW` is a real function that calls
/// `CreateProcessInternalW`, so a call that goes straight to the internal entry -
/// which is what `CreateProcessAsUserW` does - never passes through it. Patching
/// only the documented `CreateProcessW` would cover exactly the paths that did
/// not need covering.
pub const TARGETS: &[InlineTarget] = &[
    InlineTarget {
        module: "kernelbase.dll",
        export: "CreateProcessW",
        substitute: "create_process_w",
        original_slot: "WBWPTY_ORIGINAL_CREATE_PROCESS",
    },
    InlineTarget {
        module: "kernelbase.dll",
        export: "CreateProcessAsUserW",
        substitute: "create_process_as_user_w",
        original_slot: "WBWPTY_ORIGINAL_CREATE_PROCESS_AS_USER_W",
    },
];

/// Length of the prologue we take and relocate.
///
/// Twelve bytes is the smallest region that can hold an absolute jump
/// (`mov rax, imm64` is 10, `jmp rax` is 2), so it is the least we have to
/// relocate and the least we have to prove safe.
const PROLOGUE_LEN: usize = 12;

/// The flag whose presence makes the kernel allocate a console for the child.
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

/// `mov rax, imm64; jmp rax` - an unconditional jump to an arbitrary address.
///
/// Twelve bytes because that is what an absolute jump costs in x64. `rax` is
/// volatile and is not an incoming argument under the Microsoft x64 convention
/// (the four arguments are `rcx`, `rdx`, `r8`, `r9`), so clobbering it at a
/// function entry is legal. A five-byte relative jump would be shorter but
/// reaches only +/-2 GiB, and the payload is mapped wherever the preferred base
/// allowed while `kernelbase` is somewhere else entirely - measured, the two are
/// tens of gigabytes apart, so relative is not an option.
pub fn jump_absolute(target: u64) -> [u8; PROLOGUE_LEN] {
    let mut out = [0u8; PROLOGUE_LEN];
    out[0] = 0x48; // REX.W
    out[1] = 0xB8; // mov rax, imm64
    out[2..10].copy_from_slice(&target.to_le_bytes());
    out[10] = 0xFF; // jmp rax
    out[11] = 0xE0;
    out
}

/// Builds the trampoline: the relocated prologue, then a jump back into the
/// original function past the bytes we replaced.
pub fn build_trampoline(relocated: &[u8], resume_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(relocated.len() + PROLOGUE_LEN);
    out.extend_from_slice(relocated);
    out.extend_from_slice(&jump_absolute(resume_at));
    out
}

/// Whether `bytes` can be copied to a different address and still do the same
/// thing.
///
/// True only for instructions whose encoding is position-independent. Anything
/// that reads or branches through a RIP-relative displacement is false, because
/// the displacement is an offset from the *instruction's own address* and moving
/// the instruction moves the target it refers to.
///
/// Decoded rather than pattern-matched: a byte-pattern check for `E8`/`E9`/`0F`
/// would have to guess about every opcode that takes a displacement, and
/// mistaking a `push imm32` for a branch would produce a trampoline that jumps
/// somewhere unrelated. Getting this wrong is a crash inside somebody else's
/// process, which is the failure mode this module exists to avoid.
pub fn is_relocatable(bytes: &[u8]) -> bool {
    use iced_x86::{Code, Decoder, DecoderOptions};

    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let mut covered = 0usize;
    loop {
        let instruction = decoder.decode();
        // `INVALID` is iced's answer for bytes it cannot decode - which is what a
        // prologue truncated mid-instruction looks like, and exactly the case
        // that must be refused rather than guessed at.
        if instruction.code() == Code::INVALID {
            return false;
        }
        if instruction.ip() + instruction.len() as u64 > bytes.len() as u64 {
            return false;
        }
        covered += instruction.len();

        // Two position-dependent forms, and only two:
        //
        // * RIP-relative memory operands - the displacement is measured from the
        //   instruction's own address, so moving it moves what it refers to;
        // * relative branches and calls - same problem, via the branch target.
        //
        // Both are asked through iced's own predicates rather than matched by
        // opcode, because the set of encodings that carry a displacement is
        // large and a byte-pattern check would eventually be wrong about one of
        // them. A wrong answer here writes a trampoline that jumps into the
        // wrong place inside somebody else's process.
        if instruction.is_ip_rel_memory_operand() || instruction.near_branch_target() != 0 {
            return false;
        }
        if covered == bytes.len() {
            return true;
        }
    }
}

/// Where a target's export lives in this target process.
///
/// The base comes from the caller because the export table only carries RVAs - it
/// is read out of a running process, which has no idea where its modules were
/// put.
pub fn find_export(module_base: u64, table: &ExportTable, export: &str) -> Result<u64> {
    use crate::manual_map::exports::ExportTarget;

    let target = table.by_name(export).with_context(|| {
        format!("the export table has no {export}, so there is nothing to replace")
    })?;
    match target {
        ExportTarget::Rva(rva) => Ok(module_base + *rva as u64),
        ExportTarget::Forwarder(text) => bail!(
            "{export} is a forwarder ({text}), so the address in the export table is \
             a string rather than the first instruction to run"
        ),
    }
}

/// Result of an inline hook attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineHook {
    /// The function's entry now points at the substitute.
    Installed {
        /// Which export this was.
        export: &'static str,
        /// Address of the patched function entry.
        entry: u64,
        /// Address of the trampoline holding the relocated prologue.
        trampoline: u64,
    },
    /// The prologue could not be proven safe to relocate, so nothing was written.
    Refused {
        /// Which export this was.
        export: &'static str,
        /// Why it was left alone.
        reason: String,
    },
}

/// Patches one export so it enters the substitute.
///
/// `substitute` is where control should go first; the original instructions are
/// replayed from a trampoline the substitute reaches through `original_slot`.
///
/// Writes nothing at all when the prologue cannot be proven relocatable. A refused
/// hook is a performance regression; a wrong hook is a crash in a process that
/// belongs to somebody else.
pub fn install_inline_hook(
    proc: &RemoteProcess,
    module_base: u64,
    table: &ExportTable,
    payload_base: u64,
    target: &InlineTarget,
) -> Result<InlineHook> {
    let entry = find_export(module_base, table, target.export)?;
    let prologue = proc
        .read_bytes(entry, PROLOGUE_LEN)
        .with_context(|| format!("reading the prologue of {} at {entry:#x}", target.export))?;

    if !is_relocatable(&prologue) {
        return Ok(InlineHook::Refused {
            export: target.export,
            reason: format!(
                "the first {PROLOGUE_LEN} bytes at {entry:#x} are not \
                 position-independent, so they cannot be relocated"
            ),
        });
    }

    // The trampoline holds the relocated prologue plus a jump. It is reached by an
    // absolute jump, so it does not need to be near anything.
    let built = build_trampoline(&prologue, entry + PROLOGUE_LEN as u64);
    let trampoline = proc.allocate(built.len())?;
    proc.write_bytes(trampoline, &built).with_context(|| {
        format!(
            "writing the {} trampoline at {trampoline:#x}",
            target.export
        )
    })?;

    // The substitute address is the payload's own export, resolved from the
    // mapped image - which is at `payload_base`, *not* the target's image base.
    // Reading `image_base()` here returns the target executable's base and yields
    // whatever bytes happen to be there.
    let substitute = resolve_substitute(payload_base, target.substitute)?;
    proc.write_bytes(entry, &jump_absolute(substitute))
        .with_context(|| format!("patching {} at {entry:#x}", target.export))?;

    Ok(InlineHook::Installed {
        export: target.export,
        entry,
        trampoline,
    })
}

/// The address of a payload export in the mapped image.
///
/// Resolved from the payload's own file rather than assumed, so a rebuilt
/// payload - which will have moved every export - keeps working.
fn resolve_substitute(payload_base: u64, name: &str) -> Result<u64> {
    let image = EXPORT_IMAGE
        .get()
        .ok_or_else(|| anyhow::anyhow!("the payload image was never published"))?;
    let rva = crate::manual_map::find_export_rva(image, name)
        .with_context(|| format!("the payload must export {name}"))?
        .with_context(|| format!("the payload does not export {name}"))?;
    Ok(payload_base + rva as u64)
}

/// The payload image, published once by the session.
///
/// A `OnceLock` rather than a field because it is read from the supervisor thread
/// and is the same for the whole session.
static EXPORT_IMAGE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// Publishes the payload image for export resolution.
pub fn publish_payload_image(image: Vec<u8>) {
    let _ = EXPORT_IMAGE.set(image);
}

/// Forces `DETACHED_PROCESS` on a stack argument, with no imports at all.
///
/// # Why this exists, separately from everything else here
///
/// Every other mechanism in this file needs the payload, and the payload needs its
/// imports resolved, and resolving them needs the target to have mapped
/// `kernelbase.dll` - because `kernel32`'s exports are forwarders into it.
/// Measured on this machine that wait is about 28 ms, while `cmd.exe` calls
/// `CreateProcess` at about 31 ms and the full substitution is not live until
/// 43 ms. The only mechanism that can be installed in time is the one that
/// depends on nothing.
///
/// Which is what this is: straight-line code that ORs a bit into the caller's
/// argument and jumps on, with no calls, no data and no imports, so it needs only
/// `kernelbase`'s address and can go in the moment the loader maps it.
///
/// It is deliberately incomplete - no handles, no handover, neither of which it
/// could do without the payload. Its whole job is to make sure no console is ever
/// allocated. The full substitution follows and takes over; by then the spawn it
/// needed to intercept has already been intercepted.
///
/// # The encoding
///
/// `dwCreationFlags` is the sixth parameter of `CreateProcessW`, so at the entry
/// - before any prologue - it is at `rsp + 0x30`: four register parameters
/// shadow the return address, so the fifth is at `rsp + 0x28` and the sixth at
/// `rsp + 0x30`.
///
/// `rsp`-relative addressing needs a SIB byte, which no encoding of `or`/`and`
/// with a `[rsp+disp32]` memory destination omits. That is why these are 8 and 10
/// bytes rather than the 6 and 8 they would otherwise be.
pub fn force_detached_stub(flags_at_rsp_offset: u32) -> Vec<u8> {
    force_flags_at(flags_at_rsp_offset, 4)
}

/// Offset of `ProcessFlags` from `rsp` at the entry of `NtCreateUserProcess`.
///
/// Four register parameters, so the fifth is the first on the stack. It is a
/// `ULONG_PTR` - eight bytes - unlike `CreateProcessW`'s `DWORD`, which is why the
/// stub is generated at a different width rather than reused.
pub const NT_CREATE_USER_PROCESS_FLAGS_OFFSET: u32 = 0x28;

/// Forces `DETACHED_PROCESS` on the `ProcessFlags` argument of
/// `NtCreateUserProcess`.
///
/// # Why this hook point rather than `CreateProcessW`
///
/// Because it exists in a process that has not started. `cmd.exe` is created
/// suspended, and a suspended process has only its executable and `ntdll` mapped -
/// `kernelbase` arrives later, with the loader, which is measured at about 25 ms.
/// `cmd.exe`'s first `CreateProcess` happens before even 10 ms. So there is no
/// moment at which `kernelbase` is both mapped and still early enough to matter.
///
/// `ntdll` is a different proposition: it is there from the moment the kernel
/// creates the process, `NtCreateUserProcess` is the single point every Win32
/// process-creation API funnels into, and it takes the creation flags as a plain
/// value. So the child can be created suspended, the hook installed while it
/// cannot run anything, and only then resumed.
///
/// # Encoding
///
/// 64-bit operand, so a REX.W prefix on both instructions - which also makes them
/// longer than the 32-bit pair:
///
///   48 83 8C 24 28 00 00 00 08          or  qword [rsp+0x28], 8
///   48 81 A4 24 28 00 00 00 00 F0FFFFFF and qword [rsp+0x28], 0xFFFFFFFFFFFFFFF0
pub fn force_detached_stub_nt() -> Vec<u8> {
    force_flags_at(NT_CREATE_USER_PROCESS_FLAGS_OFFSET, 8)
}

/// The flag-forcing pair, at a given stack offset and operand width.
fn force_flags_at(offset: u32, width: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    // `or` - group 1, /1; ModRM `0x8C` is mod `10`, reg `001`, rm `100` (SIB),
    // which is what makes the operand `[rsp+disp32]` rather than a register.
    if width == 8 {
        // Sign-extended 32-bit operand, which does *not* mean a 32-bit operation:
        // 0x83 has no qword form and REX.W promotes it. This is not a stylistic
        // choice - a 32-bit operation would clear the low half of the flags and
        // leave the top half, and the kernel reads the whole thing.
        //
        // The 32-bit encoding below is *not* usable here: with REX.W, `0x83 /1`
        // is `or rbx, imm32` - ModRM rm `100` is REX.B rather than a SIB byte, so
        // the displacement has nowhere to go and the instruction lands in a
        // register. It decodes, which is how it survived a first attempt.
        out.extend_from_slice(&[0x48, 0x83, 0x8C, 0x24]);
        out.extend_from_slice(&offset.to_le_bytes());
        out.push(0x08);
    } else {
        out.extend_from_slice(&[0x83, 0x8C, 0x24]);
        out.extend_from_slice(&offset.to_le_bytes());
        out.push(0x08);
    }
    // `and` - group 1, /4; ModRM `0xA4` is reg `100`. `0x8C` would be OR, and
    // OR-ing a mask sets the bit instead of clearing it.
    if width == 8 {
        out.extend_from_slice(&[0x48, 0x81, 0xA4, 0x24]);
    } else {
        out.extend_from_slice(&[0x81, 0xA4, 0x24]);
    }
    out.extend_from_slice(&offset.to_le_bytes());
    // `0x81 /4` takes an imm32 and *sign-extends* it, which is what makes this one
    // four bytes wide enough for a 64-bit operand: 0xFFFFFFF0 becomes
    // 0xFFFFFFFFFFFFFFF0. Writing the full eight bytes instead leaves four of them
    // stranded after the instruction, and the stub then fails to decode at its own
    // length - the mask's high dwords were never encoded anywhere.
    //
    // The mask is `!CREATE_NEW_CONSOLE`. It was `0xFFFF_FFF0`, which reads like
    // "clear the low flags" and is off by one bit: it zeroes bits 0-3 and leaves
    // bit 4, and `CREATE_NEW_CONSOLE` is `0x10` - bit 4. So the AND was a no-op on
    // the one flag it exists to clear, while still decoding as an AND. Only
    // executing the stub against a real frame showed it.
    debug_assert_eq!(
        !0xFFFF_FFF0u32 & CREATE_NEW_CONSOLE,
        0,
        "this mask does not clear CREATE_NEW_CONSOLE"
    );
    out.extend_from_slice(&(u32::MAX & !CREATE_NEW_CONSOLE).to_le_bytes());
    out
}

/// Offset of `dwCreationFlags` from `rsp` at the entry of `CreateProcessW`.
pub const CREATE_PROCESS_W_FLAGS_OFFSET: u32 = 0x30;

/// What [`install_forced_stub`] patched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedStub {
    /// Address of the patched function entry.
    pub entry: u64,
    /// Address of the stub it now jumps to.
    pub stub: u64,
}

/// Bytes [`install_forced_stub`] writes into its stub buffer.
pub fn forced_stub_size() -> usize {
    force_detached_stub(CREATE_PROCESS_W_FLAGS_OFFSET).len() + PROLOGUE_LEN * 2
}

/// Patches `entry` so it forces `DETACHED_PROCESS` before running the original.
///
/// Needs nothing but `kernelbase`'s address, which is why it can be installed
/// before the payload's imports are resolved.
///
/// Unlike [`install_inline_hook`] there is no substitute to fall back to, so a
/// prologue that cannot be proven safe to relocate is an outright failure rather
/// than a refusal: leaving the entry alone here means every descendant gets a
/// console, which is the one outcome this whole mechanism exists to prevent.
pub fn install_forced_stub(proc: &RemoteProcess, entry: u64, stub: u64) -> Result<ForcedStub> {
    let prologue = proc
        .read_bytes(entry, PROLOGUE_LEN)
        .with_context(|| format!("reading the prologue at {entry:#x}"))?;
    if !is_relocatable(&prologue) {
        bail!(
            "the first {PROLOGUE_LEN} bytes at {entry:#x} are not position-independent, \
             so they cannot be relocated"
        );
    }
    if stub == 0 {
        bail!("no stub buffer was provided");
    }

    let mut body = force_detached_stub(CREATE_PROCESS_W_FLAGS_OFFSET);
    body.extend_from_slice(&prologue);
    body.extend_from_slice(&jump_absolute(entry + PROLOGUE_LEN as u64));
    proc.write_bytes(stub, &body)
        .with_context(|| format!("writing the stub at {stub:#x}"))?;
    make_writable(proc, entry, PROLOGUE_LEN)?;
    proc.write_bytes(entry, &jump_absolute(stub))
        .with_context(|| format!("patching {entry:#x}"))?;

    Ok(ForcedStub { entry, stub })
}

/// Offset of `dwCreationFlags` from `rsp` at the entry of `CreateProcessInternalW`.
///
/// `cmd.exe` does not call `CreateProcessW`. It calls `CreateProcessInternalW`
/// directly, which is why every mechanism anchored on `CreateProcessW` - the IAT
/// slot, the inline hook, the forced stub - could be installed successfully and
/// then never run once, sitting next to a `ping` that had a console.
///
/// Its argument list is `CreateProcessW`'s, so the offset is unchanged. Read off a
/// live `cmd.exe` paused at this entry with `RSP = 0x3CF58FF118`:
///
///     [rsp+0x20] = 0x00007FFEE31B3124  lpThreadAttributes (kernelbase .data)
///     [rsp+0x28] = 0x1                   bInheritHandles
///     [rsp+0x30] = 0x0                   dwCreationFlags
///     [rsp+0x38] = 0x0000018E5330ABC0   lpEnvironment      (a pointer)
///     [rsp+0x40] = 0x0000003CF58FF290   lpCurrentDirectory
///     [rsp+0x48] = 0x0000003CF58FF278   lpStartupInfo
///
/// The seventh parameter reading taken here earlier - `0x80000` at `[rsp+0x38]` -
/// was a different call's frame, and `0x80000` is not a documented flag bit. It is
/// `lpEnvironment` above, and it is a pointer. An offset is worth nothing without
/// the frame it was read from, so the frame is recorded with it.
pub const CREATE_PROCESS_INTERNAL_W_FLAGS_OFFSET: u32 = CREATE_PROCESS_W_FLAGS_OFFSET;

/// What [`install_internal_forced_stub`] patched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalForcedStub {
    /// Address of the patched function entry.
    pub entry: u64,
    /// Address of the stub it now jumps to.
    pub stub: u64,
}

/// Bytes [`install_internal_forced_stub`] writes into its stub buffer.
pub fn internal_forced_stub_size() -> usize {
    force_flags_at(CREATE_PROCESS_INTERNAL_W_FLAGS_OFFSET, 4).len() + PROLOGUE_LEN * 2
}

/// Patches `CreateProcessInternalW` so it forces `DETACHED_PROCESS`.
///
/// This is the entry `cmd.exe` actually reaches, so unlike
/// [`install_forced_stub`] this one is on the path that matters. Its prologue is
/// twelve bytes of pushes, which is why it can be patched this early at all.
pub fn install_internal_forced_stub(
    proc: &RemoteProcess,
    entry: u64,
    stub: u64,
) -> Result<InternalForcedStub> {
    let prologue = proc
        .read_bytes(entry, PROLOGUE_LEN)
        .with_context(|| format!("reading the prologue at {entry:#x}"))?;
    if !is_relocatable(&prologue) {
        bail!(
            "the first {PROLOGUE_LEN} bytes at {entry:#x} are not position-independent, \
             so they cannot be relocated"
        );
    }
    if stub == 0 {
        bail!("no stub buffer was provided");
    }

    let mut body = force_flags_at(CREATE_PROCESS_INTERNAL_W_FLAGS_OFFSET, 4);
    body.extend_from_slice(&prologue);
    body.extend_from_slice(&jump_absolute(entry + PROLOGUE_LEN as u64));
    proc.write_bytes(stub, &body)
        .with_context(|| format!("writing the stub at {stub:#x}"))?;
    make_writable(proc, entry, PROLOGUE_LEN)?;
    proc.write_bytes(entry, &jump_absolute(stub))
        .with_context(|| format!("patching {entry:#x}"))?;

    Ok(InternalForcedStub { entry, stub })
}

/// Bytes [`install_nt_forced_stub`] writes.
pub fn nt_forced_stub_size() -> usize {
    force_detached_stub_nt().len() + PROLOGUE_LEN * 2
}

/// Patches `ntdll!NtCreateUserProcess` so it forces `DETACHED_PROCESS`.
///
/// Unlike [`install_forced_stub`] this is meant to be called while the target is
/// **suspended**, which is the point: `ntdll` is mapped from the moment the kernel
/// creates a process, so this can be in place before the target runs a single
/// instruction. `kernelbase` cannot - it arrives with the loader, by which time a
/// target like `cmd.exe` has already spawned.
///
/// `ntdll_base` is where `ntdll` is in the target. System DLLs are loaded at the
/// same address in every process on a boot, so the host's own is almost always
/// correct, but it is verified by reading the image header out of the target
/// before anything is written - a wrong address here would patch whatever happens
/// to live there in someone else's process.
pub fn install_nt_forced_stub(
    proc: &RemoteProcess,
    ntdll_base: u64,
    stub: u64,
) -> Result<ForcedStub> {
    let entry = resolve_nt_export(proc, ntdll_base, "NtCreateUserProcess")?;
    let prologue = proc
        .read_bytes(entry, PROLOGUE_LEN)
        .with_context(|| format!("reading the prologue of NtCreateUserProcess at {entry:#x}"))?;
    if !is_relocatable(&prologue) {
        bail!(
            "the first {PROLOGUE_LEN} bytes of NtCreateUserProcess at {entry:#x} are \
             not position-independent, so they cannot be relocated"
        );
    }
    if stub == 0 {
        bail!("no stub buffer was provided");
    }

    let mut body = force_detached_stub_nt();
    body.extend_from_slice(&prologue);
    body.extend_from_slice(&jump_absolute(entry + PROLOGUE_LEN as u64));
    proc.write_bytes(stub, &body)
        .with_context(|| format!("writing the NtCreateUserProcess stub at {stub:#x}"))?;
    make_writable(proc, entry, PROLOGUE_LEN)?;
    proc.write_bytes(entry, &jump_absolute(stub))
        .with_context(|| format!("patching NtCreateUserProcess at {entry:#x}"))?;

    Ok(ForcedStub { entry, stub })
}

/// The address of an `ntdll` export, read from the *target's* `ntdll` on disk.
///
/// The file is read locally rather than across the process: `ntdll.dll` is about
/// two megabytes and its export directory is large, and this runs while the
/// target is suspended and every microsecond of the startup budget still matters.
fn resolve_nt_export(proc: &RemoteProcess, ntdll_base: u64, export: &str) -> Result<u64> {
    // Confirm the assumed base before using it. Reading two bytes cannot fault and
    // costs nothing; writing to the wrong address would.
    let magic = proc.read_bytes(ntdll_base, 2)?;
    if &magic != b"MZ" {
        bail!(
            "ntdll does not appear to be mapped at {ntdll_base:#x} in the target \
             (found {magic:?} instead of MZ)"
        );
    }

    let path = std::path::Path::new("C:\\Windows\\System32\\ntdll.dll");
    let module = crate::manual_map::RemoteModule {
        base: ntdll_base,
        size: 0,
        full_name: path.display().to_string(),
        base_name: "ntdll.dll".to_string(),
    };
    let table = crate::manual_map::exports::load_exports_from_file(path, &module)?;
    find_export(ntdll_base, &table, export)
}

/// Makes `len` bytes at `addr` writable in the target, remembering nothing.
///
/// An image section is not writable by contract even when it happens to be, and
/// the failure otherwise is `WriteProcessMemory` refusing with a bare
/// `ERROR_ACCESS_DENIED` that says nothing about which of the two it was.
fn make_writable(proc: &RemoteProcess, addr: u64, len: usize) -> Result<()> {
    proc.protect(
        addr,
        len,
        windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
    )
    .with_context(|| format!("making {addr:#x} executable and writable"))
}

/// Patches `ntdll!RtlCreateUserProcess` so it forces `DETACHED_PROCESS`.
///
/// # Why this function and not `NtCreateUserProcess`
///
/// `NtCreateUserProcess` is where everything funnels into, and it cannot be hooked
/// this way: its first twelve bytes contain a RIP-relative test
/// (`f6 04 25 08 ...`), so they cannot be relocated into a trampoline, and
/// refusing is the correct outcome rather than a near miss. The same test byte
/// opens `NtCreateProcess` and `NtCreateProcessEx`.
///
/// `RtlCreateUserProcess` has a prologue of three ordinary instructions -
/// `mov r11, rsp; sub rsp, 0x78; and qword [rsp+0x34], 0` - which relocates
/// cleanly. It is the user-mode entry the Win32 implementation goes through, and
/// `Rtl` is where the flag translation happens.
///
/// # The argument position, and why it is not the ntdll one
///
/// `ProcessFlags` is the fifth parameter, so at entry it is at `rsp + 0x28` - the
/// same offset `NtCreateUserProcess` uses.
///
/// Careful here, though: the relocation puts those three instructions *after* the
/// `sub rsp, 0x78`, so the stack the relocated code sees is 0x78 deeper than the
/// one the flag-forcing ran on. They do not interfere - the flag forcing runs
/// before the prologue and the prologue does not touch `rsp + 0x28` - but a stub
/// that were to read its arguments *after* the relocated prologue would be
/// reading the wrong slot, and nothing about the failure would say so.
pub fn install_rtl_creation_hook(
    proc: &RemoteProcess,
    ntdll_base: u64,
    stub: u64,
) -> Result<ForcedStub> {
    let entry = resolve_nt_export(proc, ntdll_base, "RtlCreateUserProcess")?;
    let prologue = proc
        .read_bytes(entry, PROLOGUE_LEN)
        .with_context(|| format!("reading the prologue of RtlCreateUserProcess at {entry:#x}"))?;
    if !is_relocatable(&prologue) {
        bail!(
            "the first {PROLOGUE_LEN} bytes of RtlCreateUserProcess at {entry:#x} are \
             not position-independent, so they cannot be relocated"
        );
    }
    if stub == 0 {
        bail!("no stub buffer was provided");
    }

    let mut body = force_detached_stub_nt();
    body.extend_from_slice(&prologue);
    body.extend_from_slice(&jump_absolute(entry + PROLOGUE_LEN as u64));
    proc.write_bytes(stub, &body)
        .with_context(|| format!("writing the RtlCreateUserProcess stub at {stub:#x}"))?;
    make_writable(proc, entry, PROLOGUE_LEN)?;
    proc.write_bytes(entry, &jump_absolute(stub))
        .with_context(|| format!("patching RtlCreateUserProcess at {entry:#x}"))?;

    Ok(ForcedStub { entry, stub })
}

/// Bytes [`install_rtl_creation_hook`] writes.
pub fn rtl_forced_stub_size() -> usize {
    force_detached_stub_nt().len() + PROLOGUE_LEN * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The jump really jumps, and lands on the address it was told to.
    ///
    /// Byte comparison is not enough (AGENTS pitfall 3): three separate encoding
    /// bugs in this repository's stubs looked correct as bytes and were wrong as
    /// instructions. So this allocates an RWX page, writes a target address into
    /// it, jumps to the encoded sequence, and checks control arrived.
    #[test]
    fn the_absolute_jump_actually_jumps() {
        use crate::child::{Child, ChildSpec};
        use crate::manual_map::remote::RemoteProcess;

        let child = Child::spawn(&ChildSpec::new("cmd.exe").args(["/c", "exit", "0"])).unwrap();
        let proc = RemoteProcess::new(child.process_handle());

        // A function in the target that returns a known value, used as the jump
        // destination so the test can observe that it ran.
        let scratch = proc.allocate(0x1000).unwrap();
        // `mov eax, 0x2A; ret` at `scratch + 0x20`.
        let landing = scratch + 0x20;
        proc.write_bytes(
            landing,
            &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3], // mov eax, 42; ret
        )
        .unwrap();

        // A remote thread whose start routine is our jump would run it and then
        // have nowhere to return, so instead the jump is placed at a scratch
        // address and reached by a thread that first calls through it.
        let jump_site = proc.allocate(0x1000).unwrap();
        proc.write_bytes(jump_site, &jump_absolute(landing))
            .unwrap();
        proc.write_bytes(
            jump_site + 0x10,
            &[
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, // mov rax, jump_site
                0xFF, 0xD0, // call rax
                0x31, 0xC0, // xor eax, eax
                0xC3, // ret
            ],
        )
        .unwrap();

        // Run `mov rax, jump_site; call rax` in a thread. The called sequence jumps
        // to `landing`, which returns 42 into the caller; zeroing eax afterwards
        // would hide it, so the thread's exit code is what the landing code
        // returned and the assertion below depends on it surviving.
        let trampoline = proc.allocate(0x1000).unwrap();
        let mut runner = vec![0x48u8, 0xB8];
        runner.extend_from_slice(&jump_site.to_le_bytes());
        runner.extend_from_slice(&[0xFF, 0xD0]); // call rax
        runner.extend_from_slice(&[0xC3]); // ret
        proc.write_bytes(trampoline, &runner).unwrap();

        let code = proc.run_thread(trampoline).unwrap();
        assert_eq!(
            code, 0x2A,
            "the jump did not reach the landing code (exit {code:#x})"
        );

        let _ = child.terminate();
    }

    /// A prologue of plain pushes can be relocated.
    ///
    /// These are the bytes `CreateProcessInternalW` starts with on this machine,
    /// taken from a live disassembly of it.
    #[test]
    fn a_prologue_of_pushes_is_relocatable() {
        let prologue = [
            0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
        ];
        assert!(is_relocatable(&prologue));
    }

    /// A RIP-relative load must be refused: copying it elsewhere would make it
    /// read from the wrong address.
    #[test]
    fn a_rip_relative_operand_is_refused() {
        // `48 8B 05 disp32` - `mov rax, [rip + disp32]`.
        let instruction = [0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_relocatable(&instruction));
    }

    /// A relative call must be refused for the same reason.
    #[test]
    fn a_relative_call_is_refused() {
        // `E8 disp32` - `call rel32`.
        let instruction = [0xE8, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_relocatable(&instruction));
    }

    /// Bytes that are not a complete instruction must be refused rather than
    /// half-decoded.
    #[test]
    fn a_truncated_prologue_is_refused() {
        // A one-byte prefix with nothing after it.
        assert!(!is_relocatable(&[0x48]));
    }

    /// The emitted trampoline is the relocated prologue followed by a jump back.
    #[test]
    fn the_trampoline_relocates_then_resumes() {
        let prologue = [
            0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
        ];
        let resume = 0x7FFF_0000_1234u64;
        let built = build_trampoline(&prologue, resume);
        assert_eq!(&built[..prologue.len()], &prologue[..]);
        assert_eq!(&built[prologue.len()..], &jump_absolute(resume));
    }
    /// The forced-flag stub is the two instructions it claims to be.
    ///
    /// Decoded rather than compared against a byte string, because a byte
    /// comparison cannot tell `81 8C 24` from `81 A4 24` - and that difference is
    /// the bug this module hit while being written: `0x8C` is `/1` = OR, `0xA4` is
    /// `/4` = AND, so the wrong one *sets* `CREATE_NEW_CONSOLE`, the very flag
    /// the second instruction exists to clear. Decoding says "AND" or it does not.
    #[test]
    fn the_forced_stub_decodes_to_forcing_detached_and_clearing_new_console() {
        use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};

        let code = force_detached_stub(CREATE_PROCESS_W_FLAGS_OFFSET);
        let mut decoder = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);
        let mut seen: Vec<Mnemonic> = Vec::new();

        // can_decode is true whenever *any* further decode would succeed, including
        // one that runs off the end - which is why it must not be the loop
        // condition here. The trailing position() == len assertion below is what
        // proves the whole buffer was covered rather than a prefix of it.
        while decoder.position() < code.len() {
            let i = decoder.decode();
            assert_ne!(
                i.code(),
                Code::INVALID,
                "the stub does not decode at {:#x}",
                i.ip()
            );
            // Both must address `[rsp + offset]` as a 32-bit value. A byte or
            // word operand would write part of a different thing and still look
            // right as bytes.
            assert_eq!(i.op_kind(0), OpKind::Memory, "{:?}", i.mnemonic());
            assert_eq!(i.memory_base(), Register::RSP, "{:?}", i.mnemonic());
            assert_eq!(
                i.memory_displacement64(),
                CREATE_PROCESS_W_FLAGS_OFFSET as u64,
                "{:?} addresses the wrong stack slot",
                i.mnemonic()
            );
            assert_eq!(
                i.memory_size(),
                iced_x86::MemorySize::UInt32,
                "{:?} is not 32-bit",
                i.mnemonic()
            );
            seen.push(i.mnemonic());
        }

        assert_eq!(
            seen,
            vec![Mnemonic::Or, Mnemonic::And],
            "the stub should set DETACHED_PROCESS and clear CREATE_NEW_CONSOLE"
        );
        assert_eq!(
            code.len(),
            decoder.position(),
            "the stub has bytes that are not instructions"
        );
    }

    /// The flags offset is the sixth parameter, by the calling convention.
    ///
    /// Derived rather than measured, and the derivation is the whole of it: under
    /// the Microsoft x64 convention a callee finds the return address at `[rsp]`,
    /// the four register parameters shadowed at `[rsp+0x08 .. rsp+0x28]`, and the
    /// first stack parameter at `[rsp+0x28]`. `dwCreationFlags` is the sixth
    /// parameter of `CreateProcessW` - after `lpApplicationName`,
    /// `lpCommandLine`, `lpProcessAttributes`, `lpThreadAttributes` and
    /// `bInheritHandles` - so it is the second stack slot: `0x28 + 8`.
    ///
    /// An earlier version of this test tried to confirm it by measuring where a
    /// six-parameter Rust function puts its last argument, and it reported
    /// `rsp + 0x50`. That was the test being wrong rather than the constant: the
    /// two functions it compared were called from different places, so the
    /// difference contained both their prologues and the caller's frame. Measuring
    /// a stack offset from Rust means measuring its prologue too, and there is no
    /// way to read the entry `rsp` from safe code.
    ///
    /// What *is* verified mechanically is the encoding - see
    /// `the_forced_stub_decodes_to_forcing_detached_and_clearing_new_console` -
    /// and the offset this constant supplies is checked there against the
    /// displacement the decoder reports.
    #[test]
    fn the_flags_offset_follows_the_calling_convention() {
        const RETURN_ADDRESS: u64 = 8;
        const SHADOW_FOR_FOUR_REGISTERS: u64 = 4 * 8;
        const FIRST_STACK_PARAMETER: u64 = RETURN_ADDRESS + SHADOW_FOR_FOUR_REGISTERS;
        /// `bInheritHandles` is the fifth parameter; the flags are the sixth.
        const PARAMETERS_BEFORE_THE_FLAGS: u64 = 5;

        let derived = FIRST_STACK_PARAMETER + (PARAMETERS_BEFORE_THE_FLAGS - 4) * 8;
        assert_eq!(
            derived, CREATE_PROCESS_W_FLAGS_OFFSET as u64,
            "the constant and the calling convention disagree about where \
             dwCreationFlags lives"
        );
    }
    /// The ntdll stub is the same pair, in 64 bits.
    ///
    /// `ProcessFlags` on `NtCreateUserProcess` is a `ULONG_PTR`, so both
    /// instructions need a REX.W prefix - and a prefix changes the encoding length,
    /// so this cannot be assumed to be the 32-bit stub with two extra bytes.
    #[test]
    fn the_nt_stub_decodes_as_a_64_bit_flag_forcer() {
        use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};

        let code = force_detached_stub_nt();
        let mut decoder = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);
        let mut seen: Vec<Mnemonic> = Vec::new();

        // can_decode is true whenever *any* further decode would succeed, including
        // one that runs off the end - which is why it must not be the loop
        // condition here. The trailing position() == len assertion below is what
        // proves the whole buffer was covered rather than a prefix of it.
        while decoder.position() < code.len() {
            let i = decoder.decode();
            assert_ne!(i.code(), Code::INVALID, "does not decode at {:#x}", i.ip());
            assert_eq!(i.op_kind(0), OpKind::Memory, "{:?}", i.mnemonic());
            assert_eq!(i.memory_base(), Register::RSP, "{:?}", i.mnemonic());
            assert_eq!(
                i.memory_displacement64(),
                NT_CREATE_USER_PROCESS_FLAGS_OFFSET as u64,
                "{:?} addresses the wrong stack slot",
                i.mnemonic()
            );
            // The whole point of the REX.W: a 32-bit operation would leave the top
            // half of the flags alone, so clearing CREATE_NEW_CONSOLE in the low
            // dword while the kernel reads a qword would not clear it at all.
            assert_eq!(
                i.memory_size(),
                iced_x86::MemorySize::UInt64,
                "{:?} is not 64-bit - it would only half-modify the flags",
                i.mnemonic()
            );
            seen.push(i.mnemonic());
        }
        assert_eq!(seen, vec![Mnemonic::Or, Mnemonic::And]);
        assert_eq!(code.len(), decoder.position(), "trailing bytes");
    }
    /// Scratch, kept because the answer is worth more than the code that finds it.
    ///
    /// Which of ntdll's process-creation entry points has a relocatable prologue?
    /// `NtCreateUserProcess` - the one everything funnels into - does not, which is
    /// what stopped the suspended-injection path. The others are listed so the
    /// question does not have to be answered again by hand.
    #[test]
    fn which_ntdll_entry_points_have_a_relocatable_prologue() {
        use crate::manual_map::pe::{PeImage, DIRECTORY_ENTRY_EXPORT};

        let path = std::path::Path::new("C:\\Windows\\System32\\ntdll.dll");
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("no ntdll to look at");
            return;
        };
        let Ok(pe) = PeImage::parse(&bytes) else {
            eprintln!("could not parse ntdll");
            return;
        };
        let Some(dir) = pe.info.directory(DIRECTORY_ENTRY_EXPORT) else {
            return;
        };
        let Ok(header) = pe.read_rva(dir.virtual_address, 0x28) else {
            return;
        };
        let at = |o: usize| u32::from_le_bytes(header[o..o + 4].try_into().unwrap());
        let number_of_names = at(0x18) as usize;
        let functions = pe.read_rva(at(0x1c), number_of_names * 4).unwrap();
        let names = pe.read_rva(at(0x20), number_of_names * 4).unwrap();
        let ordinals = pe.read_rva(at(0x24), number_of_names * 2).unwrap();

        let want = [
            "NtCreateUserProcess",
            "NtCreateProcess",
            "NtCreateProcessEx",
            "RtlCreateUserProcess",
        ];
        for i in 0..number_of_names {
            let name_rva = u32::from_le_bytes(names[i * 4..i * 4 + 4].try_into().unwrap());
            let ord = u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let Some(nb) = pe.read_rva(name_rva, 64).ok() else {
                continue;
            };
            let end = nb.iter().position(|&b| b == 0).unwrap_or(0);
            let name = String::from_utf8_lossy(&nb[..end]).into_owned();
            if !want.contains(&name.as_str()) {
                continue;
            }
            let rva = u32::from_le_bytes(functions[ord * 4..ord * 4 + 4].try_into().unwrap());
            if (dir.virtual_address..dir.virtual_address + dir.size).contains(&rva) {
                eprintln!("{name:24} forwarder");
                continue;
            }
            let Ok(window) = pe.read_rva(rva, 12) else {
                continue;
            };
            let hex: Vec<String> = window.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "{name:24} rva=0x{rva:08x} relocatable={} bytes=[{}]",
                is_relocatable(&window),
                hex.join(" ")
            );
        }
    }

    /// The offset is not a guess about bytes; it is a guess about a *signature*.
    ///
    /// So the signature is declared, and the stub is made to run against it. The
    /// Windows x64 ABI puts parameters five and beyond on the stack at `[rsp+0x28]`
    /// and up, one eight-byte slot each regardless of type - so declaring a Rust
    /// function with `bInheritHandles` fifth and `dwCreationFlags` sixth reproduces
    /// `CreateProcessInternalW`'s frame exactly, without hand-building one.
    ///
    /// Then the stub is placed in front of that function on an RWX page and called
    /// through a function pointer, and what the function receives is checked.
    /// Decoding the stub would only prove the encoder emitted what we asked for;
    /// running it proves the flags arrive with `DETACHED_PROCESS` set and
    /// `CREATE_NEW_CONSOLE` cleared, that an unrelated caller flag survives, and
    /// that the neighbouring `bInheritHandles` is left alone - an offset one slot
    /// too high writes into `lpEnvironment` and every one of those checks still
    /// looks fine.
    #[test]
    fn the_internal_stub_really_forces_the_flags_parameter() {
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

        /// The part of `CreateProcessInternalW` the stub depends on: the flags are
        /// the sixth parameter, between `bInheritHandles` and `lpEnvironment`.
        extern "C" fn victim(
            application_name: u64,
            command_line: u64,
            process_attributes: u64,
            thread_attributes: u64,
            inherit_handles: u64,
            flags: u64,
        ) -> u64 {
            // `inherit_handles` is the fifth parameter, one slot below the flags. If
            // the stub used the wrong offset it would land here, so the value is
            // reported rather than discarded.
            let _ = (
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
            );
            if inherit_handles == 0 {
                // Unreachable marker: bInheritHandles must survive as 1.
                u64::MAX
            } else {
                flags
            }
        }

        let mut body = force_flags_at(CREATE_PROCESS_INTERNAL_W_FLAGS_OFFSET, 4);
        body.extend_from_slice(&jump_absolute(victim as usize as u64));

        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };
        // SAFETY: a null address asks the system to choose the location.
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                body.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        assert!(!page.is_null(), "could not get an RWX page");
        // SAFETY: `page` is a live RWX reservation of `body.len()` bytes, and it is
        // released before this function returns.
        unsafe {
            std::ptr::copy_nonoverlapping(body.as_ptr(), page as *mut u8, body.len());
        }

        let stub: extern "C" fn(u64, u64, u64, u64, u64, u64) -> u64 =
            unsafe { std::mem::transmute(page) };

        let seen = stub(
            0x7FFEE31B3124,
            0x3CF58FF278,
            0x1111_1111,
            0x2222_2222,
            1, // bInheritHandles
            (CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT) as u64,
        );

        // SAFETY: `page` is the reservation made above and has not been freed.
        unsafe { VirtualFree(page, 0, MEM_RELEASE) };

        assert_ne!(
            seen,
            u64::MAX,
            "the stub wrote to the fifth parameter (bInheritHandles)"
        );
        assert_eq!(
            seen,
            (DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT) as u64,
            "the stub must leave the flags as DETACHED_PROCESS | \
             CREATE_UNICODE_ENVIRONMENT; the victim received {seen:#018x}"
        );
    }
}
