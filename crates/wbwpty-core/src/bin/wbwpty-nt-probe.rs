//! Prints the stack frame `cmd.exe` presents to `ntdll!NtCreateUserProcess`.
//!
//! # Why this exists
//!
//! The offset of `ProcessFlags` on that call is recorded in two places that
//! disagree: one says `[rsp+0x28]` as a 64-bit value, the other says the fifth
//! parameter is `ProcessInheritHandles` and the sixth - `[rsp+0x30]` - is the
//! flags, 32 bits wide. Guessing wrong writes over `ProcessInheritHandles` and
//! makes the target's process creation fail outright, so the offset is measured
//! rather than assumed.
//!
//! # How, without allocating a console
//!
//! The target is created `DETACHED_PROCESS | CREATE_SUSPENDED`, exactly as the
//! rest of the project does, so there is no window in which a console host can
//! appear. A capture stub is written at the entry of `NtCreateUserProcess` while
//! it cannot run, the target is resumed, and the stub copies the parameter slots
//! somewhere the host can read them back.
//!
//! # Two things this got wrong first
//!
//! `rep movsb` counts `rcx` down to zero, and `rcx` is the first argument here,
//! so a stub that copies with it without restoring the register hands
//! `NtCreateUserProcess` a null `ProcessHandle` and the target dies.
//!
//! A five-byte `E9 rel32` jump cannot reach a `VirtualAllocEx` page from `ntdll` -
//! they are about a terabyte apart, the displacement is silently truncated by
//! `as i32`, and the jump lands in the middle of nothing. The twelve-byte absolute
//! jump is not a preference, it is the only one of the two that can express the
//! distance.

use anyhow::{Context, Result};
use wbwpty_core::child::{Child, ChildSpec};
use wbwpty_core::manual_map::inline::jump_absolute;
use wbwpty_core::manual_map::remote::RemoteProcess;

/// Where the copied window starts, from `rsp`. The return address is at +0x00,
/// the four shadow slots at +0x08..+0x28, so the fifth parameter is at +0x28.
///
/// The window stops after the sixth. Reading further runs off the end of the
/// caller's frame and into its guard page: the first version copied from +0x20 to
/// +0x60 and the target died with `0xC0000005`, which looks exactly like a bad
/// patch and is not one.
const CAPTURE_FROM: u64 = 0x28;
const CAPTURE_LEN: u64 = 0x18;

/// `NtCreateUserProcess` is a syscall stub:
///
///     4c 8b d1                    mov r10, rcx
///     b8 cf 00 00 00              mov eax, 0xcf
///     f6 04 25 08 03 fe 7f 01     test byte ptr [0x7FFE0308], al
///     75 03                       jne  +3
///     0f 05                       syscall
///
/// Sixteen bytes, all of it position-independent - `0x7FFE0308` is
/// `KUSER_SHARED_DATA + 0x308` and is absolute. The old refusal of this function
/// came from asking whether twelve of those bytes were relocatable, which cuts the
/// eight-byte `test` in half and reports `INVALID` at +8.
const PROLOGUE_LEN: usize = 16;

/// The twelve-byte patch.
const PATCH_LEN: usize = 12;

/// Copies `[rsp+0x28]` and `[rsp+0x30]` into `sink` and returns to `restore`.
///
/// `rax` is the only register touched, and touching it is free: the relocated
/// prologue begins `mov eax, 0xcf`, which overwrites whatever is left there. So
/// there is nothing to save and nothing to pop.
///
/// The obvious alternative - `push rcx/rdi/rsi/rdx` around a `rep movsb` - killed
/// the target with `0xC0000005` even with the window narrowed to the two slots
/// actually wanted, and it was the difference between that and this version that
/// made the copy the only suspect. `rep movsb` counts `rcx` to zero and `rcx` is
/// the first argument here, so even a correct save-and-restore is one mistake away
/// from handing `NtCreateUserProcess` a null `ProcessHandle`.
fn capture_stub(sink: u64, code: u64, prologue: &[u8], restore: u64) -> Vec<u8> {
    let mut out = Vec::new();
    // mov rax, [rsp+0x28]      -> 48 8B 44 24 28
    // mov [rip+d], rax         -> 48 89 05 d
    // mov rax, [rsp+0x30]      -> 48 8B 44 24 30
    // mov [rip+d], rax         -> 48 89 05 d
    let first_load = 5usize;
    let first_store = first_load + 7; // 12: the second slot lands after this
    let second_load = first_store; // 12
    let second_store = second_load + 5; // 24

    out.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x28]);
    out.extend_from_slice(&[0x48, 0x89, 0x05]);
    // The displacement is measured from the end of *this* instruction, which is
    // code plus the offset just reached - not from the start of the stub.
    out.extend_from_slice(&((sink as i64 - (code as i64 + first_store as i64)) as i32).to_le_bytes());
    out.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x30]);
    out.extend_from_slice(&[0x48, 0x89, 0x05]);
    out.extend_from_slice(&((sink as i64 + 8 - (code as i64 + second_store as i64)) as i32).to_le_bytes());
    // `inc dword [rip+disp32]`. A separate tally, because "both slots are zero" is a
    // perfectly ordinary answer - a caller asking for no handle inheritance and no
    // flags at all - and watching for non-zero data cannot tell that from never
    // having run at all.
    let counter_at = second_store + 6;
    out.extend_from_slice(&[0xFF, 0x05]);
    out.extend_from_slice(&((sink as i64 + 16 - (code as i64 + counter_at as i64)) as i32).to_le_bytes());
    debug_assert_eq!(out.len(), counter_at);

    out.extend_from_slice(prologue); // the overwritten instructions, relocated
    out.extend_from_slice(&[0x49, 0xBB]); // mov r11, restore
    out.extend_from_slice(&restore.to_le_bytes());
    out.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11
    out
}

fn main() -> Result<()> {
    let host_ntdll = wbwpty_core::manual_map::remote::host_module_base("ntdll.dll");
    if host_ntdll == 0 {
        anyhow::bail!("ntdll is not mapped in the host");
    }
    let path = std::path::PathBuf::from(r"C:\Windows\System32\ntdll.dll");
    let module = wbwpty_core::manual_map::RemoteModule {
        base: host_ntdll,
        size: 0,
        full_name: path.display().to_string(),
        base_name: "ntdll.dll".to_string(),
    };
    let table = wbwpty_core::manual_map::exports::load_exports_from_file(&path, &module)
        .with_context(|| format!("reading {}", path.display()))?;
    let entry =
        wbwpty_core::manual_map::inline::find_export(host_ntdll, &table, "NtCreateUserProcess")
            .with_context(|| format!("resolving NtCreateUserProcess at {host_ntdll:#x}"))?;

    let child = Child::spawn(
        &ChildSpec::new("cmd.exe").args(["/c", "ping", "-n", "4", "127.0.0.1"]),
    )?;
    let pid = child.pid;
    let proc = RemoteProcess::new(child.process_handle());

    let magic = proc.read_bytes(host_ntdll, 2)?;
    if &magic != b"MZ" {
        anyhow::bail!("ntdll is not mapped at {host_ntdll:#x} in the target ({magic:?})");
    }

    let original = proc.read_bytes(entry, PROLOGUE_LEN)?;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
    println!("NtCreateUserProcess = {entry:#x}");
    println!("original prologue   : {}", hex(&original));

    let sink = proc.allocate(0x1000)?;
    let code = proc.allocate(0x1000)?;
    let restore = entry + PROLOGUE_LEN as u64;
    let body = capture_stub(sink, code, &original, restore);
    println!("stub body           : {}", hex(&body));
    println!("stub at             : {code:#x}");
    println!("restores at         : {restore:#x}");

    proc.write_bytes(code, &body)?;
    proc.write_bytes(sink, &[0u8; 32])?;
    proc.protect(entry, PATCH_LEN, 0x40)?; // PAGE_EXECUTE_READWRITE
    proc.write_bytes(entry, &jump_absolute(code))?;
    println!("patched; waiting for pid {pid}");

    child.resume()?;

    // Follow the counter: one call may legitimately pass zeros for both slots, so
    // the interesting call is whichever one has a non-zero fifth parameter. That
    // is also the discriminator - `CreateProcessInternalW`'s own frame shows
    // `bInheritHandles = 1` for the child that becomes ping, and the value has to
    // survive the trip down into ntdll.
    let mut seen: Vec<(u32, u64, u64, u64)> = Vec::new();
    let mut last_counter = 0u32;
    for _ in 0..600 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        let Ok(bytes) = proc.read_bytes(sink, 32) else { continue };
        let counter = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        if counter != last_counter {
            last_counter = counter;
            let a = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let b = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
            let c = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
            seen.push((counter, a, b, c));
        }
        if let Some((_, a, b, c)) = seen.iter().find(|(_, a, _, _)| *a != 0) {
            println!("\ncall #{counter} has a non-zero fifth parameter - this is the one:");
            println!("  [rsp+0x28] = {a:#018x}");
            println!("  [rsp+0x30] = {b:#018x}");
            println!("  [rsp+0x38] = {c:#018x}");
            println!("\nall calls observed:");
            for (n, a, b, c) in &seen {
                println!("  #{n}: 0x28={a:#018x} 0x30={b:#018x} 0x38={c:#018x}");
            }
            return Ok(());
        }
        if !child.is_running() {
            break;
        }
    }
    println!("no call with a non-zero fifth parameter; {} call(s) seen:", seen.len());
    for (n, a, b, c) in &seen {
        println!("  #{n}: 0x28={a:#018x} 0x30={b:#018x} 0x38={c:#018x}");
    }
    return Ok(());
}
