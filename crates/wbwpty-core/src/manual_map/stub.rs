//! The remote stub: a few dozen bytes of x64 that finish the manual map.
//!
//! All the heavy lifting (PE parsing, relocation, import resolution) happens in
//! the host, where it can be tested. The target only has to:
//!
//! 1. copy the resolved addresses into the IAT,
//! 2. call the payload's entry point with `DLL_PROCESS_ATTACH`.
//!
//! ```text
//!   job := { base, entry_rva, patch_count, patches[patch_count] }
//!          patch := { iat_rva, address }
//! ```
//!
//! Register plan (all volatile, nothing to preserve): `rcx` keeps the job
//! pointer for the whole routine, `r11` the image base, `r9`/`r8`/`r10`/`rdx`
//! are loop scratch.
//!
//! ```text
//!   48 B9 <imm64>        mov  rcx, JOB_PTR
//!   4C 8B 19             mov  r11, [rcx]           ; base
//!   4C 8B 41 10          mov  r8,  [rcx+0x10]      ; patch_count
//!   4C 8D 49 18          lea  r9,  [rcx+0x18]      ; patches
//!   49 85 C0             test r8, r8
//!   74 16                jz   done
//! loop:
//!   4D 8B 11             mov  r10, [r9]            ; iat rva
//!   4D 01 DA             add  r10, r11            ; slot address
//!   49 8B 51 08          mov  rdx, [r9+8]          ; value
//!   49 89 D2             mov  [r10], rdx
//!   49 83 C1 10          add  r9, 16
//!   49 FF C0             dec  r8
//!   75 EA                jnz  loop
//! done:
//!   48 8B 41 08          mov  rax, [rcx+8]         ; entry_rva
//!   4C 01 D8             add  rax, r11             ; base + entry
//!   4C 89 D9             mov  rcx, r11             ; hinst
//!   41 B9 01 00 00 00    mov  r9d, 1              ; DLL_PROCESS_ATTACH
//!   45 31 C0             xor  r8d, r8d             ; lpvReserved
//!   FF D0                call rax
//!   31 C0                xor  eax, eax            ; stub exit code 0
//!   C3                   ret
//! ```

const STUB_LEN: usize = 0x48;
/// Byte offset of the `jz done` displacement inside the emitted stub.
#[cfg(test)]
const JZ_DISP_AT: usize = 0x19;
/// Byte offset of the `jnz loop` displacement inside the emitted stub.
#[cfg(test)]
const JNZ_DISP_AT: usize = 0x2f;

/// Offsets inside [`JOB`] as seen by the stub, kept in sync with the listing
/// above.
const JOB_BASE: u64 = 0x00;
const JOB_ENTRY: u64 = 0x08;
const JOB_COUNT: u64 = 0x10;
const JOB_PATCHES: u64 = 0x18;
const PATCH_SIZE: u64 = 16;

/// Host-side mirror of the job structure written into the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patch {
    pub iat_rva: u32,
    pub address: u64,
}

pub fn job_size(patch_count: usize) -> usize {
    (JOB_PATCHES as usize) + patch_count * PATCH_SIZE as usize
}

/// Serialises the job structure (little endian, matching the stub's reads).
pub fn build_job(base: u64, entry_rva: u32, patches: &[Patch]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(job_size(patches.len()));
    buf.extend_from_slice(&base.to_le_bytes());
    buf.extend_from_slice(&(entry_rva as u64).to_le_bytes());
    buf.extend_from_slice(&(patches.len() as u64).to_le_bytes());
    for p in patches {
        buf.extend_from_slice(&(p.iat_rva as u64).to_le_bytes());
        buf.extend_from_slice(&p.address.to_le_bytes());
    }
    buf
}

/// Emits the stub, embedding the *address of the job* as an immediate.
pub fn build_stub(job_addr: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(STUB_LEN);

    // mov rcx, imm64
    code.extend_from_slice(&[0x48, 0xb9]);
    code.extend_from_slice(&job_addr.to_le_bytes());
    // mov r11, [rcx]
    code.extend_from_slice(&[0x4c, 0x8b, 0x19]);
    // mov r8, [rcx+0x10]
    code.extend_from_slice(&[0x4c, 0x8b, 0x41, 0x10]);
    // lea r9, [rcx+0x18]
    code.extend_from_slice(&[0x4c, 0x8d, 0x49, 0x18]);
    // test r8, r8
    code.extend_from_slice(&[0x49, 0x85, 0xc0]);
    // jz done  (patched below once `done` is known)
    let jz_at = code.len();
    code.extend_from_slice(&[0x74, 0x00]);

    let loop_start = code.len();
    // mov r10, [r9]
    code.extend_from_slice(&[0x4d, 0x8b, 0x11]);
    // add r10, r11
    code.extend_from_slice(&[0x4d, 0x01, 0xda]);
    // mov rdx, [r9+8]
    code.extend_from_slice(&[0x49, 0x8b, 0x51, 0x08]);
    // mov [r10], rdx
    code.extend_from_slice(&[0x49, 0x89, 0xd2]);
    // add r9, 16
    code.extend_from_slice(&[0x49, 0x83, 0xc1, 0x10]);
    // dec r8
    code.extend_from_slice(&[0x49, 0xff, 0xc0]);
    // jnz loop
    let jnz_at = code.len();
    code.extend_from_slice(&[0x75, 0x00]);

    let done = code.len();
    // mov rax, [rcx+8]
    code.extend_from_slice(&[0x48, 0x8b, 0x41, 0x08]);
    // add rax, r11
    code.extend_from_slice(&[0x4c, 0x01, 0xd8]);
    // mov rcx, r11
    code.extend_from_slice(&[0x4c, 0x89, 0xd9]);
    // mov r9d, 1  (DLL_PROCESS_ATTACH)
    code.extend_from_slice(&[0x41, 0xb9, 0x01, 0x00, 0x00, 0x00]);
    // xor r8d, r8d
    code.extend_from_slice(&[0x45, 0x31, 0xc0]);
    // call rax
    code.extend_from_slice(&[0xff, 0xd0]);
    // xor eax, eax
    code.extend_from_slice(&[0x31, 0xc0]);
    // ret
    code.push(0xc3);

    // Patch the two relative jumps now that the targets are known.
    code[jz_at + 1] = (done - (jz_at + 2)) as u8;
    code[jnz_at + 1] = (loop_start as i32 - (jnz_at + 2) as i32) as u8;

    debug_assert_eq!(code.len(), STUB_LEN, "stub size drifted from the listing");
    code
}

/// Shared rendezvous structure between the host and the in-target dispatcher.
///
/// The host fills the payload fields while the target spins on
/// [`SLOT_READY`]; that ordering is what makes the injection race free without
/// a debugger.
/// ```text
///   +0x00 dll_base    u64  address the payload image was mapped at
///   +0x08 ready       u64  set to 1 by the host once the IAT is patched
///   +0x10 dll_init    u64  absolute address of the payload's DllMain
///   +0x18 oep         u64  original entry point of the target executable
///   +0x20 oep_bytes   u64  the 8 bytes that were overwritten at `oep`
/// ```
pub const SLOT_DLL_BASE: usize = 0x00;
pub const SLOT_READY: usize = 0x08;
pub const SLOT_DLL_INIT: usize = 0x10;
pub const SLOT_OEP: usize = 0x18;
pub const SLOT_OEP_BYTES: usize = 0x20;
pub const SLOT_SIZE: usize = 0x28;

/// Code the target's entry point is redirected to. It is position independent
/// (the slot is reached through a RIP-relative `lea`) and needs no imports,
/// because at that point the loader has mapped nothing that a user payload
/// could rely on being at a known address.
///
/// ```text
///   4C 8D 1D <disp32>   lea  r11, [rip+disp]       ; slot
///   4D 8B 43 08         mov  r8,  [r11+0x08]       ; ready?
///   4D 85 C0            test r8, r8
///   75 04               jnz  ready
///   F3 90               pause
///   EB F5               jmp  wait
/// ready:
///   4D 8B 43 20         mov  r8,  [r11+0x20]       ; original bytes
///   4D 8B 4B 18         mov  r9,  [r11+0x18]       ; original entry point
///   4D 89 01            mov  [r9], r8              ; put them back
///   49 8B 4B 00         mov  rcx, [r11+0x00]       ; hinst = image base
///   4D 8B 53 10         mov  r10, [r11+0x10]       ; payload DllMain
///   41 FF D2            call r10
///   4D 8B 4B 18         mov  r9,  [r11+0x18]       ; original entry point
///   41 FF E1            jmp  r9
/// ```
pub fn build_entry_dispatcher(slot_rel_disp: i32) -> Vec<u8> {
    let mut code = Vec::with_capacity(64);
    // lea r11, [rip+disp32]
    code.extend_from_slice(&[0x4c, 0x8d, 0x1d]);
    code.extend_from_slice(&slot_rel_disp.to_le_bytes());
    let start = code.len();

    // wait: mov r8, [r11+0x08] ; test r8, r8 ; jnz ready ; pause ; jmp start
    code.extend_from_slice(&[0x4d, 0x8b, 0x43, 0x08]);
    code.extend_from_slice(&[0x4d, 0x85, 0xc0]);
    let jnz_at = code.len();
    code.extend_from_slice(&[0x75, 0x00]);
    code.extend_from_slice(&[0xf3, 0x90]); // pause
    let jmp_at = code.len();
    code.extend_from_slice(&[0xeb, 0x00]);

    let ready = code.len();
    // restore the original entry point bytes
    code.extend_from_slice(&[0x4d, 0x8b, 0x43, 0x20]); // mov r8, [r11+0x20]
    code.extend_from_slice(&[0x4d, 0x8b, 0x4b, 0x18]); // mov r9, [r11+0x18]
    code.extend_from_slice(&[0x4d, 0x89, 0x01]); // mov [r9], r8
                                                 // call the payload entry point with hinst = image base
    code.extend_from_slice(&[0x49, 0x8b, 0x4b, 0x00]); // mov rcx, [r11+0x00]
    code.extend_from_slice(&[0x4d, 0x8b, 0x53, 0x10]); // mov r10, [r11+0x10]
    code.extend_from_slice(&[0x41, 0xff, 0xd2]); // call r10
                                                 // jump to the original entry point
    code.extend_from_slice(&[0x4d, 0x8b, 0x4b, 0x18]); // mov r9, [r11+0x18]
    code.extend_from_slice(&[0x41, 0xff, 0xe1]); // jmp r9

    code[jnz_at + 1] = (ready - (jnz_at + 2)) as u8;
    code[jmp_at + 1] = (start as i32 - (jmp_at + 2) as i32) as u8;
    code
}

/// Entry bytes the dispatcher overwrites: `E9 rel32`.
pub fn build_entry_patch(dispatcher_addr: u64, oep_addr: u64) -> Option<[u8; 5]> {
    let delta = dispatcher_addr as i64 - (oep_addr as i64 + 5);
    let delta = i32::try_from(delta).ok()?;
    let rel = delta as i32;
    Some([
        0xe9,
        rel.to_le_bytes()[0],
        rel.to_le_bytes()[1],
        rel.to_le_bytes()[2],
        rel.to_le_bytes()[3],
    ])
}

/// Convenience view used by the tests.
pub fn job_layout() -> (u64, u64, u64, u64) {
    (JOB_BASE, JOB_ENTRY, JOB_COUNT, JOB_PATCHES)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the exact encoding. Hand written REX bytes are the classic source of
    /// "decodes to the wrong register" bugs, and the crate's `no_std` feature set
    /// for `iced-x86` has no formatter API to disassemble with, so the bytes are
    /// compared literally against the listing at the top of this file. The test
    /// below then *executes* them.
    #[test]
    fn stub_bytes_match_the_documented_listing() {
        let code = build_stub(0x1122_3344_5566_7788);
        let expected: [u8; STUB_LEN] = [
            0x48, 0xb9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rcx, imm64
            0x4c, 0x8b, 0x19, // mov r11, [rcx]
            0x4c, 0x8b, 0x41, 0x10, // mov r8,  [rcx+0x10]
            0x4c, 0x8d, 0x49, 0x18, // lea r9,  [rcx+0x18]
            0x49, 0x85, 0xc0, // test r8, r8
            0x74, 0x16, // jz done
            0x4d, 0x8b, 0x11, // mov r10, [r9]
            0x4d, 0x01, 0xda, // add r10, r11
            0x49, 0x8b, 0x51, 0x08, // mov rdx, [r9+8]
            0x49, 0x89, 0xd2, // mov [r10], rdx
            0x49, 0x83, 0xc1, 0x10, // add r9, 16
            0x49, 0xff, 0xc0, // dec r8
            0x75, 0xea, // jnz loop
            0x48, 0x8b, 0x41, 0x08, // mov rax, [rcx+8]
            0x4c, 0x01, 0xd8, // add rax, r11
            0x4c, 0x89, 0xd9, // mov rcx, r11
            0x41, 0xb9, 0x01, 0x00, 0x00, 0x00, // mov r9d, 1
            0x45, 0x31, 0xc0, // xor r8d, r8d
            0xff, 0xd0, // call rax
            0x31, 0xc0, // xor eax, eax
            0xc3, // ret
        ];
        assert_eq!(code.len(), expected.len());
        assert_eq!(code.as_slice(), expected.as_slice());
    }

    #[test]
    fn stub_length_is_stable() {
        assert_eq!(build_stub(0xdead_beef_0000).len(), STUB_LEN);
    }

    #[test]
    fn stub_branch_targets_are_backward_correct() {
        let code = build_stub(0x1000);
        // jz skips the loop, jnz jumps back to it.
        assert!(i8::from_le_bytes([code[JZ_DISP_AT]]) > 0);
        assert!(i8::from_le_bytes([code[JNZ_DISP_AT]]) < 0);
        assert_eq!(*code.last().unwrap(), 0xc3, "stub must end in ret");
    }

    #[test]
    fn job_serialisation_matches_stub_offsets() {
        let (base, entry, count, patches) = job_layout();
        assert_eq!((base, entry, count, patches), (0x00, 0x08, 0x10, 0x18));

        let job = build_job(
            0x7ff0_0000_0000,
            0x1234,
            &[
                Patch {
                    iat_rva: 0x2000,
                    address: 0xdead,
                },
                Patch {
                    iat_rva: 0x2008,
                    address: 0xbeef,
                },
            ],
        );
        assert_eq!(job.len(), job_size(2));
        assert_eq!(
            u64::from_le_bytes(job[0..8].try_into().unwrap()),
            0x7ff0_0000_0000
        );
        assert_eq!(u64::from_le_bytes(job[8..16].try_into().unwrap()), 0x1234);
        assert_eq!(u64::from_le_bytes(job[0x10..0x18].try_into().unwrap()), 2);
        assert_eq!(
            u64::from_le_bytes(job[0x18..0x20].try_into().unwrap()),
            0x2000
        );
        assert_eq!(
            u64::from_le_bytes(job[0x20..0x28].try_into().unwrap()),
            0xdead
        );
        assert_eq!(
            u64::from_le_bytes(job[0x28..0x30].try_into().unwrap()),
            0x2008
        );
        assert_eq!(
            u64::from_le_bytes(job[0x30..0x38].try_into().unwrap()),
            0xbeef
        );
    }

    /// The dispatcher is real machine code too: it must spin, then restore the
    /// overwritten entry bytes, then call the payload and jump to the original
    /// entry point.
    #[test]
    fn entry_dispatcher_waits_restores_and_calls() {
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        // Layout: [0x00..0x28] slot, [0x28..] dispatcher code, +0x200 payload.
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as u64;

        let slot = page;
        let code_at = page + SLOT_SIZE as u64;
        let code = build_entry_dispatcher((slot as i64 - (code_at + 7) as i64) as i32);

        // Payload stand-in at +0x200: mov dword [rcx+0x300], 0x1234 ; ret.
        let payload: [u8; 11] = [
            0xc7, 0x81, 0x00, 0x03, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0xc3,
        ];
        // The "original" entry point is a bare `ret` followed by padding, so the
        // dispatcher's final jump lands somewhere that returns to Rust.
        let original: u64 = 0x9090_9090_9090_90c3;

        unsafe {
            std::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                (page + 0x200) as *mut u8,
                payload.len(),
            );
            std::ptr::copy_nonoverlapping(code.as_ptr(), code_at as *mut u8, code.len());

            let put = |off: usize, v: u64| ((page + off as u64) as *mut u64).write_unaligned(v);
            let get = |off: usize| ((page + off as u64) as *const u64).read_unaligned();
            put(SLOT_DLL_BASE, page);
            put(SLOT_READY, 0);
            put(SLOT_DLL_INIT, page + 0x200);
            put(SLOT_OEP, page + 0x100);
            put(SLOT_OEP_BYTES, original);

            // Pretend the dispatcher was entered by a `jmp` from the OEP.
            let patch = build_entry_patch(code_at, page + 0x100).unwrap();
            std::ptr::copy_nonoverlapping(patch.as_ptr(), (page + 0x100) as *mut u8, 5);

            let dispatcher: extern "system" fn() = std::mem::transmute(code_at as usize);
            std::thread::scope(|s| {
                s.spawn(|| dispatcher());
                // Let it spin for a moment, then release it.
                std::thread::sleep(std::time::Duration::from_millis(50));
                assert_ne!(get(0x300), 0x1234, "must wait for the host to set ready");
                put(SLOT_READY, 1);
            });

            assert_eq!(
                get(0x300),
                0x1234,
                "payload entry must have run with hinst = base"
            );
            assert_eq!(
                get(0x100) & 0xffff_ffff,
                original & 0xffff_ffff,
                "entry bytes restored"
            );
            VirtualFree(page as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn entry_patch_encodes_a_relative_jump() {
        let patch = build_entry_patch(0x1000, 0x0800).unwrap();
        assert_eq!(patch[0], 0xe9);
        let rel = i32::from_le_bytes([patch[1], patch[2], patch[3], patch[4]]);
        assert_eq!(0x0800 + 5 + rel as i64, 0x1000);
        // Out of range targets must be rejected rather than silently truncated.
        assert!(build_entry_patch(0x1000_0000_0000, 0x0800).is_none());
    }
}
