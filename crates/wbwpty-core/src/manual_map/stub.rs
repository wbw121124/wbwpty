//! The remote stub: a handful of x64 bytes that call the payload's entry point.
//!
//! Everything heavy (PE parsing, relocation, import resolution) happens in the
//! host, where it can be tested. By the time this runs, the image is already
//! fully self-contained: the host resolved every import against the target's own
//! `PEB->Ldr` and wrote the addresses straight into the mapped image's IAT.
//!
//! So the job is tiny - it only has to make a call that
//! `CreateRemoteThread` cannot express:
//!
//! ```text
//!   job := { base, entry_rva }
//! ```
//!
//! `CreateRemoteThread` starts a thread at an address with `(lpParameter,
//! dwCreationFlags)` in `rcx`/`rdx`, but `DllMain` takes
//! `(hinst, fdwReason, lpvReserved)`. Passing the entry point directly would
//! therefore hand `DllMain` a garbage reason, and it would quietly do nothing
//! while the stub still reported success. The stub sets the three arguments
//! explicitly.
//!
//! ```text
//!   48 B9 <imm64>        mov  rcx, JOB_PTR
//!   4C 8B 19             mov  r11, [rcx]           ; base
//!   48 8B 41 08          mov  rax, [rcx+0x08]      ; entry_rva
//!   4C 01 D8             add  rax, r11             ; base + entry
//!   4C 89 D9             mov  rcx, r11             ; hinst       (arg 1)
//!   BA 01 00 00 00       mov  edx, 1               ; reason      (arg 2)
//!   45 31 C0             xor  r8d, r8d             ; lpvReserved (arg 3)
//!   FF D0                call rax
//!   31 C0                xor  eax, eax            ; stub exit code 0
//!   C3                   ret
//! ```
//!
//! # Why there is no IAT-patch loop here
//!
//! An earlier version carried a loop that walked a patch table and stored into
//! the image's IAT. It was never executed, because the host resolves imports
//! before writing the image and passes an empty table. Disassembling it (rather
//! than only comparing bytes, as the tests then did) showed three independent
//! encoding bugs hiding in dead code: `49 89 D2` is a register-to-register
//! `mov r10, rdx` and not `mov [r10], rdx`, `49 FF C0` is `inc r8` and not
//! `dec r8`, and `mov r9d, 1` set the fourth argument register instead of
//! `rdx`. Keeping unreachable machine code that has never been executed is how
//! this happened, so it is gone.

/// Size of the emitted stub.
const STUB_LEN: usize = 0x24;

/// Offsets inside the job structure as seen by the stub.
const JOB_BASE: u64 = 0x00;
const JOB_ENTRY: u64 = 0x08;

/// Host-side mirror of the job structure written into the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub base: u64,
    pub entry_rva: u32,
}

pub fn job_size() -> usize {
    0x10
}

/// Serialises the job structure (little endian, matching the stub's reads).
pub fn build_job(base: u64, entry_rva: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(job_size());
    buf.extend_from_slice(&base.to_le_bytes());
    buf.extend_from_slice(&(entry_rva as u64).to_le_bytes());
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
    // mov rax, [rcx+0x08]
    code.extend_from_slice(&[0x48, 0x8b, 0x41, 0x08]);
    // add rax, r11
    code.extend_from_slice(&[0x4c, 0x01, 0xd8]);
    // mov rcx, r11 (hinst)
    code.extend_from_slice(&[0x4c, 0x89, 0xd9]);
    // mov edx, 1 (DLL_PROCESS_ATTACH). Win64 passes argument 2 in `rdx`;
    // writing `r9d` here compiles fine and silently breaks every caller.
    code.extend_from_slice(&[0xba, 0x01, 0x00, 0x00, 0x00]);
    // xor r8d, r8d (lpvReserved)
    code.extend_from_slice(&[0x45, 0x31, 0xc0]);
    // call rax
    code.extend_from_slice(&[0xff, 0xd0]);
    // xor eax, eax
    code.extend_from_slice(&[0x31, 0xc0]);
    // ret
    code.push(0xc3);

    debug_assert_eq!(code.len(), STUB_LEN, "stub size drifted from the listing");
    code
}

/// Convenience view used by the tests.
pub fn job_layout() -> (u64, u64) {
    (JOB_BASE, JOB_ENTRY)
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
            0x48, 0x8b, 0x41, 0x08, // mov rax, [rcx+8]
            0x4c, 0x01, 0xd8, // add rax, r11
            0x4c, 0x89, 0xd9, // mov rcx, r11
            0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
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
    fn job_serialisation_matches_stub_offsets() {
        let (base, entry) = job_layout();
        assert_eq!((base, entry), (0x00, 0x08));

        let job = build_job(0x7ff0_0000_0000, 0x1234);
        assert_eq!(job.len(), job_size());
        assert_eq!(u64::from_le_bytes(job[0..8].try_into().unwrap()), 0x7ff0_0000_0000);
        assert_eq!(u64::from_le_bytes(job[8..16].try_into().unwrap()), 0x1234);
    }

    /// The byte comparison above is necessary but not sufficient: a hand written
    /// REX byte or the wrong argument register decodes to something perfectly
    /// legal that silently does the wrong thing. This *runs* the stub and
    /// inspects the three arguments `DllMain` actually receives.
    ///
    /// Regression guard for the bug where the stub set `r9d` instead of `edx`,
    /// so `DllMain` saw a garbage `fdwReason`, returned immediately, and every
    /// caller still observed exit code 0.
    #[test]
    fn stub_calls_the_entry_with_dllmain_arguments() {
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        let page = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as u64;
        assert_ne!(page, 0, "VirtualAlloc must succeed for this test to mean anything");

        // Payload records the two interesting arguments:
        //   mov [rcx+0x400], rdx      ; 48 89 91 00 04 00 00
        //   mov [rcx+0x408], r8       ; 4C 89 81 08 04 00 00
        //   ret                       ; C3
        //
        // The destination must not overlap the code: the payload itself lives at
        // base+ENTRY_RVA, so recording "near" the code would overwrite the
        // *next* instruction before the CPU fetches it.
        const ENTRY_RVA: u32 = 0x200;
        let payload: [u8; 15] = [
            0x48, 0x89, 0x91, 0x00, 0x04, 0x00, 0x00, // mov [rcx+0x400], rdx
            0x4c, 0x89, 0x81, 0x08, 0x04, 0x00, 0x00, // mov [rcx+0x408], r8
            0xc3, // ret
        ];
        let job_addr = page + 0x100;

        unsafe {
            std::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                (page + ENTRY_RVA as u64) as *mut u8,
                payload.len(),
            );
            let job = build_job(page, ENTRY_RVA);
            std::ptr::copy_nonoverlapping(job.as_ptr(), job_addr as *mut u8, job.len());

            let code = build_stub(job_addr);
            let stub_at = page + 0x300;
            std::ptr::copy_nonoverlapping(code.as_ptr(), stub_at as *mut u8, code.len());

            let entry: extern "system" fn() -> u32 = std::mem::transmute(stub_at as usize);
            let rv = entry();
            assert_eq!(rv, 0, "stub must report success");

            // `off` is a byte offset; `add` on a `*const u64` would scale it by 8
            // and read straight past the allocation.
            let get = |off: usize| (page as *const u8).add(off).cast::<u64>().read_unaligned();
            assert_eq!(
                get(0x400),
                1,
                "fdwReason must be DLL_PROCESS_ATTACH (Win64 argument 2 is rdx, not r9)"
            );
            assert_eq!(get(0x408), 0, "lpvReserved must be NULL");
            VirtualFree(page as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }
}