//! UCRT standard stream repair.
//!
//! # The problem
//!
//! A CRT that block buffers a pipe holds output until its buffer fills. Measured
//! on this machine with `tests/crt_buffering.rs`: a program that writes one
//! newline-terminated line to a pipe does not deliver it until the process
//! exits, ~700 ms later. To a user at a terminal that is indistinguishable from
//! a hung program.
//!
//! # Why not `_IOLBF`
//!
//! The obvious fix is line buffering, and it does not work here. Sweeping every
//! candidate mode against ucrtbase on this machine gives:
//!
//! | value | what ucrtbase does with it |
//! | --- | --- |
//! | `0` | `_IOFBF`, block buffered - payload arrives at exit |
//! | `1`, `2`, `3`, `8`, `32`, `128` | not a mode: runs the invalid parameter handler and **aborts the process** |
//! | **`4`** | **`_IONBF`: payload arrives immediately** |
//! | `64` | `_IOLBF`, but behaves exactly like `_IOFBF` on a pipe |
//!
//! So the three valid modes are `0`, `4`, `0x40`, and **`_IOLBF` does not flush
//! on a newline for a stream that is not a console** - which is every stream
//! this project cares about. `_IONBF` is the one that works: it costs a syscall
//! per write, which is what a terminal wants anyway.
//!
//! Those three values are UCRT's, not mingw's (`_IOFBF 0`, `_IOLBF 1`,
//! `_IONBF 2` there), so they are measured rather than looked up. Do not "fix"
//! them back to the header values.
//!
//! # What is used
//!
//! Only publicly exported entry points. On Windows 10 19045 `ucrtbase.dll` does
//! **not** export `__acrt_lowio_set_osfhandle` nor `_setvbuf` (verified with
//! `objdump -p`), so there is no private-structure surgery available even if it
//! were wanted. `_open_osfhandle` and `_dup2` are exported but are not needed
//! here: the standard descriptors are already the session pipes, because the
//! host handed them over through `STARTF_USESTDHANDLES` before the target ever
//! ran.

use core::ffi::{c_char, c_int, c_void};

use crate::ffi;

/// `_IONBF`, measured above.
const MODE_UNBUFFERED: c_int = 4;

/// `__acrt_iob_func` indices. These are the same values as `STD_OUTPUT_HANDLE`
/// and friends; ucrtbase's `_iob` array is indexed 0..2 for stdin/out/err.
const IDX_STDOUT: u32 = 1;
const IDX_STDERR: u32 = 2;

/// Passed to `setvbuf` when the caller asks it to allocate its own buffer.
/// The size is ignored for `_IONBF`, but a non-zero value is what the signature
/// wants.
const BUFFER_SIZE: usize = 4096;

type IobFunc = unsafe extern "system" fn(u32) -> *mut c_void;
type Setvbuf = unsafe extern "system" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int;

/// What the repair actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrtOutcome {
    /// `ucrtbase` was found and both of its exports resolved.
    pub ucrt_resolved: bool,
    /// How many streams `setvbuf` accepted.
    pub streams_set: u32,
    /// How many it rejected (returns non-zero).
    pub streams_refused: u32,
}

impl CrtOutcome {
    /// True when at least one stream now writes straight through.
    pub fn is_effective(self) -> bool {
        self.ucrt_resolved && self.streams_set > 0
    }
}

/// Puts the target's stdout and stderr into unbuffered mode.
///
/// Failure is always degradation, never damage: a target with no `ucrtbase` (a
/// pure kernel32 program, or one on msvcrt) simply keeps whatever buffering it
/// had, and the return value says so.
pub fn repair() -> CrtOutcome {
    let mut outcome = CrtOutcome {
        ucrt_resolved: false,
        streams_set: 0,
        streams_refused: 0,
    };

    // SAFETY: the name is a NUL terminated wide literal with static lifetime.
    let ucrt = unsafe { ffi::GetModuleHandleW(ucrt_name().as_ptr()) };
    if ucrt.is_null() {
        return outcome;
    }
    // SAFETY: a live module handle; the names are NUL terminated literals.
    let (iob, setvbuf) = unsafe {
        (
            ffi::GetProcAddress(ucrt, b"__acrt_iob_func\0".as_ptr()),
            ffi::GetProcAddress(ucrt, b"setvbuf\0".as_ptr()),
        )
    };
    let (Some(iob), Some(setvbuf)) = (iob, setvbuf) else {
        return outcome;
    };
    // `GetProcAddress` hands back a generic function pointer; the two callees
    // below are the documented signatures for these names.
    let iob: IobFunc = unsafe { core::mem::transmute(iob) };
    let setvbuf: Setvbuf = unsafe { core::mem::transmute(setvbuf) };
    outcome.ucrt_resolved = true;

    for index in [IDX_STDOUT, IDX_STDERR] {
        // SAFETY: `iob` is ucrtbase's own accessor and the index is one of the
        // three standard streams.
        let stream = unsafe { iob(index) };
        if stream.is_null() {
            continue;
        }
        // SAFETY: a live `FILE *` from ucrtbase. A null buffer asks ucrtbase to
        // allocate one from its own heap, which is initialised by now.
        let rc = unsafe { setvbuf(stream, core::ptr::null_mut(), MODE_UNBUFFERED, BUFFER_SIZE) };
        if rc == 0 {
            outcome.streams_set += 1;
        } else {
            outcome.streams_refused += 1;
        }
    }
    outcome
}

/// `L"ucrtbase.dll"` without needing an allocator or a `static` of a type the
/// manual mapper would have to place correctly.
fn ucrt_name() -> [u16; 13] {
    let mut out = [0u16; 13];
    let mut i = 0;
    while i < b"ucrtbase.dll\0".len() && i < out.len() - 1 {
        out[i] = b"ucrtbase.dll\0"[i] as u16;
        i += 1;
    }
    out
}