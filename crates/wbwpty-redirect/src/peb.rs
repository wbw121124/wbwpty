//! PEB / `RTL_USER_PROCESS_PARAMETERS` access.
//!
//! # Why this exists
//!
//! `conhost.exe` is only spawned when a process is *given a console*. The host
//! avoids that for its direct child by creating it `DETACHED_PROCESS`. But when
//! the child later calls `CreateProcess`, the base API decides whether to give
//! the *grandchild* a console by looking at the parent's state:
//!
//! * `PEB->ProcessParameters->ConsoleHandle == NULL` -> "the parent has no
//!   console" -> allocate one -> **a new `conhost.exe` appears**
//! * non-NULL -> "the parent has a console" -> the child inherits the parent's
//!   standard handles -> **no console host**
//!
//! Since our target's standard handles are already the session pipes, a truthy
//! `ConsoleHandle` makes the whole process tree inherit those pipes instead of
//! allocating consoles. This is the same trick winpty relies on, minus the
//! pseudo console.
//!
//! # Safety of a fake handle
//!
//! The value written is never dereferenced by the loader - it is only tested for
//! null. If the target passes it to a console API, that API resolves it against
//! the handle table and simply fails with `ERROR_INVALID_HANDLE`. A sentinel
//! that is obviously not a real handle is therefore safer than reusing a real
//! one: a real handle could alias something we do not own.

use core::ffi::c_void;
use core::mem::offset_of;
use core::ptr;

use crate::dlog;
use crate::ffi::{DWORD, HANDLE};

/// Sentinel written into `ConsoleHandle`. Deliberately an implausible handle
/// value so that any accidental use fails loudly instead of aliasing real state.
pub const CONSOLE_HANDLE_SENTINEL: usize = 0x123;

/// `PEB + 0x20` is `ProcessParameters`. The first four PEB fields are single
/// bytes (`InheritedAddressSpace`, `ReadImageFileExecOptions`, `BeingDebugged`,
/// `BitField`), so the first pointer slot sits at 0x08, `ImageBaseAddress` at
/// 0x10, `Ldr` at 0x18 and `ProcessParameters` at 0x20.
/// Source: `PEB` in Windows Internals / ReactOS `peb.h`.
const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20;

/// `RTL_USER_PROCESS_PARAMETERS`:
/// `MaximumLength@0x00 Length@0x04 Flags@0x08 DebugFlags@0x0C
///  ConsoleHandle@0x10 ConsoleFlags@0x18 StandardInput@0x20 ...`
/// Source: ReactOS `ntpsapi.h` (`RTL_USER_PROCESS_PARAMETERS`); x64 pointers
/// are 8 bytes and the four leading `ULONG`s occupy 16 bytes.
const PROCESS_PARAMETERS_CONSOLE_HANDLE_OFFSET: usize = 0x10;

/// Compile-time proof of the layout assumption above. `offset_of!` on the local
/// mirror below must agree with the constant, so a struct edit that drifts from
/// the documented offsets fails the build instead of corrupting a live PEB.
#[repr(C)]
struct ProcessParametersMirror {
    maximum_length: DWORD,
    length: DWORD,
    flags: DWORD,
    debug_flags: DWORD,
    console_handle: usize,
    console_flags: usize,
}

const _: () = assert!(
    offset_of!(ProcessParametersMirror, console_handle) == PROCESS_PARAMETERS_CONSOLE_HANDLE_OFFSET
);
const _: () = assert!(offset_of!(ProcessParametersMirror, console_flags) == 0x18);

/// The current process's PEB.
///
/// `NtCurrentTeb()->ProcessEnvironmentBlock` is what every debugger and
/// introspection tool reads; the compiler exposes it through the `gs` segment
/// register at offset `0x60` on x64 (`KPCR.GsBase` -> `TEB.ProcessEnvironmentBlock`).
/// One instruction, no imports, no dependency on ntdll being resolvable.
#[cfg(target_arch = "x86_64")]
fn current_peb() -> *mut c_void {
    let peb: usize;
    // SAFETY: `gs:[0x60]` is the x64 TEB pointer to the PEB; it is readable from
    // user mode at all times. The value is a valid pointer by contract.
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
    }
    peb as *mut c_void
}

#[cfg(not(target_arch = "x86_64"))]
fn current_peb() -> *mut c_void {
    ptr::null_mut()
}

/// Outcome of the console-state patch, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOutcome {
    /// The sentinel is in place.
    Patched,
    /// It was already non-null (something else got there first).
    AlreadySet,
    /// The PEB or its process parameters could not be read; nothing was changed.
    Skipped,
}

/// Fakes "this process has a console" so descendants inherit our handles
/// instead of being allocated one.
///
/// Never fails loudly and never panics: a target that cannot be patched still
/// runs, it just spawns a console host for its children.
pub fn patch_console_state() -> PatchOutcome {
    let peb = current_peb();
    if peb.is_null() {
        dlog!("peb: TEB lookup returned null");
        return PatchOutcome::Skipped;
    }

    // SAFETY: `peb` is this process' PEB, and ProcessParameters is a valid
    // pointer at this point in the process' lifetime (we are running inside it).
    let params = unsafe { ptr::read_volatile(peb.add(PEB_PROCESS_PARAMETERS_OFFSET).cast::<usize>()) };
    if params == 0 {
        dlog!("peb: ProcessParameters is null");
        return PatchOutcome::Skipped;
    }

    // SAFETY: `params` points at our own RTL_USER_PROCESS_PARAMETERS; the
    // ConsoleHandle slot is a plain pointer-sized field.
    let console_slot = unsafe { (params as *mut usize).add(PROCESS_PARAMETERS_CONSOLE_HANDLE_OFFSET) };
    let current = unsafe { ptr::read_volatile(console_slot) };
    if current != 0 {
        return PatchOutcome::AlreadySet;
    }

    // SAFETY: writing our own process parameters. The kernel only ever tests
    // this field for null, and this runs on our own remote thread.
    unsafe { ptr::write_volatile(console_slot, CONSOLE_HANDLE_SENTINEL) };

    // Verify the write actually landed; a mismatch means the offsets are wrong
    // for this build and the target must be left alone.
    let verify = unsafe { ptr::read_volatile(console_slot) };
    if verify != CONSOLE_HANDLE_SENTINEL {
        dlog!("peb: ConsoleHandle write did not stick ({verify:#x}); offsets look wrong");
        unsafe { ptr::write_volatile(console_slot, 0) };
        return PatchOutcome::Skipped;
    }

    dlog!("peb: ConsoleHandle sentinel installed");
    PatchOutcome::Patched
}

/// Restores the original `ConsoleHandle`, used when unloading cleanly.
pub fn restore_console_state(previous: usize) {
    let peb = current_peb();
    if peb.is_null() {
        return;
    }
    // SAFETY: see `patch_console_state`.
    unsafe {
        let params = ptr::read_volatile(peb.add(PEB_PROCESS_PARAMETERS_OFFSET).cast::<usize>());
        if params != 0 {
            let slot = (params as *mut usize).add(PROCESS_PARAMETERS_CONSOLE_HANDLE_OFFSET);
            ptr::write_volatile(slot, previous);
        }
    }
}

/// The value currently stored in `ConsoleHandle`, or `None` when unreadable.
pub fn console_handle() -> Option<usize> {
    let peb = current_peb();
    if peb.is_null() {
        return None;
    }
    // SAFETY: see `patch_console_state`.
    unsafe {
        let params = ptr::read_volatile(peb.add(PEB_PROCESS_PARAMETERS_OFFSET).cast::<usize>());
        if params == 0 {
            None
        } else {
            Some(ptr::read_volatile(
                (params as *mut usize).add(PROCESS_PARAMETERS_CONSOLE_HANDLE_OFFSET),
            ))
        }
    }
}

/// Convenience alias so callers do not have to name the raw pointer type.
pub type Peb = *mut c_void;

/// Keeps `HANDLE` referenced for the sentinel documentation above.
#[allow(dead_code)]
const _SENTINEL_TYPE: HANDLE = CONSOLE_HANDLE_SENTINEL as HANDLE;