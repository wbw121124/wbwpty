//! Interception: make everything the target spawns land on our pipes.
//!
//! # Why this exists
//!
//! The target's own standard handles are correct - the host handed them over
//! through `STARTF_USESTDHANDLES` before the target ran an instruction. What
//! does not survive is the *second* generation: a process the target creates
//! gets neither a console nor any standard handles, so it is mute, and it is
//! also the reason a `conhost.exe` appears. Two independent halves, both
//! measured (`tests/descendant_creation.rs`):
//!
//! | how the child is created | console host | output reaches our pipe |
//! | --- | --- | --- |
//! | handle inheritance only | yes | no |
//! | `STARTF_USESTDHANDLES` | **yes** | yes |
//! | `DETACHED_PROCESS` | no | **no** |
//! | **`DETACHED_PROCESS` + `STARTF_USESTDHANDLES`** | **no** | **yes** |
//!
//! Doing either half alone leaves one promise broken, which is why
//! [`create_process_w`] does both.
//!
//! # How it is reached
//!
//! By rewriting the target's **Import Address Table**, not by patching code.
//! `cmd.exe` imports `CreateProcessW` from
//! `api-ms-win-core-processthreads-l1-1-0.dll` and `cmd.exe` is a Control Flow
//! Guard image (`DllCharacteristics = 0xc160`). An IAT slot is data, so the
//! guard never sees it - where an inline trampoline in `KernelBase` would have
//! to be a registered call target to survive at all.
//!
//! The host does the rewriting from outside; see
//! `wbwpty_core::manual_map::iat`. All this module has to do is be the thing
//! the slot points at.
//!
//! # The handle values
//!
//! They come from the host, not from `GetStdHandle`. Measured on this machine:
//! `GetStdHandle` can hand back `INVALID_HANDLE_VALUE` in a process whose
//! stdout is a perfectly working pipe, and passing those on gives the child
//! three broken handles and an immediate exit code of 1. The host knows the
//! real values - it is the one that created them - and inherited handle values
//! are the same number on both sides of a `CreateProcess`.

use core::ffi::c_void;

use crate::ffi::{self, BOOL, DWORD, HANDLE, PROCESS_INFORMATION, STARTUPINFOW};

/// The real `CreateProcessW` inside the target, published by the host before it
/// rewrites the IAT. Written first, always: a target that called the hook with
/// this still zero would call address zero.
#[no_mangle]
pub static mut WBWPTY_ORIGINAL_CREATE_PROCESS: usize = 0;

/// `stdin`, `stdout`, `stderr` as the target sees them.
#[no_mangle]
pub static mut WBWPTY_STD_HANDLES: [usize; 3] = [0, 0, 0];

/// Counts of what the hook has done, published for the host to read back.
///
/// Packed as `children << 8 | failures`. A hook that silently stops being
/// called is indistinguishable from one that never worked, and this is the only
/// place that shows up.
#[no_mangle]
pub static mut WBWPTY_HOOK_STATS: u32 = 0;

type CreateProcessW = unsafe extern "system" fn(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: DWORD,
    lp_environment: *const c_void,
    lp_current_directory: *const u16,
    lp_startup_info: *mut STARTUPINFOW,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL;

/// `SECURITY_ATTRIBUTES`, only so the parameter types are honest. Nothing here
/// ever looks inside it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_ATTRIBUTES {
    n_length: DWORD,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: BOOL,
}

/// Substituted for the target's `CreateProcessW`.
///
/// Everything it changes is forced, not conditional:
///
/// * `DETACHED_PROCESS` is OR-ed into the flags. This is what stops the base
///   API from allocating a console for the child, and therefore what stops a
///   `conhost.exe` from appearing. `CREATE_NEW_CONSOLE` in the flags would
///   contradict it, so it is cleared first - the docs call that combination
///   undefined, and an undefined combination that produces a console host is
///   exactly what this project exists to prevent.
/// * `STARTF_USESTDHANDLES` is set with the session's own pipes, which is what
///   routes the child's output.
///
/// A child created with no `STARTUPINFOW` gets one, because there is nowhere to
/// put the handles otherwise.
#[no_mangle]
pub unsafe extern "system" fn create_process_w(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: DWORD,
    lp_environment: *const c_void,
    lp_current_directory: *const u16,
    lp_startup_info: *mut STARTUPINFOW,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let original = WBWPTY_ORIGINAL_CREATE_PROCESS;
    if original == 0 {
        // The host rewrites the IAT only after publishing the original, so
        // reaching this means the two raced or the image was patched by
        // something else. Doing nothing is the only safe answer.
        return 0;
    }
    let original: CreateProcessW = core::mem::transmute(original);

    let handles = WBWPTY_STD_HANDLES;
    if handles[1] == 0 {
        // No session handles: we would only be removing the child's console
        // without giving it a way to write. Leave it alone.
        return original(
            lp_application_name,
            lp_command_line,
            lp_process_attributes,
            lp_thread_attributes,
            b_inherit_handles,
            dw_creation_flags,
            lp_environment,
            lp_current_directory,
            lp_startup_info,
            lp_process_information,
        );
    }

    // A caller with no STARTUPINFOW has nowhere to put the handles.
    let mut owned;
    let si = if lp_startup_info.is_null() {
        owned = zeroed_startup_info();
        &mut owned as *mut STARTUPINFOW
    } else {
        lp_startup_info
    };

    (*si).dwFlags |= ffi::STARTF_USESTDHANDLES;
    (*si).hStdInput = handles[0] as HANDLE;
    (*si).hStdOutput = handles[1] as HANDLE;
    (*si).hStdError = handles[2] as HANDLE;

    let flags = (dw_creation_flags & !ffi::CREATE_NEW_CONSOLE) | ffi::DETACHED_PROCESS;

    let ok = original(
        lp_application_name,
        lp_command_line,
        lp_process_attributes,
        lp_thread_attributes,
        // Passed through unchanged. The matrix row this hook is written against
        // (`DETACHED_PROCESS` + `STARTF_USESTDHANDLES`) was measured with
        // handle inheritance on, and nothing in it requires turning it off.
        b_inherit_handles,
        flags,
        lp_environment,
        lp_current_directory,
        si,
        lp_process_information,
    );

    WBWPTY_HOOK_STATS = if ok != 0 {
        WBWPTY_HOOK_STATS.wrapping_add(1 << 8)
    } else {
        WBWPTY_HOOK_STATS.wrapping_add(1)
    };
    ok
}

fn zeroed_startup_info() -> STARTUPINFOW {
    // SAFETY: `STARTUPINFOW` is `#[repr(C)]` and every field is a plain integer
    // or pointer, so all-zero bits is a valid value for each of them.
    unsafe { core::mem::zeroed() }
}