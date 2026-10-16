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

/// The real `CreateProcessAsUserW`, published on the same terms.
///
/// A target does not have to reach process creation through `CreateProcessW`,
/// and `cmd.exe` demonstrably does not: driven from its own command line under
/// `/c`, it creates children without ever calling the `CreateProcessW` slot the
/// host rewrites, yet an interactive `cmd /k` does call it for the same
/// operation. `cmd.exe` imports `CreateProcessAsUserW` and `CreateProcessA`
/// alongside `CreateProcessW`, so those are the entries that have to be
/// intercepted too - otherwise the substitution is installed, reports success,
/// and is never entered.
#[no_mangle]
pub static mut WBWPTY_ORIGINAL_CREATE_PROCESS_AS_USER_W: usize = 0;

/// The real `CreateProcessA`, published on the same terms as above.
#[no_mangle]
pub static mut WBWPTY_ORIGINAL_CREATE_PROCESS_A: usize = 0;

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

/// The flags this hook actually handed to the kernel.
///
/// `calls` is the number of children created through the substitution, and
/// `creation_flags` is the `dwCreationFlags` value passed to the real
/// `CreateProcessW` on the most recent one. Publishing it exists because the
/// host cannot otherwise tell "the substitution was installed and forced
/// `DETACHED_PROCESS`" from "the substitution was installed and something
/// downstream changed the flags" - and those two look identical from outside,
/// right down to the console appearing anyway.
#[no_mangle]
pub static mut WBWPTY_HOOK_FLAGS: [DWORD; 2] = [0, 0];

/// Whether to hand the child an explicit environment block.
///
/// Set by the host, and a question rather than an answer: generation 1 always
/// passes one (with `CREATE_UNICODE_ENVIRONMENT`), while generation 2 forwards
/// whatever the target passed, which for `cmd.exe` is `lpEnvironment = NULL`.
/// `NULL` means "inherit mine" and is well defined, so there is no reason to
/// prefer either - but the two generations differ here and the grandchild's
/// stdout does not bind, so this makes the difference testable one run at a time
/// instead of a guess baked into the code.
#[no_mangle]
pub static mut WBWPTY_EXPLICIT_ENVIRONMENT: u32 = 0;

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

/// Records the flags one substitution is about to hand the kernel, then counts
/// the result.
///
/// Shared by every entry point on purpose: the three APIs differ only in how
/// they spell their arguments, and the promise this module makes - no console,
/// our pipes - has to be kept identically by all of them or a target can pick
/// the one that is not.
unsafe fn note_call(flags: DWORD) {
    WBWPTY_HOOK_FLAGS = [flags, WBWPTY_HOOK_FLAGS[1] + 1];
}

unsafe fn note_result(ok: BOOL) {
    WBWPTY_HOOK_STATS = if ok != 0 {
        WBWPTY_HOOK_STATS.wrapping_add(1 << 8)
    } else {
        WBWPTY_HOOK_STATS.wrapping_add(1)
    };
}

/// The flags this project forces, whatever the caller asked for.
///
/// `CREATE_NEW_CONSOLE` is cleared because it contradicts `DETACHED_PROCESS`
/// (the docs call that combination undefined) and an undefined combination
/// that produces a console host is exactly what this project exists to prevent.
unsafe fn force_flags(dw_creation_flags: DWORD) -> DWORD {
    (dw_creation_flags & !ffi::CREATE_NEW_CONSOLE) | ffi::DETACHED_PROCESS
}

/// Decides what environment block to pass, and whether to flag it as Unicode.
///
/// Returns `(block, flags)`. When the target passed `NULL` - "inherit mine" -
/// and [`WBWPTY_EXPLICIT_ENVIRONMENT`] is set, the inherited environment is
/// materialised with `GetEnvironmentStringsW` and flagged, because that is what
/// generation 1 does. Otherwise the caller's `NULL` is left alone.
///
/// The block belongs to the caller of `CreateProcessW` only for the duration of
/// the call; the kernel copies it, so [`release_environment`] runs straight
/// after.
unsafe fn resolve_environment(lp_environment: *const c_void, flags: DWORD) -> (*const c_void, DWORD) {
    if !lp_environment.is_null() || WBWPTY_EXPLICIT_ENVIRONMENT == 0 {
        return (lp_environment, flags);
    }
    let block = ffi::GetEnvironmentStringsW();
    if block.is_null() {
        return (lp_environment, flags);
    }
    (block as *const c_void, flags | ffi::CREATE_UNICODE_ENVIRONMENT)
}

/// Releases a block obtained from [`resolve_environment`], if one was made.
///
/// # Safety
/// Must only be called with the pair `resolve_environment` returned, and only
/// once, after the `CreateProcessW` call it was handed to has returned.
unsafe fn release_environment(resolved: *const c_void, original: *const c_void) {
    if !resolved.is_null() && resolved != original {
        ffi::FreeEnvironmentStringsW(resolved as *mut u16);
    }
}

/// Points `si` at the session's three handles.
///
/// `STARTF_USESTDHANDLES` is what routes the child's output; `DETACHED_PROCESS`
/// is what stops a console being allocated for it. Neither half works alone -
/// see the table at the top of this module.
unsafe fn publish_handles_w(si: *mut STARTUPINFOW) {
    let h = wbwpty_resolved_handles();
    (*si).dwFlags |= ffi::STARTF_USESTDHANDLES;
    (*si).hStdInput = h[0] as HANDLE;
    (*si).hStdOutput = h[1] as HANDLE;
    (*si).hStdError = h[2] as HANDLE;
}

/// Resolves the three handles the child will actually receive.
///
/// Falls back to reopening the named pipe for any slot whose published handle no
/// longer names anything. See [`usable_handle`] for why that happens.
unsafe fn wbwpty_resolved_handles() -> [usize; 3] {
    let mut out = WBWPTY_STD_HANDLES;
    if let Some(h) = usable_handle(0, ffi::GENERIC_READ, "WBWPTY_IN") {
        out[0] = h as usize;
    }
    if let Some(h) = usable_handle(1, ffi::GENERIC_WRITE, "WBWPTY_OUT") {
        out[1] = h as usize;
    }
    if let Some(h) = usable_handle(2, ffi::GENERIC_WRITE, "WBWPTY_OUT") {
        out[2] = h as usize;
    }
    out
}

/// [`publish_handles_w`] for the `A` variant, which has an identical layout.
///
/// # Safety
/// Mirrored against [`STARTUPINFOA`] and the `const _` assertions in `ffi`, so
/// the three fields written here sit at the same offsets as in `STARTUPINFOW`.
unsafe fn publish_handles_a(si: *mut crate::ffi::STARTUPINFOA) {
    let handles = WBWPTY_STD_HANDLES;
    (*si).dwFlags |= ffi::STARTF_USESTDHANDLES;
    (*si).hStdInput = handles[0] as HANDLE;
    (*si).hStdOutput = handles[1] as HANDLE;
    (*si).hStdError = handles[2] as HANDLE;
}

/// True when the host gave us pipes to hand on.
///
/// Without them, forcing `DETACHED_PROCESS` would only take the child's console
/// away and leave it with nowhere to write, so the caller is left alone.
unsafe fn have_session_handles() -> bool {
    WBWPTY_STD_HANDLES[1] != 0
}

/// Longest pipe name this will bother to look for.
///
/// `\\.\pipe\` plus a session nonce is comfortably inside this. Fixed capacity
/// on the stack: rule 3, no allocator.
const PIPE_NAME_MAX: usize = 128;

/// Longest variable name this will bother to look for, plus its terminator.
///
/// 16 is comfortably above `WBWPTY_IN` / `WBWPTY_OUT`, and the length is
/// asserted below rather than trusted: writing the name into a fixed buffer is
/// exactly the kind of thing that corrupts the stack silently when the constant
/// grows and nobody recompiles the check.
const ENV_NAME_MAX: usize = 16;

/// The session pipe name the host published in the environment.
///
/// Both this process and every child inherit it, so a substitute running here
/// can name the same pipe the child needs.
unsafe fn env_pipe_name(which: &str, buf: &mut [u16]) -> bool {
    debug_assert!(which.len() + 1 <= ENV_NAME_MAX, "env name buffer too small");
    let bytes = which.as_bytes();
    if bytes.len() + 1 > ENV_NAME_MAX {
        return false;
    }
    let mut name = [0u16; ENV_NAME_MAX];
    for (i, b) in bytes.iter().enumerate() {
        name[i] = *b as u16;
    }
    name[bytes.len()] = 0;

    let got = ffi::GetEnvironmentVariableW(
        name.as_ptr(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    );
    got != 0 && (got as usize) < buf.len()
}

/// True when `h` still names a pipe this module can hand to a child.
///
/// The test is `FILE_TYPE_PIPE`, not merely "not unknown", and the difference
/// is the whole bug: a target that redirects its own stdout closes the inherited
/// pipe and then `CreateFile("nul")` reuses the same value. `nul` is a character
/// device, so `GetFileType` answers `FILE_TYPE_CHAR` and a check for
/// `FILE_TYPE_UNKNOWN` happily calls that handle "fine" - the child then gets a
/// device that swallows everything, which is how `sys.stdout` ends up `None`
/// while `GetStdHandle` still reports a plausible number.
unsafe fn handle_is_pipe(h: HANDLE) -> bool {
    !h.is_null() && h != INVALID_HANDLE && ffi::GetFileType(h) == ffi::FILE_TYPE_PIPE
}

/// Returns a handle the child can actually write to for the given slot.
///
/// When the published handle still names a pipe it is used as-is. When it does
/// not - because the target closed and recycled it - the same named pipe is
/// reopened by name, which is why the host puts `WBWPTY_IN` / `WBWPTY_OUT` in
/// the environment rather than only handing over three numbers.
///
/// Returns `None` when neither works, and the caller then leaves the child with
/// whatever it had: a wrong handle is worse than none, and failing to redirect
/// is a smaller problem than corrupting a program that was working.
///
/// # Safety
/// `slot` is an index into [`WBWPTY_STD_HANDLES`].
unsafe fn usable_handle(slot: usize, access: DWORD, which: &str) -> Option<HANDLE> {
    let published = WBWPTY_STD_HANDLES[slot] as HANDLE;
    if handle_is_pipe(published) {
        return Some(published);
    }

    let mut name = [0u16; PIPE_NAME_MAX];
    if !env_pipe_name(which, &mut name) {
        return None;
    }
    let h = ffi::CreateFileW(
        name.as_ptr(),
        access,
        ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE,
        core::ptr::null_mut(),
        ffi::OPEN_EXISTING,
        // Overlapped, because this runs in the target's `CreateProcess`: a
        // client that waits for a free server instance would block the caller
        // and the child would never be created.
        ffi::FILE_FLAG_OVERLAPPED,
        INVALID_HANDLE,
    );
    if handle_is_pipe(h) {
        Some(h)
    } else {
        None
    }
}

/// `INVALID_HANDLE_VALUE`, which is `HANDLE`'s way of saying "no handle".
const INVALID_HANDLE: HANDLE = -1isize as HANDLE;

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

    if !have_session_handles() {
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
    let mut owned = zeroed_startup_info();
    let si = if lp_startup_info.is_null() {
        &mut owned as *mut STARTUPINFOW
    } else {
        lp_startup_info
    };

    publish_handles_w(si);
    let flags = force_flags(dw_creation_flags);
    let (environment, flags) = resolve_environment(lp_environment, flags);
    note_call(flags);

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
        environment,
        lp_current_directory,
        si,
        lp_process_information,
    );
    release_environment(environment, lp_environment);

    note_result(ok);
    ok
}

/// Substituted for the target's `CreateProcessAsUserW`.
///
/// Identical in effect to [`create_process_w`] - same forced flags, same
/// handles - and reached by a target that creates processes under a token
/// rather than as itself. The token and logon flags are forwarded untouched:
/// this module's job is console and stdio, not impersonation.
#[no_mangle]
pub unsafe extern "system" fn create_process_as_user_w(
    h_token: HANDLE,
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
    let original = WBWPTY_ORIGINAL_CREATE_PROCESS_AS_USER_W;
    if original == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(
        HANDLE,
        *const u16,
        *mut u16,
        *const SECURITY_ATTRIBUTES,
        *const SECURITY_ATTRIBUTES,
        BOOL,
        DWORD,
        *const c_void,
        *const u16,
        *mut STARTUPINFOW,
        *mut PROCESS_INFORMATION,
    ) -> BOOL;
    let original: Fn = core::mem::transmute(original);

    if !have_session_handles() {
        return original(
            h_token,
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

    let mut owned = zeroed_startup_info();
    let si = if lp_startup_info.is_null() {
        &mut owned as *mut STARTUPINFOW
    } else {
        lp_startup_info
    };

    publish_handles_w(si);
    let flags = force_flags(dw_creation_flags);
    note_call(flags);

    let ok = original(
        h_token,
        lp_application_name,
        lp_command_line,
        lp_process_attributes,
        lp_thread_attributes,
        b_inherit_handles,
        flags,
        lp_environment,
        lp_current_directory,
        si,
        lp_process_information,
    );

    note_result(ok);
    ok
}

/// Substituted for the target's `CreateProcessA`.
///
/// The ANSI twin of [`create_process_w`]: same forced flags, same handles, and
/// a [`STARTUPINFOA`] whose relevant offsets are identical on x64. The command
/// line is passed through in whatever encoding the caller used - converting it
/// would mean a buffer this module cannot own.
#[no_mangle]
pub unsafe extern "system" fn create_process_a(
    lp_application_name: *const u8,
    lp_command_line: *mut u8,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: DWORD,
    lp_environment: *const c_void,
    lp_current_directory: *const u8,
    lp_startup_info: *mut crate::ffi::STARTUPINFOA,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let original = WBWPTY_ORIGINAL_CREATE_PROCESS_A;
    if original == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(
        *const u8,
        *mut u8,
        *const SECURITY_ATTRIBUTES,
        *const SECURITY_ATTRIBUTES,
        BOOL,
        DWORD,
        *const c_void,
        *const u8,
        *mut crate::ffi::STARTUPINFOA,
        *mut PROCESS_INFORMATION,
    ) -> BOOL;
    let original: Fn = core::mem::transmute(original);

    if !have_session_handles() {
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

    let mut owned = zeroed_startup_info_a();
    let si = if lp_startup_info.is_null() {
        &mut owned as *mut crate::ffi::STARTUPINFOA
    } else {
        lp_startup_info
    };

    publish_handles_a(si);
    let flags = force_flags(dw_creation_flags);
    note_call(flags);

    let ok = original(
        lp_application_name,
        lp_command_line,
        lp_process_attributes,
        lp_thread_attributes,
        b_inherit_handles,
        flags,
        lp_environment,
        lp_current_directory,
        si,
        lp_process_information,
    );

    note_result(ok);
    ok
}


fn zeroed_startup_info() -> STARTUPINFOW {
    // SAFETY: `STARTUPINFOW` is `#[repr(C)]` and every field is a plain integer
    // or pointer, so all-zero bits is a valid value for each of them.
    unsafe { core::mem::zeroed() }
}

/// [`zeroed_startup_info`] for the `A` variant.
fn zeroed_startup_info_a() -> crate::ffi::STARTUPINFOA {
    // SAFETY: as above, for `STARTUPINFOA`.
    unsafe { core::mem::zeroed() }
}


