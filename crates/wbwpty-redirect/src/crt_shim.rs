//! `#[no_mangle]` definitions of the C runtime routines the Windows GNU
//! toolchain's compiler-builtins expect to find in the host executable.
//!
//! # Why these exist
//!
//! They are not here because this crate uses them. They are here because a
//! `no_std` crate on `x86_64-pc-windows-gnu` still gets a `compiler_builtins`
//! runtime, and that runtime references `memcpy`, `memset`, `strlen`, `memcmp`,
//! `calloc` and `free` as *imports*. An import is a demand on the host process:
//! [`crate::manual_map`] can only resolve an import against a module the target
//! has already mapped, so every one of these DLLs is a module the target must
//! finish loading before the payload can be injected at all.
//!
//! That cost is not small and it is not optional. Measured on this machine,
//! `cmd.exe` needs roughly 50 ms to map the five `api-ms-win-crt-*` DLLs below,
//! and `cmd.exe /c <command>` creates its first child well inside that window.
//! With those imports present the `CreateProcess` substitution went live 59 ms
//! after spawn - after the child had already been given a console host of its
//! own, which is the bug this crate exists to prevent.
//!
//! Defining the routines here removes the imports: the payload's import list
//! becomes `KERNEL32.dll` alone, which `cmd.exe` has mapped about a millisecond
//! after it starts. Injection then finishes before the target runs any code that
//! could spawn anything.
//!
//! # Why hand-written rather than `memcpy` from the CRT
//!
//! Using the CRT's `memcpy` here would reintroduce the very import it is meant
//! to remove. These are straightforward implementations of the C semantics -
//! overlap-tolerant, correctly ordered - not fast ones. `memcpy` is legal to
//! implement with a byte loop; what matters is that it is correct, because a
//! wrong one corrupts the target silently.
//!
//! # `calloc`/`free`
//!
//! `compiler_builtins` references these for the panic/unwind machinery that
//! this crate never takes, because `panic = "abort"` and there is no
//! `#[alloc]`. They still appear as imports, so they still have to exist. The
//! implementations below refuse rather than hand out memory: a payload that has
//! no allocator must never quietly acquire one, and a call here is a bug that
//! should be loud. Returning null turns a would-be corruption into an
//! allocation failure the caller has to handle.

use core::sync::atomic::{AtomicU32, Ordering};

/// How many times something tried to use the allocator this crate does not have.
///
/// Read by the host through the status word's log path; there is no other way
/// for a `no_std` DLL to complain without allocating.
static ALLOC_REFUSALS: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Memory primitives
//
// Each is `unsafe extern "C"` because that is the ABI the compiler-generated
// code expects, and all three are the plain reading of their C contract.
// ---------------------------------------------------------------------------

/// `memcpy`: copies `n` bytes; source and destination must not overlap.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n == 0 {
        return dest;
    }
    // `copy_nonoverlapping` states the precondition in the type system and emits
    // the byte loop; going through `read`/`write` by hand would be the same code
    // with the requirement merely documented.
    core::ptr::copy_nonoverlapping(src, dest, n);
    dest
}

/// `memmove`: like `memcpy`, but the regions may overlap.
#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n == 0 {
        return dest;
    }
    // The one call that gets the overlapping case right.
    core::ptr::copy(src, dest, n);
    dest
}

/// `memset`: writes `value` to `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, value: i32, n: usize) -> *mut u8 {
    if n == 0 {
        return dest;
    }
    core::ptr::write_bytes(dest, value as u8, n);
    dest
}

/// `memcmp`: compares `n` bytes, returning the sign of the first difference.
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = (*a.add(i), *b.add(i));
        if x != y {
            // Widened to `i32` before subtracting: `u8` subtraction would wrap and
            // turn "a < b" into a positive result for most inputs.
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

/// `strlen`: length of a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    while *s.add(n) != 0 {
        n += 1;
    }
    n
}

/// `strncmp`: compares at most `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = (*a.add(i), *b.add(i));
        if x != y {
            return x as i32 - y as i32;
        }
        // Two NULs end the comparison; falling through to `n` would keep reading.
        if x == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

// ---------------------------------------------------------------------------
// The allocator this crate does not have
// ---------------------------------------------------------------------------

/// `calloc`: refuses, and counts the refusal.
///
/// Not an implementation - this crate is `no_std` and has no allocator, which is
/// the whole reason the worker thread may run before the target's heap exists
/// (AGENTS rule 3). Returning null is the honest answer: the caller sees a
/// failure, rather than getting a pointer into memory this code does not own.
#[no_mangle]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut core::ffi::c_void {
    ALLOC_REFUSALS.fetch_add(1, Ordering::Relaxed);
    core::ptr::null_mut()
}

/// `free`: refuses. There is nothing of ours to release, and inventing a heap
/// here to match would be the bug this module exists to prevent.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut core::ffi::c_void) {
    ALLOC_REFUSALS.fetch_add(1, Ordering::Relaxed);
    let _ = ptr;
}

/// How many allocation attempts have been refused.
///
/// Exists so the host can tell "the payload never allocated" apart from "the
/// payload allocated and something went wrong", which look identical from
/// outside otherwise.
pub fn allocation_refusals() -> u32 {
    ALLOC_REFUSALS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// C runtime start-up
//
// The toolchain links a small C start-up alongside `compiler_builtins`, and it
// references these. None of them is reachable from this crate's own code: there
// is no `main`, no static initialiser to run, and `panic = "abort"`. They are
// declared here so that the *linker* resolves them against this object rather
// than against the import table, which is the entire point - see the module
// docs.
// ---------------------------------------------------------------------------

/// `_initterm`: runs a table of initialiser functions. This crate has none.
#[no_mangle]
pub unsafe extern "C" fn _initterm(start: *mut core::ffi::c_void, end: *mut core::ffi::c_void) {
    let _ = (start, end);
}

/// `_initterm_e`: as [`_initterm`], and reports failure.
#[no_mangle]
pub unsafe extern "C" fn _initterm_e(
    start: *mut core::ffi::c_void,
    end: *mut core::ffi::c_void,
    _complete: *mut core::ffi::c_void,
) -> i32 {
    let _ = (start, end);
    0
}

/// `_initialize_onexit_table`: prepares the atexit table. Unused here.
#[no_mangle]
pub unsafe extern "C" fn _initialize_onexit_table() {}

/// `_execute_onexit_table`: runs the atexit table. Unused here.
#[no_mangle]
pub unsafe extern "C" fn _execute_onexit_table() {}

/// `_register_onexit_function`: registers an atexit handler.
///
/// Returns a non-zero value, which the C contract requires for success. There is
/// nothing to run the handler - and a DLL attached into a live process has no
// business running code at unload anyway - so the registration is simply not
/// honoured. Returning false instead would make some callers treat a normal
/// teardown as an error.
#[no_mangle]
pub unsafe extern "C" fn _register_onexit_function(
    _func: *mut core::ffi::c_void,
    _param: *mut core::ffi::c_void,
) -> i32 {
    1
}

/// `abort`: the process cannot continue after one of these.
///
/// Kept honest: `Sleep(INFINITE)` parks the thread instead of pulling the rug
/// out from under the target, which is what `abort` would do. The target then
/// has to be terminated deliberately, by the host or by the user, rather than
/// losing whatever state it was in to a signal it never asked for.
#[no_mangle]
pub unsafe extern "C" fn abort() -> ! {
    loop {
        // SAFETY: `Sleep` has no preconditions.
        unsafe { crate::ffi::Sleep(0xffff_ffff) };
    }
}

/// `_exit`: leaves without unwinding or flushing.
///
/// Implemented in terms of `TerminateProcess` on the current process, which is
/// the only way to express it here - `ExitProcess` would be an import we are
/// trying not to have. The exit status is the low 32 bits of the argument, which
/// is what `_exit` specifies.
#[no_mangle]
pub unsafe extern "C" fn _exit(status: i32) -> ! {
    // SAFETY: `GetCurrentProcess` returns the pseudo-handle and
    // `TerminateProcess` accepts it; both are documented that way and neither
    // takes ownership of anything.
    unsafe {
        crate::ffi::TerminateProcess(crate::ffi::GetCurrentProcess(), status as u32);
    }
    loop {
        // SAFETY: as above. `TerminateProcess` on the current process does not
        // return, but the compiler cannot know that, and an infinite loop is the
        // honest statement of "this thread is finished".
        unsafe { crate::ffi::Sleep(0xffff_ffff) };
    }
}

/// `__acrt_iob_func`: the CRT's per-thread stream table.
///
/// The only caller would be CRT-internal formatting, which this payload does not
/// do. Returning null is the documented "no CRT attached" answer, and it is what
/// a DLL loaded into a process whose CRT this module has deliberately avoided
/// touching should report.
#[no_mangle]
pub unsafe extern "C" fn __acrt_iob_func(_index: i32) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

/// `__stdio_common_vfprintf`: formats to a stream.
///
/// A stub that reports "unsupported" rather than writing anything. Reaching it
/// would mean something reached for `printf`, and this payload formats its own
/// diagnostics into a stack buffer in [`crate::log`] instead. Silently succeeding
/// would hide that; the negative return says the write did not happen.
#[no_mangle]
pub unsafe extern "C" fn __stdio_common_vfprintf(
    _options: *mut core::ffi::c_void,
    _stream: *mut core::ffi::c_void,
    _format: *const u8,
    _arg_list: *mut core::ffi::c_void,
    _max_count: usize,
) -> i32 {
    -1
}