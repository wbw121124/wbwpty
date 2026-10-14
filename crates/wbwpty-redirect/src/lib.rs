//! wbwpty-redirect: the DLL that is manually mapped into the target process.
//!
//! Constraints (see AGENTS.md):
//!   * `#![no_std]` and `panic = "abort"` — this DLL runs inside someone else's
//!     process, possibly before that process' CRT/heap is initialised, so it
//!     must never touch the allocator, TLS or unwinding.
//!   * `DllMain` runs under the loader lock and before the target's entry
//!     point, so it only does work that is safe under those rules: opening
//!     handles, `SetStdHandle`, PEB bookkeeping, and starting a thread.
//!   * Every failure path must degrade gracefully; never make the target crash.

#![no_std]

pub mod crt;
pub mod ffi;
pub mod log;
pub mod peb;
pub mod stdio;

use core::ffi::c_void;

use ffi::{HINSTANCE, DWORD};

/// Injection status word published for the host to read back after mapping.
///
/// The host maps the image with `FILE_MAP_WRITE`-like semantics (plain RWX
/// pages), so it can read this out of the mapped `base + wbwpty_status_rva`.
/// Keeping it as a plain `static mut`-free `UnsafeCell` avoids pulling `core::cell`
/// initialisation into the image; a `static` with an initial value is stored in
/// `.data`/`.bss` which the manual mapper allocates, so it is safe to touch
/// before the entry point runs.
#[no_mangle]
pub static mut WBWPTY_STATUS: u32 = 0;

/// Marks the image as live. Written by [`wbwpty_probe`] so the host can tell
/// "the image mapped and its code runs" from "the image is present but its code
/// faults", which is otherwise indistinguishable from a silent failure.
pub const PROBE_MARKER: u32 = 0xc0de_cafe;

/// Bisect entry point: touches nothing but the payload's own writable data.
///
/// If the host can read [`PROBE_MARKER`] back out of the target after mapping
/// this as the entry, the manual mapper produced a working image. If it cannot,
/// the fault is in the mapping (relocations, sections, or the call itself) and
/// not in whatever [`DllMain`] happens to do.
#[no_mangle]
pub extern "system" fn wbwpty_probe() -> i32 {
    unsafe { WBWPTY_STATUS = PROBE_MARKER };
    0
}

pub const WBWPTY_STATUS_IDLE: u32 = 0;
pub const WBWPTY_STATUS_OK: u32 = 1;
pub const WBWPTY_STATUS_NO_PIPE_IN: u32 = 2;
pub const WBWPTY_STATUS_NO_PIPE_OUT: u32 = 3;

/// Entry point invoked by the manual mapper (and by the C runtime when the DLL
/// is loaded normally with `LoadLibrary`).
#[no_mangle]
pub extern "system" fn DllMain(_hinst: HINSTANCE, reason: DWORD, _reserved: *mut c_void) -> i32 {
    // Record the args so the host can verify the stub passed them correctly,
    // and exercise the same code path the real attach would.
    unsafe {
        WBWPTY_STATUS = PROBE_MARKER | (reason << 8) | ((_hinst as usize & 0xff) as u32);
    }
    match reason {
        ffi::DLL_PROCESS_ATTACH => {
            crate::stdio::install();
        }
        ffi::DLL_THREAD_ATTACH | ffi::DLL_THREAD_DETACH | ffi::DLL_PROCESS_DETACH => {}
        _ => {}
    }
    ffi::TRUE
}

/// `core` is shipped in the sysroot compiled with unwinding, so its `.xdata`
/// still references `rust_eh_personality` even though this crate is built with
/// `panic = "abort"`. Nothing in this DLL can unwind (the panic handler below
/// loops forever), so an empty personality routine satisfies the linker.
#[no_mangle]
extern "C" fn rust_eh_personality() {}

/// A panic in a `no_std` DLL must not unwind. Report and spin forever; the host
/// watchdog will terminate the target rather than corrupt its state.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::dlog!("panic in DllMain: {}", info);
    loop {
        // SAFETY: `Sleep` has no preconditions; `INFINITE` keeps us parked.
        unsafe { ffi::Sleep(0xffff_ffff) };
    }
}