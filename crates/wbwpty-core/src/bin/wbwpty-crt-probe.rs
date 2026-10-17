//! Test fixture: write to stdout **through ucrtbase's own buffered stdio**.
//!
//! # Why this exists
//!
//! Stage 7 wants the payload to put the target's stdio into line-buffered mode,
//! because a CRT that block-buffers a pipe holds output until its buffer fills,
//! which is what makes a long-running program look hung. Two things have to be
//! established before that is worth building, and neither can be guessed:
//!
//! 1. What `_IOLBF` actually is. It is a macro, not an export, so it cannot be
//!    read out of `ucrtbase.dll`. MSVC's UCRT and mingw's msvcrt disagree about
//!    its value, and the payload runs inside processes built against either.
//! 2. Whether calling `setvbuf` on a stream that has already been written to
//!    does anything at all. The C standard says the call is undefined once I/O
//!    has started, and by the time the payload can be mapped the target's CRT
//!    has long since initialised stdio.
//!
//! # Why it talks to ucrtbase explicitly
//!
//! This binary is built with the gnu toolchain, so its own `printf` goes
//! through **msvcrt**, not ucrtbase. Resolving ucrtbase's exports at runtime and
//! writing through ucrtbase's `FILE *` gives a stream that is buffered exactly
//! the way a ucrt program's would be - block buffered, because the handle is a
//! pipe - and lets the test toggle the mode and watch what happens.
//!
//! # Usage
//!
//! ```text
//! wbwpty-crt-probe [--setvbuf MODE] [--bytes N] [--sleep-ms N] [--newline]
//! ```
//!
//! Writes `--bytes` bytes to ucrtbase's stdout without flushing, sleeps, exits.
//! Whether the bytes reach the pipe during the sleep or only at exit is what
//! tells the caller which buffering mode is in effect.

use std::ffi::{c_char, c_int, c_void, CString};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

type Setvbuf = unsafe extern "system" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int;
type IobFunc = unsafe extern "system" fn(u32) -> *mut c_void;
type Fwrite = unsafe extern "system" fn(*const c_void, usize, usize, *mut c_void) -> usize;

const OUT_BUFFER_SIZE: usize = 4096;

fn main() {
    let mut mode: Option<i32> = None;
    let mut bytes = 64usize;
    let mut sleep_ms = 400u64;
    let mut newline = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setvbuf" => mode = args.next().and_then(|v| v.parse::<i32>().ok()),
            "--bytes" => {
                bytes = args
                    .next()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(bytes)
            }
            "--sleep-ms" => {
                sleep_ms = args
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(sleep_ms)
            }
            "--newline" => newline = true,
            other => {
                eprintln!("wbwpty-crt-probe: unknown argument {other:?}");
                std::process::exit(2);
            }
        }
    }

    let ucrt = ucrtbase();
    // SAFETY: ucrtbase exports all three; `stdout` is index 1 per `_iob`.
    let (iobf, setvbuf, fwrite): (IobFunc, Setvbuf, Fwrite) = unsafe {
        (
            std::mem::transmute(resolve(ucrt, "__acrt_iob_func")),
            std::mem::transmute(resolve(ucrt, "setvbuf")),
            std::mem::transmute(resolve(ucrt, "fwrite")),
        )
    };

    // SAFETY: index 1 is stdout and the function pointer is ucrtbase's.
    let stdout = unsafe { iobf(1) };
    if stdout.is_null() {
        eprintln!("wbwpty-crt-probe: ucrtbase gave us a null stdout");
        std::process::exit(3);
    }

    let setvbuf_result = mode.map(|m| {
        // SAFETY: a null buffer asks ucrtbase to allocate one of its own, which
        // is its heap and is initialised by the time anything writes.
        let rc = unsafe { setvbuf(stdout, std::ptr::null_mut(), m, OUT_BUFFER_SIZE) };
        eprintln!("wbwpty-crt-probe: setvbuf(mode={m}) -> {rc}");
        rc
    });

    let mut payload = vec![b'A'; bytes + usize::from(newline)];
    if newline {
        let last = payload.len() - 1;
        payload[last] = b'\n';
    }

    // SAFETY: a live `FILE *` and a buffer that outlives the call. No flush:
    // whether these bytes arrive during the sleep is the whole measurement.
    let written = unsafe { fwrite(payload.as_ptr() as *const c_void, 1, payload.len(), stdout) };
    eprintln!(
        "wbwpty-crt-probe: fwrite={written} setvbuf={setvbuf_result:?} sleeping={sleep_ms}ms"
    );

    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
}

fn ucrtbase() -> HMODULE {
    let name: Vec<u16> = "ucrtbase.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: the name is NUL terminated and outlives the call.
    let handle = unsafe { LoadLibraryW(name.as_ptr()) };
    if handle.is_null() {
        eprintln!("wbwpty-crt-probe: ucrtbase.dll did not load");
        std::process::exit(3);
    }
    handle
}

/// Resolves an export by name.
///
/// # Safety
/// `ucrt` must be a live module handle; the returned pointer is only valid for
/// as long as it stays loaded.
unsafe fn resolve(ucrt: HMODULE, name: &str) -> *const c_void {
    let cname = CString::new(name).expect("literal has no NUL");
    let addr = GetProcAddress(ucrt, cname.as_ptr().cast::<u8>());
    if addr.is_none() {
        eprintln!("wbwpty-crt-probe: ucrtbase does not export {name}");
        std::process::exit(3);
    }
    addr.map(|f| f as *const c_void).unwrap_or(std::ptr::null())
}
