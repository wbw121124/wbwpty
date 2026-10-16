//! Console API substitutes.
//!
//! # Why the target needs them at all
//!
//! A program whose stdout is a pipe works: `printf`, `WriteFile`, Rust's `println!`
//! all go to the handle the host handed over at creation. Plenty of programs do
//! not work that way. They ask for a *console* and use the console API:
//! `WriteConsoleW`, `GetConsoleMode`, `ReadConsoleInputW`. On a pipe those calls
//! fail - `WriteConsoleW` on a pipe is `ERROR_INVALID_HANDLE` - and the program
//! reacts by printing diagnostics, disabling its own output, or exiting.
//!
//! `cmd.exe` and `python.exe` do not need this; plenty of other tools do.
//!
//! # What is and is not in here
//!
//! Everything in this module answers from what the payload already holds, with no
//! question asked of anyone:
//!
//! * `WriteConsoleA` / `WriteConsoleW` - convert and write to the session's
//!   stdout, whose handle value the host published in `WBWPTY_STD_HANDLES`.
//! * `GetConsoleMode` / `SetConsoleMode` - a virtual mode word.
//! * `AllocConsole` / `FreeConsole` / `AttachConsole` - the three that only ever
//!   cost a program a failure.
//!
//! What is **not** here, and why, matters as much:
//!
//! * `GetConsoleScreenBufferInfo` and friends need a cursor position and a
//!   screen, and the screen is a virtual screen that needs a heap. This DLL is
//!   `no_std` with no allocator (AGENTS rule 3) - a worker thread may run before
//!   the target's CRT has a heap at all - so the screen cannot live here. It
//!   lives in the host, which has one, and answering those calls means a round
//!   trip. That is a separate piece of work, and until it exists those functions
//!   are deliberately *not* intercepted: leaving them alone fails honestly,
//!   whereas a substitute that answers from a made-up cursor position would fail
//!   confusingly.
//!
//! # How they are reached
//!
//! By rewriting the target's Import Address Table, the same way
//! [`crate::hook`] does for `CreateProcessW`. An IAT slot is data, so a Control
//! Flow Guard image never inspects it, and there is no instruction boundary to
//! find.
//!
//! That means one coverage limit, stated rather than hidden: a program that
//! resolves a console API at runtime with `GetProcAddress` does not have an
//! import slot for it, so it is not intercepted. That is the same limit the
//! `CreateProcessW` substitution has always had.
//!
//! # The handle value is not `GetStdHandle`
//!
//! Writes go to `WBWPTY_STD_HANDLES[1]`, which the host published and which is
//! the number of the pipe the target was *given*. AGENTS pitfall 14 is the reason:
//! `GetStdHandle` has been measured returning `INVALID_HANDLE_VALUE` in a process
//! whose stdout is a perfectly working pipe.

use core::ffi::c_void;
use core::ptr;

use crate::ffi::{self, BOOL, DWORD, HANDLE};
use crate::hook::WBWPTY_STD_HANDLES;

/// Long enough for any single conversion step, and still a stack frame.
const CONVERT_CAP: usize = 512;

/// The mode word [`wbwpty_get_console_mode`] reports, and the last one
/// [`wbwpty_set_console_mode`] was given.
///
/// A terminal, not a legacy console: what a program actually branches on is
/// `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, and a program that sees it will emit
/// escape sequences we want rather than cursor-positioning calls we would have to
/// interpret.
///
/// ```text
///   ENABLE_PROCESSED_OUTPUT            0x0001
///   ENABLE_WRAP_AT_EOL_OUTPUT         0x0002
///   ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
/// ```
const DEFAULT_CONSOLE_MODE: DWORD = 0x0001 | 0x0002 | 0x0004;

static CONSOLE_MODE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(DEFAULT_CONSOLE_MODE);

/// Counts, published for the host to read back out of the target.
///
/// Packed as `failures << 16 | calls`. A substitute that silently stops being
/// called is indistinguishable from one that never worked, and this is the only
/// place that shows up - which is the same argument as `WBWPTY_HOOK_STATS`.
#[no_mangle]
pub static mut WBWPTY_CONSOLE_STATS: u32 = 0;

/// What the console API substitutes did, for the host to read back.
#[no_mangle]
pub static mut WBWPTY_CONSOLE_MODE: u32 = DEFAULT_CONSOLE_MODE;

/// `GetConsoleMode`.
///
/// Reports a terminal's mode word for **any** handle, including one that is not a
/// console. Refusing a pipe would be the honest answer and the useless one: the
/// usual reaction is to disable output entirely, which is exactly the behaviour
/// this project exists to prevent.
#[no_mangle]
pub unsafe extern "system" fn wbwpty_get_console_mode(
    _handle: HANDLE,
    mode: *mut DWORD,
) -> BOOL {
    if mode.is_null() {
        return fail();
    }
    // SAFETY: the caller passed a non-null out parameter.
    unsafe { *mode = CONSOLE_MODE.load(core::sync::atomic::Ordering::Relaxed) };
    count(ffi::TRUE)
}

/// `SetConsoleMode`.
///
/// Takes whatever it is given. The mode word is ours to report, and a program
/// that turns off `ENABLE_VIRTUAL_TERMINAL_PROCESSING` has told us it wants
/// legacy output - which still means "the bytes we were given", so there is
/// nothing to refuse.
#[no_mangle]
pub unsafe extern "system" fn wbwpty_set_console_mode(
    _handle: HANDLE,
    mode: DWORD,
) -> BOOL {
    CONSOLE_MODE.store(mode, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: written from a thread inside the target, read by the host through
    // the same single word, which is the whole point of publishing it.
    unsafe { WBWPTY_CONSOLE_MODE = mode };
    count(ffi::TRUE)
}

/// `WriteConsoleW`.
///
/// The wide-character console write, which is the one that matters: a program
/// holding UTF-16 text has no other way to get it out.
#[no_mangle]
pub unsafe extern "system" fn wbwpty_write_console_w(
    _console: HANDLE,
    buffer: *const u16,
    chars_to_write: DWORD,
    chars_written: *mut DWORD,
    _reserved: *mut c_void,
) -> BOOL {
    if buffer.is_null() && chars_to_write != 0 {
        return fail();
    }
    count(write_units(
        // SAFETY: the caller promises `chars_to_write` units at `buffer`.
        unsafe { core::slice::from_raw_parts(buffer, chars_to_write as usize) },
        chars_written,
    ))
}

/// `WriteConsoleA`.
///
/// Already single-byte, and already the target's own encoding - which is the
/// point: the host reads the pipe as UTF-8, and reinterpreting the target's
/// OEM bytes would corrupt them. Whatever the program meant by them is what the
/// terminal gets, which is also what happens when the program writes to stdout
/// directly instead of going near this API.
#[no_mangle]
pub unsafe extern "system" fn wbwpty_write_console_a(
    _console: HANDLE,
    buffer: *const u8,
    chars_to_write: DWORD,
    chars_written: *mut DWORD,
    _reserved: *mut c_void,
) -> BOOL {
    if buffer.is_null() && chars_to_write != 0 {
        return fail();
    }
    // SAFETY: the caller promises `chars_to_write` bytes at `buffer`.
    let bytes = unsafe { core::slice::from_raw_parts(buffer, chars_to_write as usize) };
    let ok = match write_bytes(bytes) {
        Some(_) => {
            if !chars_written.is_null() {
                // SAFETY: the caller's out parameter. One byte is one character in
                // this encoding, which is exactly the promise this API makes.
                unsafe { *chars_written = bytes.len() as u32 };
            }
            ffi::TRUE
        }
        None => {
            if !chars_written.is_null() {
                // SAFETY: as above.
                unsafe { *chars_written = 0 };
            }
            ffi::FALSE
        }
    };
    count(ok)
}

/// `AllocConsole` - a no-op that succeeds.
///
/// The target already has somewhere to write. Allocating a second console is
/// precisely what would put a `conhost.exe` on the desktop.
#[no_mangle]
pub unsafe extern "system" fn wbwpty_alloc_console() -> BOOL {
    count(ffi::TRUE)
}

/// `FreeConsole` - a no-op that succeeds. See [`wbwpty_alloc_console`].
#[no_mangle]
pub unsafe extern "system" fn wbwpty_free_console() -> BOOL {
    count(ffi::TRUE)
}

/// `AttachConsole` - fails, always.
///
/// There is no console to attach to and pretending otherwise would have the
/// program start writing into a handle it believes is a console.
#[no_mangle]
pub unsafe extern "system" fn wbwpty_attach_console(_pid: DWORD) -> BOOL {
    fail()
}

/// Writes wide characters to the session's stdout as UTF-8.
///
/// Chunked through a stack buffer: the payload has no allocator, so a
/// whole-string conversion buffer is not an option, and a program is perfectly
/// entitled to write more text than any fixed buffer holds.
fn write_units(units: &[u16], chars_written: *mut DWORD) -> BOOL {
    let mut utf8 = [0u8; CONVERT_CAP];
    let mut chars = 0u32;
    let mut at = 0usize;

    while at < units.len() {
        // Fill the buffer with whole characters only. Cutting one in half would
        // turn an astral character into two replacement characters, which is the
        // kind of corruption nobody notices until it matters.
        let mut used = 0usize;
        let mut chunk_chars = 0u32;
        let mut next = at;
        while next < units.len() {
            let (need, step) = utf8_len(units, next);
            if used + need > CONVERT_CAP {
                break;
            }
            used += encode(units, next, &mut utf8[used..]);
            next += step;
            chunk_chars += 1;
        }
        if used == 0 {
            // The buffer cannot hold even one character. It is 512 bytes and the
            // widest character is four, so this cannot happen; if it somehow does,
            // stopping beats spinning.
            break;
        }
        if write_bytes(&utf8[..used]).is_none() {
            if !chars_written.is_null() {
                // SAFETY: the caller's out parameter; report the part that did go
                // out, which is what the API promises on a short write.
                unsafe { *chars_written = chars };
            }
            return ffi::FALSE;
        }
        chars += chunk_chars;
        at = next;
    }

    if !chars_written.is_null() {
        // SAFETY: the caller passed an out parameter. Counted in *characters*,
        // which is what this API promises - not in bytes, and not in UTF-16 units,
        // so one astral character counts once.
        unsafe { *chars_written = chars };
    }
    ffi::TRUE
}

/// `(bytes, units consumed)` for the character starting at `index`.
///
/// A high surrogate followed by a low surrogate is one character of four bytes.
/// Either surrogate on its own is not a character, and becomes U+FFFD.
fn utf8_len(units: &[u16], index: usize) -> (usize, usize) {
    let unit = units[index];
    if is_high_surrogate(unit) && index + 1 < units.len() && is_low_surrogate(units[index + 1]) {
        return (4, 2);
    }
    if is_high_surrogate(unit) || is_low_surrogate(unit) {
        return (3, 1);
    }
    match unit {
        0x0000..=0x007f => (1, 1),
        0x0080..=0x07ff => (2, 1),
        _ => (3, 1),
    }
}

/// UTF-16LE → UTF-8 at `units[index]`, returning how many bytes it wrote.
fn encode(units: &[u16], index: usize, out: &mut [u8]) -> usize {
    let unit = units[index];
    if is_high_surrogate(unit) {
        if index + 1 < units.len() && is_low_surrogate(units[index + 1]) {
            // One astral character: combine the pair, then encode as four bytes.
            let code =
                0x1_0000 + (((unit as u32) - 0xd800) << 10) + ((units[index + 1] as u32) - 0xdc00);
            out[0] = 0xf0 | (code >> 18) as u8;
            out[1] = 0x80 | ((code >> 12) & 0x3f) as u8;
            out[2] = 0x80 | ((code >> 6) & 0x3f) as u8;
            out[3] = 0x80 | (code & 0x3f) as u8;
            return 4;
        }
        replacement(out);
        return 3;
    }
    if is_low_surrogate(unit) {
        replacement(out);
        return 3;
    }
    match unit {
        0x0000..=0x007f => {
            out[0] = unit as u8;
            1
        }
        0x0080..=0x07ff => {
            out[0] = 0xc0 | (unit >> 6) as u8;
            out[1] = 0x80 | (unit & 0x3f) as u8;
            2
        }
        _ => {
            out[0] = 0xe0 | (unit >> 12) as u8;
            out[1] = 0x80 | ((unit >> 6) & 0x3f) as u8;
            out[2] = 0x80 | (unit & 0x3f) as u8;
            3
        }
    }
}

/// U+FFFD, the replacement character.
fn replacement(out: &mut [u8]) {
    out[0] = 0xef;
    out[1] = 0xbf;
    out[2] = 0xbd;
}

fn is_high_surrogate(unit: u16) -> bool {
    (0xd800..=0xdbff).contains(&unit)
}

fn is_low_surrogate(unit: u16) -> bool {
    (0xdc00..=0xdfff).contains(&unit)
}

/// Writes to the session's stdout. Returns how many bytes went out.
fn write_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return Some(0);
    }
    // SAFETY: a single word the host wrote before the substitution was installed.
    let handle = unsafe { WBWPTY_STD_HANDLES[1] as HANDLE };
    if handle.is_null() {
        return None;
    }

    let mut sent = 0u32;
    while (sent as usize) < bytes.len() {
        let mut written = 0u32;
        let rest = &bytes[sent as usize..];
        // SAFETY: `handle` is the target's own stdout, the slice is live, and a
        // synchronous write (null OVERLAPPED) needs no event.
        let ok = unsafe {
            ffi::WriteFile(
                handle,
                rest.as_ptr() as *const c_void,
                rest.len() as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return None;
        }
        sent += written;
    }
    Some(sent)
}

/// One substitution finished, successfully or not.
fn count(ok: BOOL) -> BOOL {
    // SAFETY: written from inside the target and read by the host as one word.
    unsafe {
        WBWPTY_CONSOLE_STATS = WBWPTY_CONSOLE_STATS.wrapping_add(if ok != 0 { 1 } else { 1 << 16 });
    }
    ok
}

/// A substitution that refuses, counted as a failure.
///
/// The error code is left alone deliberately: a program that reads it will see
/// whatever it saw before, and the call's failure is reported through the stats
/// word rather than through a fabricated `GetLastError`.
fn fail() -> BOOL {
    count(ffi::FALSE)
}