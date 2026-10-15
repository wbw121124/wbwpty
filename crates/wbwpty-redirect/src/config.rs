//! The environment contract the host publishes for this payload.
//!
//! Read once, on the payload's own worker thread rather than in `DllMain`.
//! Parsing is not expensive, but the reason for the placement is not: `DllMain`
//! runs under the loader lock, and anything that pulls in another module's
//! initialisation path is a deadlock waiting to happen.
//!
//! Only the published names are read, and a missing or malformed value falls
//! back to the default rather than failing: a target whose geometry we guessed
//! wrong is still a target that runs.
//!
//! The names are frozen - see the contract in `wbwpty-core::child`.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ffi;

const DEFAULT_ROWS: u32 = 25;
const DEFAULT_COLS: u32 = 80;
/// `WBWPTY_CP == 0` means "leave whatever the target picks".
const DEFAULT_CODE_PAGE: u32 = 0;

static ROWS: AtomicU32 = AtomicU32::new(DEFAULT_ROWS);
static COLS: AtomicU32 = AtomicU32::new(DEFAULT_COLS);
static SHIM: AtomicU32 = AtomicU32::new(1);
static CODE_PAGE: AtomicU32 = AtomicU32::new(DEFAULT_CODE_PAGE);

/// Long enough for any of the contract's values, short enough for a stack frame.
const ENV_CAP: usize = 32;

/// Reads the contract out of this process' environment. Idempotent.
pub fn load() {
    ROWS.store(read_u16(ENV_ROWS, DEFAULT_ROWS), Ordering::Relaxed);
    COLS.store(read_u16(ENV_COLS, DEFAULT_COLS), Ordering::Relaxed);
    SHIM.store(read_flag(ENV_SHIM, true), Ordering::Relaxed);
    CODE_PAGE.store(read_u32(ENV_CP, DEFAULT_CODE_PAGE), Ordering::Relaxed);
}

pub fn rows() -> u16 {
    ROWS.load(Ordering::Relaxed) as u16
}

pub fn cols() -> u16 {
    COLS.load(Ordering::Relaxed) as u16
}

/// Whether the console API shim was requested. Honoured from Stage 8 on.
pub fn shim() -> bool {
    SHIM.load(Ordering::Relaxed) == 1
}

/// The target's code page override, or `0` for "do not touch it".
pub fn code_page() -> u32 {
    CODE_PAGE.load(Ordering::Relaxed)
}

const ENV_ROWS: &[u8] = b"WBWPTY_ROWS\0";
const ENV_COLS: &[u8] = b"WBWPTY_COLS\0";
const ENV_SHIM: &[u8] = b"WBWPTY_SHIM\0";
const ENV_CP: &[u8] = b"WBWPTY_CP\0";

/// Reads a UTF-16 environment value into `out`, returning its length in u16
/// units, or 0 when it is absent or does not fit.
///
/// # Safety
/// `name` must be a NUL terminated wide string, which every `ENV_*` above is.
unsafe fn read_env(name: &[u8], out: &mut [u16]) -> usize {
    debug_assert_eq!(name.last(), Some(&0));
    let n = ffi::GetEnvironmentVariableW(name.as_ptr().cast::<u16>(), out.as_mut_ptr(), out.len() as u32);
    // A return greater than the buffer means the value did not fit, which for
    // this contract cannot happen; treat it as absent rather than truncating.
    if n == 0 || n as usize >= out.len() {
        return 0;
    }
    n as usize
}

fn read_u16(name: &[u8], default: u32) -> u32 {
    let mut buf = [0u16; ENV_CAP];
    // SAFETY: `buf` outlives the call and `name` is NUL terminated.
    let n = unsafe { read_env(name, &mut buf) };
    if n == 0 {
        return default;
    }
    match parse_decimal(&buf[..n]) {
        Some(value) if value != 0 => value,
        _ => default,
    }
}

fn read_u32(name: &[u8], default: u32) -> u32 {
    let mut buf = [0u16; ENV_CAP];
    // SAFETY: as above.
    let n = unsafe { read_env(name, &mut buf) };
    if n == 0 {
        return default;
    }
    parse_decimal(&buf[..n]).unwrap_or(default)
}

fn read_flag(name: &[u8], default: bool) -> u32 {
    let mut buf = [0u16; ENV_CAP];
    // SAFETY: as above.
    let n = unsafe { read_env(name, &mut buf) };
    if n == 0 {
        return u32::from(default);
    }
    match buf[0] {
        // The host only ever writes "0" or "1", so the first unit is the whole
        // answer. Anything else is a malformed value, not a truthy one.
        c @ 0x30..=0x39 => (c == 0x31) as u32,
        _ => u32::from(default),
    }
}

/// Decimal parse of a UTF-16 slice, saturating rather than wrapping.
///
/// Only ASCII digits are accepted: a value that is not a plain number is a
/// malformed contract, and guessing at it is worse than using the default.
fn parse_decimal(units: &[u16]) -> Option<u32> {
    let mut value: u32 = 0;
    for &unit in units {
        if !(0x30..=0x39).contains(&unit) {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((unit - 0x30) as u32)?;
    }
    Some(value)
}