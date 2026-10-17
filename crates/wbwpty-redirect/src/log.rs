//! Logging for the injected DLL.
//!
//! A DLL cannot return errors to its host and must never crash the target
//! process, so every diagnostic goes through `OutputDebugStringA` (always
//! available) and, when `WBWPTY_LOG` names a file, additionally to that file.
//! Formatting happens into a *stack* buffer: this module must stay allocation
//! free (see AGENTS.md rule 3).
//!
//! # Why this formats by hand
//!
//! This used to be `core::fmt` plus `TruncWriter`, which is the obvious way to do
//! it and the reason the payload could not be injected quickly enough to beat a
//! target's first `CreateProcess`.
//!
//! `core::fmt`'s formatting machinery pulls in the C runtime: `Display` for a
//! `str` reaches `strlen`, the generic `Arguments` machinery reaches `memcpy`, and
//! anything reaching `write!` with a format string can reach
//! `__stdio_common_vfprintf`. The panic handler, which formats a `PanicInfo`,
//! is enough to drag all of that in. So the built payload imported
//! `calloc`, `free`, `memcpy`, `memset`, `strlen`, `__stdio_common_vfprintf`,
//! `_initterm` and the rest of the UCRT.
//!
//! That is not cosmetic. Injection can only complete once every module the
//! payload imports is mapped in the target, so a payload that needs the UCRT
//! cannot finish until the target has finished loading the UCRT - measured at
//! about 50 ms for `cmd.exe`, while `cmd.exe /c <command>` spawns its first
//! child within a couple. Measured on this machine, that was the entire gap:
//! with the UCRT dependencies the substitution went live 59 ms after spawn, and
//! the child's `conhost.exe` had already been created.
//!
//! Hand-rolled formatting keeps the payload's import list to `KERNEL32.dll`
//! alone, which `cmd.exe` has mapped within about 1 ms. See
//! [`fmt`] for the mini-formatter, and `log::without_crt_dependencies` for the
//! assertion that keeps this from regressing.
//!
//! What is deliberately not supported: floats, width/precision/fill flags,
//! alternate radix prefixes, padding, and any `Display` impl beyond the
//! primitives below. That is a real limitation, and the right trade here -
//! every byte of formatting machinery is a byte of the target's startup budget,
//! and a diagnostic that costs the injection its window is worse than a
//! diagnostic that does not get printed.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ffi;

const CAP: usize = 512;

/// Lazily opened log file. Written once from `DLL_PROCESS_ATTACH` only, so a
/// plain relaxed store/load pair is enough.
static LOG_FILE: AtomicU32 = AtomicU32::new(0);
static LOG_READY: AtomicU32 = AtomicU32::new(0);

/// Mirror every diagnostic to `OutputDebugStringA` regardless of `WBWPTY_LOG`.
///
/// Call from `DLL_PROCESS_ATTACH` before anything else can fail.
pub fn init_from_env() {
    let mut path = [0u16; 260];
    let n = unsafe { ffi::GetEnvironmentVariableW(cstr_w(b"WBWPTY_LOG\0").as_ptr(), path.as_mut_ptr(), path.len() as u32) };
    if n == 0 || n as usize > path.len() {
        return;
    }
    let h = unsafe {
        ffi::CreateFileW(
            path.as_mut_ptr(),
            ffi::GENERIC_WRITE,
            ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE,
            core::ptr::null_mut(),
            3, // OPEN_EXISTING
            ffi::FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if !h.is_null() {
        LOG_FILE.store(h as u32, Ordering::Relaxed);
        LOG_READY.store(1, Ordering::Relaxed);
    }
}

/// Emits one already-formatted line.
///
/// Takes bytes rather than `fmt::Arguments` so that no caller can accidentally
/// pull the formatting machinery back in: the formatting happens at the call
/// site, by [`fmt::Msg`].
pub fn write_bytes(body: &[u8]) {
    let mut buf = [0u8; CAP];
    // "[wbwpty] " is 9 bytes and the CRLF 2, so 11 of headroom; anything longer
    // than `CAP` is dropped rather than overflowing.
    if body.len() > CAP - 12 {
        return;
    }
    let mut n = 0;
    while n < 9 {
        buf[n] = PREFIX[n];
        n += 1;
    }
    let mut i = 0;
    while i < body.len() {
        buf[n] = body[i];
        n += 1;
        i += 1;
    }
    buf[n] = b'\r';
    buf[n + 1] = b'\n';
    n += 2;
    buf[n] = 0;

    unsafe {
        ffi::OutputDebugStringA(buf.as_ptr());

        if LOG_READY.load(Ordering::Relaxed) == 1 {
            let h = LOG_FILE.load(Ordering::Relaxed) as ffi::HANDLE;
            let mut written: u32 = 0;
            ffi::WriteFile(
                h,
                buf.as_ptr() as *const core::ffi::c_void,
                n as u32,
                &mut written,
                core::ptr::null_mut(),
            );
        }
    }
}

const PREFIX: &[u8; 9] = b"[wbwpty] ";

/// `#[used]`-style helper to build a NUL terminated wide literal at runtime
/// without allocating: a `&'static [u8]` is reinterpreted as `LPCWSTR`.
const fn cstr_w(s: &[u8]) -> [u16; 64] {
    let mut out = [0u16; 64];
    let mut i = 0;
    while i < s.len() && i < 63 {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

/// Formats into a stack buffer. See the module docs for why this exists rather
/// than `core::fmt`.
pub mod fmt {
    /// A fixed-capacity byte sink that drops whatever does not fit.
    pub struct Msg {
        buf: [u8; super::CAP],
        len: usize,
    }

    impl Msg {
        /// A new, empty message.
        pub fn new() -> Self {
            Self {
                buf: [0; super::CAP],
                len: 0,
            }
        }

        /// The formatted bytes, NUL not included.
        pub fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }

        /// Appends raw text.
        pub fn str(&mut self, s: &str) -> &mut Self {
            self.bytes(s.as_bytes())
        }

        /// Appends raw bytes.
        pub fn bytes(&mut self, s: &[u8]) -> &mut Self {
            let room = self.buf.len() - 1 - self.len;
            let take = if s.len() < room { s.len() } else { room };
            let mut i = 0;
            while i < take {
                self.buf[self.len + i] = s[i];
                i += 1;
            }
            self.len += take;
            self
        }

        /// Appends `value` in decimal, with a `-` for negatives.
        pub fn i64(&mut self, mut value: i64) -> &mut Self {
            if value < 0 {
                self.bytes(b"-");
                // `wrapping_neg` because `i64::MIN` has no positive counterpart.
                value = value.wrapping_neg();
            }
            self.u64(value as u64)
        }

        /// Appends `value` in decimal.
        pub fn u64(&mut self, mut value: u64) -> &mut Self {
            let mut digits = [0u8; 20];
            let mut n = 0;
            // `value == 0` has no iterations, so write the one digit separately.
            if value == 0 {
                return self.bytes(b"0");
            }
            while value != 0 && n < digits.len() {
                digits[n] = b'0' + (value % 10) as u8;
                value /= 10;
                n += 1;
            }
            while n > 0 {
                n -= 1;
                self.bytes(&[digits[n]]);
            }
            self
        }

        /// Appends `value` as `0x` followed by lowercase hex, no padding.
        pub fn hex(&mut self, value: u64) -> &mut Self {
            self.bytes(b"0x");
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut started = false;
            for shift in (0..16).rev() {
                let nibble = ((value >> (shift * 4)) & 0xf) as usize;
                // Suppress leading zeros, but keep one digit for zero itself.
                if nibble == 0 && !started && shift != 0 {
                    continue;
                }
                started = true;
                self.bytes(&[DIGITS[nibble]]);
            }
            self
        }

        /// Appends `0x` when true, nothing when false.
        pub fn flag(&mut self, value: bool) -> &mut Self {
            self.bytes(if value { b"true" } else { b"false" })
        }
    }
}

/// Logs a message built by a closure.
///
/// Written as a closure rather than as `dlog!("a {} b", x)` on purpose. A format
/// string needs `core::fmt`, and `core::fmt` is what pulls the C runtime into the
/// payload - see the module docs. Taking a block instead means the arguments are
/// ordinary method calls on [`fmt::Msg`], and nothing in the image can reach the
/// formatter machinery at all.
///
/// ```
/// dlog!(|m| {
///     m.str("slot ").hex(0x7ff9_0000).str(" flags ").hex(flags);
/// });
/// ```
#[macro_export]
macro_rules! dlog {
    (|$m:ident| $body:block) => {{
        let mut $m = $crate::log::fmt::Msg::new();
        $body;
        $crate::log::write_bytes($m.as_bytes());
    }};
}

/// Logs a constant message, no formatting at all.
#[macro_export]
macro_rules! dlog_line {
    ($text:literal) => {
        $crate::log::write_bytes(concat!($text, "\r\n").as_bytes())
    };
}