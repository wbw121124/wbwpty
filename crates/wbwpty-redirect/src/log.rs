//! Logging for the injected DLL.
//!
//! A DLL cannot return errors to its host and must never crash the target
//! process, so every diagnostic goes through `OutputDebugStringA` (always
//! available) and, when `WBWPTY_LOG` names a file, additionally to that file.
//! Formatting happens into a *stack* buffer: this module must stay allocation
//! free (see AGENTS.md rule 3).

use core::fmt::{self, Write};
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

pub fn write_line(args: fmt::Arguments<'_>) {
    let mut buf = [0u8; CAP];
    let mut w = TruncWriter { buf: &mut buf, len: 0 };

    let _ = write!(w, "[wbwpty] ");
    let _ = write!(w, "{args}");
    let _ = write!(w, "\r\n");
    let n = w.len.min(CAP - 1);
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

/// `core::fmt::Write` adapter that silently drops whatever does not fit.
struct TruncWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Write for TruncWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let end = (self.len + bytes.len()).min(self.buf.len());
        self.buf[self.len..end].copy_from_slice(&bytes[..end - self.len]);
        self.len = end;
        Ok(())
    }
}

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

#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {
        $crate::log::write_line(format_args!($($arg)*))
    };
}