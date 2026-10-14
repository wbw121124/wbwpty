//! Error plumbing.
//!
//! Public APIs speak `anyhow::Result` (AGENTS.md rule 8). Win32 failures always
//! carry the operation that failed *and* the thread's last error code, because
//! almost every Win32 function only reports failure through `GetLastError()`.

use std::fmt;

pub use anyhow::{anyhow, bail, Context, Result};

/// Convenience alias so callers can `use wbwpty_core::Result`.
pub type CoreResult<T> = anyhow::Result<T>;

/// Wraps a `BOOL`-returning Win32 call: on `FALSE` produces an error carrying
/// the operation name and `GetLastError()`.
pub fn check_bool(op: impl Into<String>, ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(anyhow!("{} failed: {}", op.into(), last_error_text()))
    }
}

/// Wraps a `HANDLE`-returning Win32 call, rejecting both `NULL` and
/// `INVALID_HANDLE_VALUE`.
pub fn check_handle(op: impl Into<String>, handle: isize) -> Result<()> {
    const INVALID: isize = -1;
    if handle != 0 && handle != INVALID {
        Ok(())
    } else {
        Err(anyhow!("{} failed: {}", op.into(), last_error_text()))
    }
}

/// Human readable form of the calling thread's last error.
pub fn last_error_text() -> String {
    std::io::Error::from_raw_os_error(last_error_code() as i32).to_string()
}

/// Raw `GetLastError()` for the calling thread.
pub fn last_error_code() -> u32 {
    // SAFETY: `GetLastError` is a leaf call with no preconditions.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

/// RAII wrapper around a Win32 `HANDLE` that closes on drop.
#[derive(Debug)]
pub struct Handle(pub isize);

impl Handle {
    pub fn new(handle: isize) -> Self {
        Self(handle)
    }

    /// Takes ownership of `handle`; a null/`INVALID_HANDLE_VALUE` value becomes
    /// a handle-less (but still usable) wrapper.
    pub fn from_raw(handle: isize) -> Self {
        Self(handle)
    }

    pub fn is_valid(&self) -> bool {
        self.0 != 0 && self.0 != -1
    }

    pub fn as_raw(&self) -> isize {
        self.0
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({:#x})", self.0)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.is_valid() {
            // SAFETY: we own this handle and close it exactly once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0 as _) };
        }
    }
}

/// Adds `GetLastError()` to any `anyhow` error.
pub trait Win32Context<T> {
    fn win32_context(self, op: &str) -> Result<T>;
}

impl<T> Win32Context<T> for Result<T> {
    fn win32_context(self, op: &str) -> Result<T> {
        self.with_context(|| format!("{op}: {}", last_error_text()))
    }
}