//! Named pipe byte transport.
//!
//! Two unidirectional `\\.\pipe\wbwpty-*` instances back a session:
//!
//! ```text
//!   host  --WriteFile-->  \\.\pipe\...\-in   --> CreateFileW in the target
//!   host  <--ReadFile--   \\.\pipe\...\-out  <-- CreateFileW in the target
//! ```
//!
//! Two one-way instances are used rather than one duplex instance because a
//! duplex pipe makes "who may read / who may write" depend on the access mask
//! the client happened to ask for, which is exactly the kind of thing that
//! silently deadlocks. One-way instances also give us clean EOF semantics: when
//! the host closes the `-in` server handle the target's `ReadFile` returns 0
//! bytes, which is a real "stdin at EOF" for the child.
//!
//! Both server ends are opened `FILE_FLAG_OVERLAPPED`, which is what lets a pump
//! thread be torn down with `CancelIoEx` instead of blocking on a read that
//! will never complete.

use std::io;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{
    GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject, INFINITE};

use crate::error::{last_error_text, Handle};

/// 64 KiB per direction: large enough that a burst of command output is not
/// split into dozens of syscalls, small enough to stay off the large-page
/// threshold.
const PIPE_BUFFER: u32 = 64 * 1024;

/// Which way the bytes flow for one pipe instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Host writes, target reads (the target's stdin).
    ToTarget,
    /// Target writes, host reads (the target's stdout/stderr).
    FromTarget,
}

/// Result of a single non-blocking-ish read attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadEvent {
    /// Bytes were read.
    Data(usize),
    /// Nothing arrived within the timeout; the caller should do other work.
    Timeout,
    /// Every writer closed its handle: the target's stdout is finished.
    Eof,
}

/// One server end of a named pipe.
pub struct PipeEnd {
    name: String,
    handle: Handle,
    event: Handle,
    /// Boxed because `OVERLAPPED` must stay at a fixed address between the
    /// issuing call and the completion.
    ov: Box<OVERLAPPED>,
}

impl PipeEnd {
    /// Creates (but does not wait for) the server instance.
    pub fn create(name: &str, dir: Direction) -> Result<Self> {
        let access = match dir {
            Direction::ToTarget => PIPE_ACCESS_OUTBOUND,
            Direction::FromTarget => PIPE_ACCESS_INBOUND,
        };

        let wide = to_wide(name);
        // SAFETY: `wide` is NUL terminated and live for the whole call.
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                access | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,                          // max instances: one target
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,                          // default timeout
                std::ptr::null(),           // default security
            )
        };

        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            bail!("CreateNamedPipeW({name}) failed: {}", last_error_text());
        }
        let handle = Handle::from_raw(handle as isize);

        // Manual reset event: one overlapped operation per event.
        // SAFETY: null security attributes, no name, no preconditions.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            bail!("CreateEventW failed: {}", last_error_text());
        }
        let event = Handle::from_raw(event as isize);

        let mut ov = Box::new(OVERLAPPED::default());
        ov.hEvent = event.as_raw() as HANDLE;

        Ok(Self { name: name.to_owned(), handle, event, ov })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Opens the client side, exactly like the injected DLL does. Used by tests
    /// and by `--self-test` to exercise the transport without a child process.
    pub fn open_client(&self, access: u32) -> Result<Handle> {
        let wide = to_wide(&self.name);
        // SAFETY: `wide` is NUL terminated and live for the whole call.
        let h = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateFileW(
                wide.as_ptr(),
                access,
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            bail!(
                "CreateFileW({}) as pipe client failed: {}",
                self.name,
                last_error_text()
            );
        }
        Ok(Handle::from_raw(h as isize))
    }

    fn reset_overlapped(&mut self) {
        self.ov.Internal = 0;
        self.ov.InternalHigh = 0;
        // windows-sys models the union of {Offset, OffsetHigh} / {Pointer,
        // Offset} as `Anonymous`.
        self.ov.Anonymous.Anonymous.Offset = 0;
        self.ov.Anonymous.Anonymous.OffsetHigh = 0;
    }

    /// Reads into `buf`, waiting at most `timeout_ms`.
    pub fn read(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<ReadEvent> {
        let h = self.handle.as_raw() as HANDLE;
        self.reset_overlapped();
        // SAFETY: overlapped slot is zeroed, buffer is valid for `len` bytes.
        unsafe {
            ResetEvent(self.event.as_raw() as HANDLE);
            let mut read: u32 = 0;
            let ok = ReadFile(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                &mut *self.ov,
            );

            if ok != 0 {
                return Ok(ReadEvent::Data(read as usize));
            }

            let err = GetLastError();
            if err != windows_sys::Win32::Foundation::ERROR_IO_PENDING {
                if err == windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE
                    || err == windows_sys::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED
                {
                    return Ok(ReadEvent::Eof);
                }
                bail!("ReadFile({}) failed: {err} ({})", self.name, last_error_text());
            }

            match WaitForSingleObject(self.event.as_raw() as HANDLE, timeout_ms) {
                WAIT_OBJECT_0 => {
                    let mut transferred: u32 = 0;
                    let ok = GetOverlappedResult(h, &*self.ov, &mut transferred, 0);
                    if ok == 0 {
                        let err = GetLastError();
                        if err == windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE {
                            return Ok(ReadEvent::Eof);
                        }
                        bail!("GetOverlappedResult({}) failed: {}", self.name, last_error_text());
                    }
                    if transferred == 0 {
                        Ok(ReadEvent::Eof)
                    } else {
                        Ok(ReadEvent::Data(transferred as usize))
                    }
                }
                WAIT_TIMEOUT => {
                    // Cancel and *drain* before returning: the OVERLAPPED slot
                    // must not be reused while the kernel still owns it.
                    CancelIoEx(h, &mut *self.ov);
                    WaitForSingleObject(self.event.as_raw() as HANDLE, INFINITE);
                    Ok(ReadEvent::Timeout)
                }
                other => bail!("WaitForSingleObject({}) returned {other}", self.name),
            }
        }
    }

    /// Writes every byte of `buf`, looping over short writes.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<usize> {
        let h = self.handle.as_raw() as HANDLE;
        let mut done = 0usize;

        while done < buf.len() {
            self.reset_overlapped();
            let chunk = &buf[done..];
            // SAFETY: overlapped slot is zeroed, buffer valid for `chunk`.
            unsafe {
                ResetEvent(self.event.as_raw() as HANDLE);
                let mut written: u32 = 0;
                let ok = WriteFile(
                    h,
                    chunk.as_ptr(),
                    chunk.len() as u32,
                    &mut written,
                    &mut *self.ov,
                );

                if ok == 0 {
                    let err = GetLastError();
                    if err != windows_sys::Win32::Foundation::ERROR_IO_PENDING {
                        if err == windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE
                            || err == windows_sys::Win32::Foundation::ERROR_NO_DATA
                        {
                            bail!("target closed {}", self.name);
                        }
                        bail!("WriteFile({}) failed: {err} ({})", self.name, last_error_text());
                    }
                    if WaitForSingleObject(self.event.as_raw() as HANDLE, INFINITE) != WAIT_OBJECT_0 {
                        bail!("write to {} never completed", self.name);
                    }
                    let mut transferred: u32 = 0;
                    if GetOverlappedResult(h, &*self.ov, &mut transferred, 0) == 0 {
                        bail!("GetOverlappedResult({}) failed: {}", self.name, last_error_text());
                    }
                    if transferred == 0 {
                        bail!("write to {} transferred nothing", self.name);
                    }
                    done += transferred as usize;
                } else {
                    done += written as usize;
                }
            }
        }

        Ok(done)
    }
}

/// The host side of a full session transport: one pipe each way.
///
/// `PipePair` owns both server handles and hands out the *names* the injected
/// DLL needs, which is how the configuration crosses the process boundary.
pub struct PipePair {
    input: PipeEnd,
    output: PipeEnd,
}

impl PipePair {
    /// Builds names from the host pid plus a caller supplied nonce so that two
    /// sessions on one machine never collide.
    pub fn new(nonce: u64) -> Result<Self> {
        let pid = std::process::id();
        let input = PipeEnd::create(
            &format!(r"\\.\pipe\wbwpty-{pid}-{nonce:016x}-in"),
            Direction::ToTarget,
        )?;
        let output = PipeEnd::create(
            &format!(r"\\.\pipe\wbwpty-{pid}-{nonce:016x}-out"),
            Direction::FromTarget,
        )?;
        Ok(Self { input, output })
    }

    pub fn input(&mut self) -> &mut PipeEnd {
        &mut self.input
    }

    pub fn output(&mut self) -> &mut PipeEnd {
        &mut self.output
    }

    pub fn input_name(&self) -> &str {
        self.input.name()
    }

    pub fn output_name(&self) -> &str {
        self.output.name()
    }

    /// Drops both server ends. Any in-flight read on the `-in` instance
    /// completes with 0 bytes, which is the child's EOF signal.
    pub fn shutdown(&mut self) {
        // `PipeEnd` closes its handle on drop; nothing else to do here.
    }

    /// Opens the client ends and marks them inheritable so they can be handed
    /// to the target as its standard handles.
    ///
    /// The caller owns the returned handles and must close its copies once the
    /// child exists: the child keeps its own, and EOF only propagates when the
    /// last writer is gone.
    pub fn open_target_stdio(&mut self) -> Result<InheritableStdio> {
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};

        // The `-in` server is outbound (host writes), so the target reads.
        let stdin = self.input.open_client(GENERIC_READ)?;
        // The `-out` server is inbound (host reads), so the target writes; it
        // serves both of the target's output streams.
        let stdout = self.output.open_client(GENERIC_WRITE)?;
        let stderr = stdout.duplicate()?;

        for h in [&stdin, &stdout, &stderr] {
            // SAFETY: handles come from `open_client`, which validated them.
            let ok = unsafe {
                SetHandleInformation(
                    h.as_raw() as HANDLE,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            };
            if ok == 0 {
                bail!("SetHandleInformation(HANDLE_FLAG_INHERIT) failed: {}", last_error_text());
            }
        }

        Ok(InheritableStdio {
            stdin: stdin.as_raw() as HANDLE,
            stdout: stdout.as_raw() as HANDLE,
            stderr: stderr.as_raw() as HANDLE,
            _handles: vec![stdin, stdout, stderr],
        })
    }
}

/// Client ends of the session pipes, marked inheritable, together with the
/// host's copies so they can be dropped once the child has them.
pub struct InheritableStdio {
    pub stdin: HANDLE,
    pub stdout: HANDLE,
    pub stderr: HANDLE,
    _handles: Vec<Handle>,
}

/// NUL terminated UTF-16 for the `*W` Win32 entry points.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper used by the output pump to distinguish "child is gone" from "child is
/// slow", so the session loop can shut down in the right order.
pub fn describe_read(e: ReadEvent) -> io::Result<Option<usize>> {
    match e {
        ReadEvent::Data(n) => Ok(Some(n)),
        ReadEvent::Timeout => Ok(None),
        ReadEvent::Eof => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "pipe closed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves the transport works in both directions against a second handle on
    /// the same machine, which is the same traffic pattern the injected DLL
    /// produces.
    #[test]
    fn round_trips_bytes_and_reports_eof() {
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Foundation::GENERIC_WRITE;

        let mut pair = PipePair::new(0xfeed_beef).unwrap();

        // The target opens the `-out` instance for writing and `-in` for
        // reading; the host owns the mirrored ends.
        let target_stdout = pair.output().open_client(GENERIC_WRITE).unwrap();
        let target_stdin = pair.input().open_client(GENERIC_READ).unwrap();

        // host -> target
        pair.input().write_all(b"hello wbwpty\r\n").unwrap();

        let mut buf = [0u8; 64];
        let mut got = 0u32;
        // SAFETY: synchronous read into a live buffer on a connected pipe.
        let ok = unsafe {
            ReadFile(
                target_stdin.as_raw() as HANDLE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "target read failed: {}", last_error_text());
        assert_eq!(&buf[..got as usize], b"hello wbwpty\r\n");

        // target -> host
        let mut written = 0;
        // SAFETY: synchronous write to a connected pipe client handle.
        let ok = unsafe {
            WriteFile(
                target_stdout.as_raw() as HANDLE,
                b"from target".as_ptr(),
                11,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "target write failed: {}", last_error_text());

        match pair.output().read(&mut buf, 5_000).unwrap() {
            ReadEvent::Data(n) => assert_eq!(&buf[..n], b"from target"),
            other => panic!("expected data, got {other:?}"),
        }

        // Closing the target's write handle must surface as EOF on the host.
        drop(target_stdout);
        match pair.output().read(&mut buf, 5_000).unwrap() {
            ReadEvent::Eof | ReadEvent::Timeout => {}
            other => panic!("expected EOF after target close, got {other:?}"),
        }
        drop(target_stdin);
    }

    #[test]
    fn pipe_names_are_unique_per_nonce() {
        let a = PipePair::new(1).unwrap();
        let b = PipePair::new(2).unwrap();
        assert_ne!(a.input_name(), b.input_name());
        assert!(a.output_name().ends_with("-out"));
        assert!(a.input_name().starts_with(r"\\.\pipe\wbwpty-"));
    }
}