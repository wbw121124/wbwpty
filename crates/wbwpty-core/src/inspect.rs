//! Process snapshots used to *prove* the "no console host" claim.
//!
//! The project's entire premise is that a target launched through wbwpty never
//! causes `conhost.exe` to appear. That is not something the code can assert by
//! construction, so it is measured instead: count the console hosts on the
//! machine before and after a session and compare.

use anyhow::Result;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::error::{check_bool, last_error_text, Handle};

/// Total number of processes currently running.
pub fn process_count() -> Result<usize> {
    // SAFETY: the snapshot handle and entry buffer are owned by this function.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = Handle::from_raw(snapshot as isize);
    if !snapshot.is_valid() {
        check_bool("CreateToolhelp32Snapshot", false)?;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut count = 0usize;
    // SAFETY: `snapshot` is live and `entry` is sized for the API.
    let mut ok = unsafe { Process32FirstW(snapshot.as_raw() as _, &mut entry) };
    while ok != 0 {
        count += 1;
        // SAFETY: same handles, `entry` stays sized.
        ok = unsafe { Process32NextW(snapshot.as_raw() as _, &mut entry) };
    }
    Ok(count)
}

/// How many `conhost.exe` processes exist right now.
pub fn conhost_count() -> Result<usize> {
    // SAFETY: as above; the entry buffer lives across the whole walk.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = Handle::from_raw(snapshot as isize);
    if !snapshot.is_valid() {
        return Err(anyhow::anyhow!(
            "CreateToolhelp32Snapshot: {}",
            last_error_text()
        ));
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut conhosts = 0usize;
    // SAFETY: `snapshot` is live; `entry` is correctly sized.
    let mut ok = unsafe { Process32FirstW(snapshot.as_raw() as _, &mut entry) };
    while ok != 0 {
        if name_equals(&entry.szExeFile, "conhost.exe") {
            conhosts += 1;
        }
        // SAFETY: same handles.
        ok = unsafe { Process32NextW(snapshot.as_raw() as _, &mut entry) };
    }
    Ok(conhosts)
}

/// `PROCESSENTRY32W::szExeFile` is a fixed `[u16; MAX_PATH]` that is not NUL
/// terminated in pathological cases.
fn name_equals(buffer: &[u16], expected: &str) -> bool {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let actual: String = String::from_utf16_lossy(&buffer[..end]).to_ascii_lowercase();
    actual == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_processes_and_conhosts() {
        // Both calls must work on a live machine; the values are not asserted
        // because they depend on what else is running.
        assert!(process_count().unwrap() > 0);
        let _ = conhost_count().unwrap();
    }

    #[test]
    fn name_comparison_is_case_insensitive_and_nul_aware() {
        let s: Vec<u16> = "CONHOST.EXE".encode_utf16().collect();
        let mut buf = vec![0u16; s.len() + 1];
        buf[..s.len()].copy_from_slice(&s);
        assert!(name_equals(&buf, "conhost.exe"));

        // A buffer with no NUL must compare its whole contents, not read past.
        let unterminated: Vec<u16> = "con".encode_utf16().collect();
        assert!(!name_equals(&unterminated, "conhost.exe"));
    }
}
