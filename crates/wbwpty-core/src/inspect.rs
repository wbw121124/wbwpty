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

/// Live `conhost.exe` processes as `(pid, parent pid)`.
///
/// The `conhost.exe` a console gets is spawned as a child of the process that
/// owns the console, so the parent is what makes the difference between "this
/// process tree caused a console host" and "the machine already had one".
/// Counting alone cannot tell those apart: a test harness runs inside a console,
/// and a machine with anything else running moves the count for unrelated
/// reasons. Measured against a short-lived child it is worse than useless - the
/// child is often gone before the "after" count is taken, and the delta is a
/// coin flip.
pub fn conhost_parents() -> Result<Vec<(u32, u32)>> {
    // SAFETY: the snapshot handle and entry buffer are owned by this function.
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

    let mut hosts = Vec::new();
    // SAFETY: `snapshot` is live; `entry` is correctly sized.
    let mut ok = unsafe { Process32FirstW(snapshot.as_raw() as _, &mut entry) };
    while ok != 0 {
        if name_equals(&entry.szExeFile, "conhost.exe") {
            hosts.push((entry.th32ProcessID, entry.th32ParentProcessID));
        }
        // SAFETY: same handles.
        ok = unsafe { Process32NextW(snapshot.as_raw() as _, &mut entry) };
    }
    Ok(hosts)
}

/// One row of the process table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    /// `th32ParentProcessID`. This is a *pid*, not a handle, and it is the
    /// parent as the loader recorded it, which is what makes ancestry walking
    /// possible at all.
    pub parent: u32,
    pub name: String,
}

/// A snapshot of every process currently running.
///
/// Needed where counting cannot answer the question. `conhost_count()` cannot
/// distinguish "this tree caused a console host" from "the machine already had
/// one", and a descendant that is gone before the second sample takes the
/// delta with it. Ancestry does not have either problem: the console host is
/// always a child of the process that owns the console, and it is sampled
/// while it is still alive.
pub fn process_table() -> Result<Vec<ProcessEntry>> {
    // SAFETY: the snapshot handle and entry buffer are owned by this function.
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

    let mut table = Vec::new();
    // SAFETY: `snapshot` is live; `entry` is correctly sized.
    let mut ok = unsafe { Process32FirstW(snapshot.as_raw() as _, &mut entry) };
    while ok != 0 {
        let end = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        table.push(ProcessEntry {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            name: String::from_utf16_lossy(&entry.szExeFile[..end]).to_ascii_lowercase(),
        });
        // SAFETY: same handles.
        ok = unsafe { Process32NextW(snapshot.as_raw() as _, &mut entry) };
    }
    Ok(table)
}

/// Every pid in `table` whose ancestry reaches `root`, `root` itself included.
///
/// Repeated passes rather than a single reverse walk: a snapshot is unordered,
/// so a grandchild can appear before its parent in the list and one pass would
/// miss it. Passes are bounded by the depth cap, which also terminates on a
/// cycle - `th32ParentProcessID` is a pid and pids are reused, so a malformed
/// table really can contain one.
pub fn descendants_of(table: &[ProcessEntry], root: u32) -> Vec<u32> {
    let mut found = std::collections::BTreeSet::new();
    found.insert(root);
    // A process tree is not deep; 64 is far past any chain this produces.
    for _ in 0..64 {
        let before = found.len();
        for entry in table {
            if found.contains(&entry.parent) {
                found.insert(entry.pid);
            }
        }
        if found.len() == before {
            break;
        }
    }
    found.into_iter().collect()
}

/// Distance from `root` to `pid` along parent links; `root` itself is 0.
///
/// Teardown needs this and nothing else will do: children have to die before
/// their parents, or a parent that exits first reparents them to something
/// unrelated and they drop out of the ancestry the walk is based on. That is
/// how a "we cleaned up after ourselves" loop ends up leaving processes behind.
pub fn ancestry_depth(table: &[ProcessEntry], root: u32, pid: u32) -> Option<usize> {
    let parent_of = |p: u32| table.iter().find(|e| e.pid == p).map(|e| e.parent);

    let mut current = pid;
    for depth in 0..64usize {
        if current == root {
            return Some(depth);
        }
        current = parent_of(current)?;
    }
    None
}

/// `conhost.exe` processes among `root`'s descendants.
///
/// The attribution this project needs: a console host shows up as a child of
/// the process that owns the console, so walking up from each host is what ties
/// it to the tree under test rather than to the rest of the machine.
pub fn descendant_console_hosts(table: &[ProcessEntry], root: u32) -> Vec<ProcessEntry> {
    let mine: std::collections::HashSet<u32> = descendants_of(table, root).into_iter().collect();
    table
        .iter()
        .filter(|e| e.name == "conhost.exe" && mine.contains(&e.pid))
        .cloned()
        .collect()
}

/// Terminates a process by pid, so a test can clean up after a fixture that
/// deliberately spawns something.
///
/// Exists because the fixtures here spawn children on purpose, and a child that
/// got a console of its own leaves a visible `conhost.exe` window behind it.
/// That is the very thing the project exists to prevent, so a test that provokes
/// it has to be the one to take it down again.
pub fn terminate(pid: u32) -> Result<bool> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    // SAFETY: `PROCESS_TERMINATE` is the only access requested and the returned
    // handle is closed before returning.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return Ok(false);
    }
    let handle = Handle::from_raw(handle as isize);
    // SAFETY: the handle was just opened with terminate access.
    let ok = unsafe { TerminateProcess(handle.as_raw() as HANDLE, 0) } != 0;
    Ok(ok)
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

    fn entry(pid: u32, parent: u32, name: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            parent,
            name: name.to_ascii_lowercase(),
        }
    }

    /// Ancestry has to survive the snapshot's arbitrary order, and it has to
    /// survive a pid that is its own ancestor.
    ///
    /// Both are real on Windows: `Process32First/Next` makes no ordering
    /// promise, and `th32ParentProcessID` is a pid, so a reused one can point
    /// at a process that no longer exists. A single-pass walk gets the first
    /// case wrong; an unbounded one hangs on the second.
    #[test]
    fn ancestry_survives_unordered_and_cyclic_tables() {
        let table = vec![
            entry(30, 20, "conhost.exe"),
            entry(10, 1, "cmd.exe"),
            entry(20, 10, "cmd.exe"),
            entry(5, 5, "cmd.exe"),
        ];

        // Grandchild before parent in the list, so one reverse pass misses it.
        assert_eq!(descendants_of(&table, 10), vec![10, 20, 30]);

        // A pid that is its own ancestor must terminate, not spin.
        assert_eq!(descendants_of(&table, 5), vec![5]);

        let hosts = descendant_console_hosts(&table, 10);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].pid, 30);

        // Someone else's tree contributes nothing.
        assert!(descendant_console_hosts(&table, 999).is_empty());
    }

    /// The live machine, sampled for real: ancestry from our own pid has to
    /// include this process.
    #[test]
    fn the_live_table_agrees_with_our_own_pid() {
        let table = process_table().expect("process table");
        assert!(table.iter().any(|e| e.pid == std::process::id()));
        assert!(descendants_of(&table, std::process::id()).contains(&std::process::id()));
    }

    /// Depth is what orders a teardown, and a cycle must not hang it.
    #[test]
    fn depth_counts_generations_and_gives_up_on_cycles() {
        let table = vec![
            entry(10, 1, "cmd.exe"),
            entry(20, 10, "cmd.exe"),
            entry(30, 20, "ping.exe"),
            entry(99, 1, "conhost.exe"),
            entry(7, 7, "cmd.exe"),
        ];
        assert_eq!(ancestry_depth(&table, 10, 10), Some(0));
        assert_eq!(ancestry_depth(&table, 10, 20), Some(1));
        assert_eq!(ancestry_depth(&table, 10, 30), Some(2));
        assert_eq!(ancestry_depth(&table, 10, 99), None);
        assert_eq!(ancestry_depth(&table, 7, 7), Some(0));
    }
}
