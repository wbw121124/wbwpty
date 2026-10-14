//! Remote process access: memory, allocation and the PEB module list walk.
//!
//! The injector needs to answer three questions about the (still suspended!)
//! target:
//!
//! 1. where is its PEB -> to walk `PEB->Ldr` and learn which DLLs are mapped,
//! 2. can I read/write its memory,
//! 3. which 64 KiB hole can I map the payload into.
//!
//! Offsets below are x64 and are cross checked at runtime; see
//! [`RemoteProcess::walk_modules`] for the validation rules. Sources:
//! `PEB` (Windows Internals / ReactOS `peb.h`), `PEB_LDR_DATA`
//! (`ntdll!LdrpInitializeLoader` usage), `LDR_DATA_TABLE_ENTRY` (same).

use std::ffi::c_void;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{HANDLE, TRUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
};

use crate::error::last_error_text;

// x64 PEB.Ldr. The first four fields are single bytes (InheritedAddressSpace,
// ReadImageFileExecOptions, BeingDebugged, BitField), so the first pointer slot
// sits at 0x08 (Mutant), 0x10 (ImageBaseAddress), 0x18 (Ldr), 0x20
// (ProcessParameters).
const PEB_IMAGE_BASE_OFFSET: u64 = 0x10;
const PEB_LDR_OFFSET: u64 = 0x18;
// x64 PEB_LDR_DATA: Length@0x00 Initialized@0x04 SsHandle@0x08
// InLoadOrderModuleList@0x10 InMemoryOrderModuleList@0x20
// InInitializationOrderModuleList@0x30 EntryInProgress@0x40
const PEB_LDR_IN_MEMORY_ORDER_LIST_OFFSET: u64 = 0x20;
// x64 LDR_DATA_TABLE_ENTRY: InLoadOrderLinks@0x00 InMemoryOrderLinks@0x10
// InInitializationOrderLinks@0x20 DllBase@0x30 EntryPoint@0x38 SizeOfImage@0x40
// FullDllName@0x48 BaseDllName@0x58
const LDR_ENTRY_IN_MEMORY_ORDER_OFFSET: u64 = 0x10;
const LDR_ENTRY_DLL_BASE_OFFSET: u64 = 0x30;
const LDR_ENTRY_SIZE_OF_IMAGE_OFFSET: u64 = 0x40;
const LDR_ENTRY_FULL_DLL_NAME_OFFSET: u64 = 0x48;
const LDR_ENTRY_BASE_DLL_NAME_OFFSET: u64 = 0x58;

/// `PROCESS_INFORMATION_CLASS::ProcessBasicInformation`
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
/// A module name longer than this means we mis-parsed something.
const MAX_NAME_BYTES: usize = 512;
/// Hard cap on the module list walk so a corrupt list cannot spin forever.
const MAX_MODULES: usize = 512;

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    _pad: u32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        h_process: HANDLE,
        info_class: u32,
        info: *mut c_void,
        info_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// One mapped module inside the target.
#[derive(Debug, Clone)]
pub struct RemoteModule {
    pub base: u64,
    pub size: u32,
    pub full_name: String,
    pub base_name: String,
}

impl RemoteModule {
    /// True for forwarder-style API set names, which must be resolved through
    /// the loader rather than a plain file on disk.
    pub fn is_api_set(&self) -> bool {
        let n = self.base_name.to_ascii_lowercase();
        n.starts_with("api-ms-win-") || n.starts_with("ext-ms-win-")
    }
}

/// Where the target's module addresses came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSource {
    /// Walked `PEB->Ldr->InMemoryOrderModuleList` in the target.
    Peb,
    /// Fell back to the host's own mapping, verified against the target.
    ///
    /// A `CREATE_SUSPENDED` process has **not** run `LdrInitializeThunk` yet,
    /// so `PEB->Ldr` is still NULL and there is nothing to walk. That is fine
    /// for the imports every injected payload needs: Windows DLLs are mapped
    /// from a single section object per boot, so `KERNEL32.dll`, `ntdll.dll`,
    /// `msvcrt.dll`, ... live at the *same* address in every process. The
    /// fallback still verifies the address by reading the target's copy of the
    /// MZ header before trusting it.
    HostShared,
}

/// The set of modules available to the importer.
#[derive(Debug)]
pub struct RemoteModules {
    source: ModuleSource,
    modules: Vec<RemoteModule>,
}

impl RemoteModules {
    /// Prefers the PEB walk and falls back to the shared system mapping.
    pub fn discover(proc: &RemoteProcess) -> Result<Self> {
        match proc.walk_modules() {
            Ok(modules) => {
                Ok(Self { source: ModuleSource::Peb, modules })
            }
            Err(peb_error) => {
                // Only the "no loader yet" case is acceptable to fall back
                // from; anything else (implausible links, missing known DLLs)
                // means our offsets are wrong and we must not paper over it.
                if proc.peb_ldr_is_null()? {
                    Ok(Self { source: ModuleSource::HostShared, modules: Vec::new() })
                } else {
                    Err(peb_error)
                }
            }
        }
    }

    pub fn source(&self) -> ModuleSource {
        self.source
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    fn from_peb(&self, name: &str) -> Option<u64> {
        self.modules
            .iter()
            .find(|m| m.base_name.eq_ignore_ascii_case(name))
            .or_else(|| {
                self.modules.iter().find(|m| {
                    m.full_name
                        .rsplit(['\\', '/'])
                        .next()
                        .is_some_and(|f| f.eq_ignore_ascii_case(name))
                })
            })
            .map(|m| m.base)
    }

    /// Resolves a module name to its base address inside the target.
    pub fn base_for_name(&self, proc: &RemoteProcess, name: &str) -> Result<u64> {
        if let Some(base) = self.from_peb(name) {
            return Ok(base);
        }

        let host_base = host_module_base(name);
        if host_base == 0 {
            bail!("module {name} is not mapped in the target and not loadable here");
        }

        // Trust but verify: the target must actually have this image at that
        // address, otherwise a write would corrupt it.
        let magic = proc.read_bytes(host_base, 2)?;
        if &magic != b"MZ" {
            bail!(
                "host base {host_base:#x} for {name} does not map to an image in the target"
            );
        }
        Ok(host_base)
    }
}

/// `GetModuleHandleW` in the host, 0 when the DLL is not loaded here.
fn host_module_base(name: &str) -> u64 {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: NUL terminated; a NULL return simply means "not loaded".
    unsafe { windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(wide.as_ptr()) as u64 }
}

/// Borrowed handle to a foreign (suspended) process.
#[derive(Clone, Copy)]
pub struct RemoteProcess {
    handle: HANDLE,
}

impl RemoteProcess {
    pub fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Reads `len` bytes from the target at `addr`.
    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        // SAFETY: `addr` comes from structures we parsed out of the target's
        // own address space; failures are reported through the return value.
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut got,
            )
        };
        if ok == 0 || got != len {
            bail!("ReadProcessMemory({addr:#x}, {len}) failed: {}", last_error_text());
        }
        Ok(buf)
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let b = self.read_bytes(addr, 8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        let b = self.read_bytes(addr, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Writes `data` to `addr`; short writes are a hard error because a
    /// half-written image would crash the target.
    pub fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<()> {
        let mut written = 0usize;
        // SAFETY: `addr` is a freshly reserved region in the target.
        let ok = unsafe {
            WriteProcessMemory(
                self.handle,
                addr as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                &mut written,
            )
        };
        if ok == 0 || written != data.len() {
            bail!(
                "WriteProcessMemory({addr:#x}, {}) failed ({written} written): {}",
                data.len(),
                last_error_text()
            );
        }
        Ok(())
    }

    /// Reserves and commits `size` bytes anywhere in the target.
    pub fn allocate(&self, size: usize) -> Result<u64> {
        // SAFETY: null hint lets the allocator choose; target is a live handle.
        let p = unsafe {
            VirtualAllocEx(
                self.handle,
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if p.is_null() {
            bail!("VirtualAllocEx({size}) failed: {}", last_error_text());
        }
        Ok(p as u64)
    }

    /// True when `[addr, addr+size)` is unclaimed, which is what lets us try
    /// the preferred image base first and avoid relocating at all.
    pub fn is_range_free(&self, addr: u64, size: u64) -> bool {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `mbi` is a live, correctly sized out parameter.
        let got = unsafe {
            VirtualQueryEx(
                self.handle,
                addr as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if got != std::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
            return false;
        }
        if mbi.State != MEM_FREE {
            return false;
        }
        let region_start = mbi.BaseAddress as u64;
        let region_end = region_start + mbi.RegionSize as u64;
        addr >= region_start && addr + size <= region_end
    }

    /// Address of the target's PEB.
    pub fn peb(&self) -> Result<u64> {
        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        // SAFETY: `pbi` is a live out buffer of the exact class size.
        let status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut returned,
            )
        };
        if status != 0 {
            bail!("NtQueryInformationProcess failed: NTSTATUS {status:#x}");
        }
        if returned as usize != std::mem::size_of::<ProcessBasicInformation>() {
            bail!(
                "NtQueryInformationProcess returned {returned} bytes, expected {}",
                std::mem::size_of::<ProcessBasicInformation>()
            );
        }
        if pbi.peb_base_address.is_null() {
            bail!("target reported a null PEB (already terminated?)");
        }
        Ok(pbi.peb_base_address as u64)
    }

    /// Walks `PEB->Ldr->InMemoryOrderModuleList`.
    ///
    /// Every list node is validated before it is followed, so a bogus link can
    /// only produce an error - never an infinite loop or a wild read.
    pub fn walk_modules(&self) -> Result<Vec<RemoteModule>> {
        let peb = self.peb()?;
        let ldr = self.read_u64(peb + PEB_LDR_OFFSET).context("reading PEB->Ldr")?;
        let head = ldr + PEB_LDR_IN_MEMORY_ORDER_LIST_OFFSET;
        let first = self.read_u64(head).context("reading InMemoryOrderModuleList.Flink")?;

        let mut modules = Vec::with_capacity(64);
        let mut node = first;
        let mut previous = head;
        let mut iterations = 0usize;

        while node != head {
            if node < 0x1000 || !is_canonical(node) {
                bail!("module list link {node:#x} is not a plausible address");
            }
            let entry = node - LDR_ENTRY_IN_MEMORY_ORDER_OFFSET;
            let base = self.read_u64(entry + LDR_ENTRY_DLL_BASE_OFFSET)?;
            if !is_canonical(base) {
                bail!("module {entry:#x} has implausible DllBase {base:#x}");
            }
            let size = self.read_u32(entry + LDR_ENTRY_SIZE_OF_IMAGE_OFFSET)?;
            let full_name = self.read_unicode_string(entry + LDR_ENTRY_FULL_DLL_NAME_OFFSET)?;
            let base_name = self.read_unicode_string(entry + LDR_ENTRY_BASE_DLL_NAME_OFFSET)?;

            modules.push(RemoteModule { base, size, full_name, base_name });

            let blink = self.read_u64(node + 8)?;
            if blink != previous {
                bail!("module list is not doubly linked at {node:#x} (blink {blink:#x})");
            }
            let next = self.read_u64(node)?;
            if next == node {
                bail!("module list is self-referential at {node:#x}");
            }
            previous = node;
            node = next;

            iterations += 1;
            if iterations >= MAX_MODULES {
                bail!("module list exceeded {MAX_MODULES} entries");
            }
        }

        if modules.is_empty() {
            bail!("module list walk produced nothing");
        }
        // A correct walk always contains these two; use it as the sanity check.
        let has_ntdll = modules.iter().any(|m| m.base_name.eq_ignore_ascii_case("ntdll.dll"));
        let has_kernel32 =
            modules.iter().any(|m| m.base_name.eq_ignore_ascii_case("kernel32.dll"));
        if !has_ntdll || !has_kernel32 {
            bail!("PEB walk is missing ntdll.dll/kernel32.dll; offsets look wrong");
        }
        Ok(modules)
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let b = self.read_bytes(addr, 4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// True when the target's PEB exists but the loader has not run yet, which
    /// is the normal state of a `CREATE_SUSPENDED` process.
    pub fn peb_ldr_is_null(&self) -> Result<bool> {
        let peb = self.peb()?;
        Ok(self.read_u64(peb + PEB_LDR_OFFSET)? == 0)
    }

    /// `PEB->ImageBaseAddress`: where the loader mapped the executable itself.
    /// Available even while the process is suspended, because the kernel does
    /// that mapping inside `NtCreateUserProcess`.
    pub fn image_base(&self) -> Result<u64> {
        let peb = self.peb()?;
        self.read_u64(peb + PEB_IMAGE_BASE_OFFSET)
    }

    /// Reserves `size` bytes as close to `near` as possible.
    ///
    /// The entry dispatcher jumps to the target's entry point with a `rel32`, so
    /// it has to live within ±2 GiB of it; `VirtualAllocEx` honours the hint on
    /// a best-effort basis.
    pub fn allocate_near(&self, near: u64, size: usize) -> Result<u64> {
        const STEP: u64 = 0x1000;
        for i in 0..0x1000u64 {
            for delta in [0i64, -(i as i64) * STEP as i64, (i as i64) * STEP as i64] {
                if i == 0 && delta != 0 {
                    continue;
                }
                let candidate = (near as i64 + delta) as u64;
                if !is_canonical(candidate) {
                    continue;
                }
                // SAFETY: hint address, target handle; a null return means the
                // hint was unusable and we try the next candidate.
                let p = unsafe {
                    VirtualAllocEx(
                        self.handle,
                        candidate as *mut c_void,
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    )
                };
                if !p.is_null() {
                    return Ok(p as u64);
                }
            }
        }
        bail!("could not allocate {size} bytes near {near:#x}: {}", last_error_text())
    }

    /// Reads a `UNICODE_STRING` (Length@0x00, MaximumLength@0x04, Buffer@0x08).
    fn read_unicode_string(&self, addr: u64) -> Result<String> {
        let length = self.read_u16(addr)? as usize;
        if length > MAX_NAME_BYTES || length % 2 != 0 {
            bail!("implausible UNICODE_STRING length {length} at {addr:#x}");
        }
        let buffer = self.read_u64(addr + 8)?;
        if length == 0 {
            return Ok(String::new());
        }
        if !is_canonical(buffer) {
            bail!("implausible UNICODE_STRING buffer {buffer:#x}");
        }
        let raw = self.read_bytes(buffer, length)?;
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

fn is_canonical(addr: u64) -> bool {
    // x64 user space canonical form: bits 63..48 must all match bit 47.
    let high = addr >> 48;
    high == 0 || high == 0xffff
}

/// Builds a `BOOL` for APIs that return `TRUE`/`FALSE`.
pub fn true_bool() -> i32 {
    TRUE
}