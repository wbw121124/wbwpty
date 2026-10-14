//! Manual PE mapping into a suspended process.
//!
//! `LoadLibrary` into a process whose loader never ran is a gamble: the loader
//! lock, the process heap and the API set maps may all be uninitialised. This
//! module sidesteps the loader entirely:
//!
//! ```text
//!   host                                   target (still suspended)
//!   ----                                   ---------------------------
//!   parse PE + relocate                    (nothing has executed yet)
//!   VirtualAllocEx + WriteProcessMemory ---> image at `base`
//!   resolve every import through the PEB ---> (needs no target code)
//!   CreateRemoteThread(stub) --------------> patch IATs, call DllMain
//! ```
//!
//! Everything except the last 10 instructions is done and tested on the host
//! side; the target-side stub lives in [`stub`].

pub mod exports;
pub mod pe;
pub mod remote;
pub mod stub;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::child::Child;

pub use pe::PeImage;
pub use remote::{ModuleSource, RemoteModule, RemoteModules, RemoteProcess};

/// What the injector did, for logging and for tests.
#[derive(Debug, Clone)]
pub struct InjectionReport {
    /// Address the image was mapped at in the target.
    pub image_base: u64,
    /// RVA of the entry point that was called.
    pub entry_rva: u32,
    /// Number of IAT slots patched.
    pub patch_count: usize,
    /// Distance between the preferred base and the mapped one.
    pub reloc_delta: i64,
    /// Modules discovered (see [`ModuleSource`] for how).
    pub module_count: usize,
    /// Whether addresses came from the target PEB or the shared system map.
    pub module_source: ModuleSource,
}

/// Maps `dll` into `child` and calls its exported `DllMain`.
///
/// `entry_symbol` defaults to `DllMain`. When the DLL exports it we call that
/// export directly instead of the PE entry point: the Rust `cdylib` entry
/// (`DllMainCRTStartup`, from mingw) expects an initialised C runtime, which a
/// manually mapped image has not had.
pub fn inject_dll(child: &Child, dll: &Path, entry_symbol: &str) -> Result<InjectionReport> {
    let file = std::fs::read(dll)
        .with_context(|| format!("reading redirect DLL {}", dll.display()))?;
    inject_bytes(child, &file, entry_symbol)
}

/// [`inject_dll`] for an in-memory image.
pub fn inject_bytes(child: &Child, image: &[u8], entry_symbol: &str) -> Result<InjectionReport> {
let proc = RemoteProcess::new(child.process_handle());
    let pe = PeImage::parse(image)?;
    if !pe.info.is_dll {
        bail!("{} is not a DLL (IMAGE_FILE_DLL is not set)", child_image_hint(image));
    }
    let entry_rva = resolve_entry_rva(&pe, image, entry_symbol)?;

    // Arm the dispatcher, then let the loader run: it stops at our patched
    // entry point with a fully populated PEB, which is the only moment where
    // import resolution can be trusted.
    let trap = EntryTrap::arm(&proc, child)?;
    let outcome = (|| -> Result<InjectionReport> {
        child.resume()?;
        trap.wait_until_armed(std::time::Duration::from_secs(15))?;

        let modules = RemoteModules::discover(&proc)?;
        let (base, reloc_delta) = allocate_image(&proc, &pe)?;
        let mut mapped = pe.map(reloc_delta)?;
        // Imports are written straight into the mapped image, so the payload is
        // fully self-contained by the time `DllMain` is called and no runtime
        // patch loop is needed.
        let patch_count = resolve_imports(&proc, &modules, &pe, &mut mapped)?;
        proc.write_bytes(base, &mapped)?;
        trap.release(base + entry_rva as u64);

        Ok(InjectionReport {
            image_base: base,
            entry_rva,
            patch_count,
            reloc_delta,
            module_count: modules.len(),
            module_source: modules.source(),
        })
    })();

    match outcome {
        Ok(report) => Ok(report),
        Err(err) => {
            // Never leave the target spinning in the dispatcher: release it
            // with a no-op entry point, then restore the original bytes.
            trap.abort();
            Err(err)
        }
    }
}

/// The in-target rendezvous used to inject before any user code runs.
struct EntryTrap {
    proc: RemoteProcess,
    slot_addr: u64,
    /// Address of the `ret` used as a null entry point when something fails.
    null_init: u64,
    oep_addr: u64,
    original: [u8; 8],
}

impl EntryTrap {
    /// Patches the target's entry point to jump into a dispatcher that waits
    /// for [`Self::release`].
    fn arm(proc: &RemoteProcess, child: &Child) -> Result<Self> {
        let image_base = proc.image_base()?;
        // The entry RVA comes from the executable's own PE header on disk; the
        // kernel always honours `AddressOfEntryPoint`.
        let exe_bytes = std::fs::read(&child.image)
            .with_context(|| format!("reading {}", child.image.display()))?;
let exe = PeImage::parse(&exe_bytes)?;
        let oep = image_base + exe.info.entry_rva as u64;

        let original: [u8; 8] = proc.read_bytes(oep, 8)?.try_into().expect("8 bytes");
        // Refuse to arm if something already looks like a jump or padding.
        if original[0] == 0xe9 || original[..2] == [0xff, 0x25] {
            bail!("entry point {oep:#x} already starts with a jump; refusing to patch");
        }

        let code = stub::build_entry_dispatcher(0); // placeholder, real displacement below
        let size = stub::SLOT_SIZE + code.len() + 1;
        let slot_addr = proc.allocate_near(oep, size)?;
        let code_addr = slot_addr + stub::SLOT_SIZE as u64;

        // `lea r11, [rip+disp]` is 7 bytes and RIP is the following instruction.
        let disp = (slot_addr as i64 - (code_addr + 7) as i64) as i32;
        let code = stub::build_entry_dispatcher(disp);

        let mut slot = vec![0u8; stub::SLOT_SIZE];
        slot[stub::SLOT_READY..stub::SLOT_READY + 8].copy_from_slice(&0u64.to_le_bytes());
        slot[stub::SLOT_OEP..stub::SLOT_OEP + 8].copy_from_slice(&oep.to_le_bytes());
        slot[stub::SLOT_OEP_BYTES..stub::SLOT_OEP_BYTES + 8]
            .copy_from_slice(&u64::from_le_bytes(original).to_le_bytes());

        proc.write_bytes(slot_addr, &slot)?;
        proc.write_bytes(code_addr, &code)?;
        proc.write_bytes(code_addr + code.len() as u64, &[0xc3])?; // null entry point

        let patch = stub::build_entry_patch(code_addr, oep)
            .ok_or_else(|| anyhow::anyhow!("dispatcher at {code_addr:#x} is out of rel32 range"))?;
        proc.write_bytes(oep, &patch)?;

        Ok(Self {
            proc: RemoteProcess::new(proc.handle()),
            slot_addr,
            null_init: code_addr + code.len() as u64,
            oep_addr: oep,
            original,
        })
    }

/// Blocks until the target's loader reaches the patched entry point.
    fn wait_until_armed(&self, timeout: std::time::Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let ready = self
                .proc
                .read_bytes(self.slot_addr + stub::SLOT_READY as u64, 8)?;
            if u64::from_le_bytes(ready.try_into().expect("8 bytes")) != 0 {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                let oep_now = self.proc.read_bytes(self.oep_addr, 8).unwrap_or_default();
                let mut exit = 0u32;
                // SAFETY: live handle and out parameter; failure is ignored.
                let ok = unsafe {
                    windows_sys::Win32::System::Threading::GetExitCodeProcess(
                        self.proc.handle(),
                        &mut exit,
                    )
                };
                bail!(
                    "target never reached its entry point (oep {:#x} now {:02x?}, \
                     process exit code {ok}/{exit:#x}, slot {:#x})",
                    self.oep_addr,
                    oep_now,
                    self.slot_addr
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Hands the payload to the dispatcher: it restores the entry point, calls
    /// `DllMain` and continues to the original code.
    fn release(&self, init_address: u64) {
        self.write_slot(stub::SLOT_DLL_BASE, init_address);
        self.write_slot(stub::SLOT_DLL_INIT, init_address);
        // `ready` last: it is the release flag.
        self.write_slot(stub::SLOT_READY, 1);
    }

    /// Fails safely: lets the target continue with a no-op entry point and
    /// restores the bytes at the entry point.
    fn abort(&self) {
        self.write_slot(stub::SLOT_DLL_BASE, self.null_init);
        self.write_slot(stub::SLOT_DLL_INIT, self.null_init);
        self.write_slot(stub::SLOT_READY, 1);
        let _ = self.proc.write_bytes(self.oep_addr, &self.original);
    }

    fn write_slot(&self, offset: usize, value: u64) {
        let _ = self.proc.write_bytes(
            self.slot_addr + offset as u64,
            &value.to_le_bytes(),
        );
    }
}

/// Picks the mapped base, preferring the image's own base address.
fn allocate_image(proc: &RemoteProcess, pe: &PeImage) -> Result<(u64, i64)> {
    let size = pe.info.size_of_image as u64;

    if proc.is_range_free(pe.info.image_base, size) {
        return Ok((pe.info.image_base, 0));
    }

    if !pe.info.has_relocations() {
        bail!(
            "preferred base {:#x} is taken and the DLL has no relocation table",
            pe.info.image_base
        );
    }

    // Walk outwards from the preferred base in 64 KiB steps: staying close
    // keeps the payload in the same address neighbourhood as a normal load.
    const STEP: u64 = 0x1_0000;
    let attempts = 0x1000; // up to +/-64 MiB
    for i in 1..attempts {
        for candidate in [
            pe.info.image_base.wrapping_sub(i * STEP),
            pe.info.image_base.wrapping_add(i * STEP),
        ] {
            if candidate == 0 || !is_user_address(candidate) {
                continue;
            }
            if proc.is_range_free(candidate, size) {
                return Ok((candidate, candidate as i64 - pe.info.image_base as i64));
            }
        }
    }

    let base = proc.allocate(size as usize)?;
    Ok((base, base as i64 - pe.info.image_base as i64))
}

fn is_user_address(addr: u64) -> bool {
    let high = addr >> 48;
    (high == 0 && addr != 0) || high == 0xffff
}

fn child_image_hint(image: &[u8]) -> String {
    format!("payload image ({} bytes)", image.len())
}

/// Which exported symbol to call. `DllMain` when present, otherwise the PE
/// entry point.
fn resolve_entry_rva(pe: &PeImage, image: &[u8], entry_symbol: &str) -> Result<u32> {
    if pe.info.directory(pe::DIRECTORY_ENTRY_EXPORT).is_some() {
        // The payload is a local file: parse its own export table directly.
        if let Some(rva) = find_export_rva(image, entry_symbol)? {
            return Ok(rva);
        }
    }
    if pe.info.entry_rva == 0 {
        bail!("payload has neither an export named {entry_symbol} nor an entry point");
    }
    Ok(pe.info.entry_rva)
}

/// Looks a name up in a *local* PE image's export directory.
///
/// Everything is read through [`PeImage::read_rva`] because export data lives
/// in sections, where an RVA is not a file offset.
fn find_export_rva(image: &[u8], name: &str) -> Result<Option<u32>> {
    let pe = PeImage::parse(image)?;
    let Some(dir) = pe.info.directory(pe::DIRECTORY_ENTRY_EXPORT) else {
        return Ok(None);
    };

    // IMAGE_EXPORT_DIRECTORY: NumberOfFunctions@0x14 NumberOfNames@0x18
    // AddressOfFunctions@0x1C AddressOfNames@0x20 AddressOfNameOrdinals@0x24
    let header = pe.read_rva(dir.virtual_address, 0x28)?;
    let number_of_names = pe::u32_at(header, 0x18)? as usize;
    let functions_rva = pe::u32_at(header, 0x1c)?;
    let names_rva = pe::u32_at(header, 0x20)?;
    let ordinals_rva = pe::u32_at(header, 0x24)?;

    if number_of_names > 0x10000 {
        bail!("implausible export name count {number_of_names}");
    }

    for i in 0..number_of_names {
        let name_ptr = pe::u32_at(pe.read_rva(names_rva + (i as u32) * 4, 4)?, 0)?;
        let ordinal_index = pe::u16_at(pe.read_rva(ordinals_rva + (i as u32) * 2, 2)?, 0)?;
        let entry = pe.read_rva_clamped(name_ptr, 512)?;
        let end = entry.iter().position(|&b| b == 0).unwrap_or(0);
        if &entry[..end] == name.as_bytes() {
            let rva =
                pe::u32_at(pe.read_rva(functions_rva + (ordinal_index as u32) * 4, 4)?, 0)?;
            return Ok(Some(rva));
        }
    }
    Ok(None)
}

/// Resolves every import of the image against the modules the target already
/// has, writing the addresses straight into the mapped image's IAT.
///
/// Returns the number of slots that were filled.
fn resolve_imports(
    proc: &RemoteProcess,
    modules: &RemoteModules,
    pe: &PeImage,
    mapped: &mut [u8],
) -> Result<usize> {
    let Some(dir) = pe.info.directory(pe::DIRECTORY_ENTRY_IMPORT) else {
        return Ok(0);
    };

    let mut resolver = ImportResolver::new(proc, modules);
    let mut patched = 0usize;
    let mut descriptor_rva = dir.virtual_address;
    let mut descriptors = 0usize;

    loop {
        let base = descriptor_rva as usize;
        let original_first_thunk = pe::u32_at(mapped, base)?;
        let name_rva = pe::u32_at(mapped, base + 12)?;
        let first_thunk = pe::u32_at(mapped, base + 16)?;
        descriptors += 1;

        // A zeroed descriptor terminates the list.
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if descriptors > 64 {
            bail!("import descriptor list does not terminate");
        }
        if first_thunk == 0 {
            bail!("import descriptor at {descriptor_rva:#x} has no IAT");
        }

        let module_name = read_c_string(mapped, name_rva as usize)?;
        let module_base = resolver.module_base_for(&module_name).with_context(|| {
            format!("resolving imports of {module_name} (descriptor {descriptor_rva:#x})")
        })?;

        // IMAGE_IMPORT_DESCRIPTOR64 thunks are 16 bytes: u64 + u64.
        let lookup_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
        let mut index = 0usize;
        loop {
            let thunk_off = lookup_rva as usize + index * 16;
            let value = pe::u64_at(mapped, thunk_off)?;
            if value == 0 {
                break;
            }

            let address = if value & pe::IMAGE_ORDINAL_FLAG64 != 0 {
                resolver.resolve(module_base, &exports::ImportBy::Ordinal(value & 0xffff))?
            } else {
                let hint_name_rva = (value & 0x7fff_ffff) as u32;
                // IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[] }
                let symbol = read_c_string(mapped, hint_name_rva as usize + 2)?;
                resolver.resolve(module_base, &exports::ImportBy::Name(symbol))?
            };

            let slot = first_thunk as usize + index * 8;
            if slot + 8 > mapped.len() {
                bail!("IAT slot {slot:#x} is outside the image");
            }
            mapped[slot..slot + 8].copy_from_slice(&address.to_le_bytes());
            patched += 1;
            index += 1;
        }

        descriptor_rva += 20;
    }

    if patched == 0 {
        bail!("payload has an import directory but no imports were resolved");
    }

    Ok(patched)
}

fn read_c_string(image: &[u8], at: usize) -> Result<String> {
    let slice = image
        .get(at..at + 512)
        .ok_or_else(|| anyhow::anyhow!("string at {at:#x} is outside the image"))?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(0);
    Ok(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Caches export tables and resolves names, following forwarders.
///
/// Modules are addressed by base address rather than by reference so the
/// resolver can keep its cache while a lookup is in flight.
struct ImportResolver<'a> {
    proc: &'a RemoteProcess,
    modules: &'a RemoteModules,
    exports: HashMap<u64, exports::ExportTable>,
}

impl<'a> ImportResolver<'a> {
    fn new(proc: &'a RemoteProcess, modules: &'a RemoteModules) -> Self {
        Self { proc, modules, exports: HashMap::new() }
    }

    fn module_base_for(&mut self, name: &str) -> Result<u64> {
        self.modules.base_for_name(self.proc, name)
    }

    fn module_view(&self, base: u64) -> RemoteModule {
        RemoteModule {
            base,
            size: 0,
            full_name: format!("{base:#x}"),
            base_name: format!("{base:#x}"),
        }
    }

    fn table(&mut self, base: u64) -> Result<&exports::ExportTable> {
        if !self.exports.contains_key(&base) {
            let module = self.module_view(base);
            let table = exports::load_exports(self.proc, &module)
                .with_context(|| format!("loading exports at {base:#x}"))?;
            if table.is_empty() {
                bail!("{base:#x} has no export directory");
            }
            self.exports.insert(base, table);
        }
        Ok(self.exports.get(&base).expect("just inserted"))
    }

    fn resolve(&mut self, base: u64, what: &exports::ImportBy) -> Result<u64> {
        self.resolve_depth(base, what, 0)
    }

    fn resolve_depth(
        &mut self,
        base: u64,
        what: &exports::ImportBy,
        depth: u32,
    ) -> Result<u64> {
        if depth > 4 {
            bail!("forwarder chain too deep for {}", what.describe());
        }

        let entry = match what {
            exports::ImportBy::Name(n) => self.table(base)?.by_name(n).cloned(),
            exports::ImportBy::Ordinal(o) => self.table(base)?.by_ordinal(*o as u16).cloned(),
        }
        .with_context(|| format!("{base:#x} does not export {}", what.describe()))?;

        match entry {
            exports::ExportTarget::Rva(rva) => Ok(base + rva as u64),
            exports::ExportTarget::Forwarder(text) => {
                let (dll, symbol) = exports::split_forwarder(&text)?;
                let target = self.module_base_for(&dll).with_context(|| {
                    format!("forwarder {text} points at an unmapped module")
                })?;
                self.resolve_depth(target, &exports::ImportBy::Name(symbol), depth + 1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::child::ChildSpec;

/// A full round trip against a real, suspended child process: parse the
    /// built DLL, map it, run its `DllMain`.
    ///
    /// Currently `#[ignore]`d: the entry dispatcher works (see the stub tests)
    /// but `cmd.exe` never reaches its entry point under
    /// `DETACHED_PROCESS`, so the injection window never opens. Tracked in
    /// README "当前状态"; run with
    /// `cargo test -p wbwpty-core injects_into -- --ignored --nocapture`.
    #[test]
    #[ignore = "open issue: target never reaches the entry point"]
    fn injects_into_a_suspended_cmd() {
        let Some(dll) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };

        let child = Child::spawn(&ChildSpec::new("cmd.exe").args(["/c", "exit", "0"])).unwrap();
        let report = inject_dll(&child, &dll, "DllMain").expect("manual map failed");

        assert!(report.image_base != 0);
        assert!(report.patch_count > 0, "KERNEL32/msvcrt imports must be patched");
        assert!(report.entry_rva != 0);

        // The target still has to run afterwards.
        child.resume().unwrap();
        assert_eq!(child.wait().unwrap(), 0);
    }

    /// A *running* target has a populated `PEB->Ldr`, which is the situation the
    /// PEB walk is designed for. (A suspended one has not run the loader yet.)
    #[test]
    fn peb_walk_works_once_the_target_is_running() {
        let child = Child::spawn(&ChildSpec::new("cmd.exe").args(["/c", "ping -n 6 127.0.0.1 >nul"]))
            .unwrap();
        child.resume().unwrap();

        let proc = RemoteProcess::new(child.process_handle());
        let mut modules = None;
        for _ in 0..200 {
            if let Ok(m) = proc.walk_modules() {
                modules = Some(m);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let modules = modules.expect("loader never initialised in the target");
        assert!(modules.iter().any(|m| m.base_name.eq_ignore_ascii_case("kernel32.dll")));
        let _ = child.terminate();
    }

    /// Locates `wbwpty_redirect.dll` next to the test executable (cargo puts unit
    /// test binaries in `target/<profile>/deps`, the payload in
    /// `target/<profile>`).
    pub fn payload_dll_path() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let candidates = [
            exe.with_file_name("wbwpty_redirect.dll"),
            exe.parent()?.join("..").join("wbwpty_redirect.dll"),
        ];
        candidates.iter().find(|c| c.is_file()).map(|c| c.canonicalize().unwrap_or_else(|_| c.clone()))
    }
}