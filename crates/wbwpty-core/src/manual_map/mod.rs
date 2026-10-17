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

pub mod console;
pub mod exports;
pub mod hook;
pub mod iat;
pub mod inline;
pub mod pe;
pub mod remote;
pub mod stub;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::child::Child;

pub use console::{install_console_hook, ConsoleApi, ConsoleHookReport, CONSOLE_APIS};
pub use hook::{install_create_process_hook, HookReport, Intercept};
pub use iat::ImportSlot;
pub use pe::PeImage;
pub use remote::{
    ConsolePatch, ConsoleState, ModuleNotMapped, ModuleSource, RemoteModule, RemoteModules,
    RemoteProcess, CONSOLE_HANDLE_SENTINEL,
};

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
    /// How long the host waited for `PEB->Ldr` to become walkable.
    pub loader_wait_ms: u64,
}

/// Maps `dll` into `child` and calls its exported `DllMain`.
///
/// `entry_symbol` defaults to `DllMain`. When the DLL exports it we call that
/// export directly instead of the PE entry point: the Rust `cdylib` entry
/// (`DllMainCRTStartup`, from mingw) expects an initialised C runtime, which a
/// manually mapped image has not had.
pub fn inject_dll(child: &Child, dll: &Path, entry_symbol: &str) -> Result<InjectionReport> {
    let file =
        std::fs::read(dll).with_context(|| format!("reading redirect DLL {}", dll.display()))?;
    let proc = RemoteProcess::new(child.process_handle());
    inject_bytes(&proc, child.pid, &file, entry_symbol)
}

/// How long [`inject_bytes`] waits for `LdrpInitializeProcess`.
///
/// Generous for the session's own target, which is expected to be an interactive
/// process that stays alive. A descendant is a different proposition - it may
/// be gone in milliseconds - so the supervisor uses a much shorter wait and
/// retries on the next poll instead.
const DEFAULT_LOADER_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the injector re-checks the target while waiting for its loader.
///
/// Deliberately small. Readiness is now driven by the real precondition - every
/// module the payload imports is mapped - rather than by waiting for the module
/// list to stop changing, so the loop usually exits on its first or second pass.
/// A long interval here would reintroduce exactly the window this design
/// removes: a target that spawns a child in its first few milliseconds gets that
/// child a console before anyone patched `ConsoleHandle`.
const INJECT_POLL: std::time::Duration = std::time::Duration::from_millis(1);

/// [`inject_bytes`] with the session's own loader wait, calling the entry point.
pub fn inject_bytes(
    proc: &RemoteProcess,
    pid: u32,
    image: &[u8],
    entry_symbol: &str,
) -> Result<InjectionReport> {
    let prepared = inject_bytes_inner(
        proc,
        pid,
        image,
        entry_symbol,
        DEFAULT_LOADER_WAIT,
        INJECT_POLL,
        true,
    )?;
    let (report, _entry) = prepared.into_parts();
    Ok(report)
}

/// Maps the payload without calling its entry point, for a target that is still
/// suspended.
///
/// This is the half of injection that can be done to a process that has not been
/// resumed yet: everything up to and including the final `WriteProcessMemory` is
/// pure data movement. The caller resumes the target and then calls
/// [`PreparedEntry::call_entry`].
///
/// The reason to want this is timing, not tidiness. `cmd.exe /c <command>` spawns
/// its first child within a couple of milliseconds of resuming, and work done
/// *after* the resume - waiting for the loader, resolving imports, installing the
/// `CreateProcess` substitution - happens after that child has already been given
/// a console of its own. Mapping first does not close the window by itself, but it
/// puts the payload in the target before the target runs any code, which is what
/// makes a pre-emptive hook possible.
pub fn inject_bytes_suspended(
    proc: &RemoteProcess,
    pid: u32,
    image: &[u8],
    entry_symbol: &str,
    loader_wait: std::time::Duration,
) -> Result<PreparedInjection> {
    let prepared = inject_bytes_inner(
        proc,
        pid,
        image,
        entry_symbol,
        loader_wait,
        INJECT_POLL,
        false,
    )?;
    let (report, entry) = prepared.into_parts();
    Ok(PreparedInjection { report, entry })
}

/// Both halves of injection: the report, and the entry point still to be called.
pub struct PreparedInjection {
    pub report: InjectionReport,
    pub entry: PreparedEntry,
}

impl PreparedInjection {
    /// Splits the two halves apart.
    fn into_parts(self) -> (InjectionReport, PreparedEntry) {
        (self.report, self.entry)
    }
}

/// [`inject_bytes`] for a caller that cannot afford to block for
/// [`DEFAULT_LOADER_WAIT`].
///
/// The supervisor drives this from a thread that has to stay responsive to the
/// session shutting down, so the wait is short and failure means "try again
/// later" rather than "this will never work".
///
/// `proc` rather than a `&Child` because a descendant is not a `Child`: it was
/// created by the target, and the host only ever learns its pid from a process
/// table snapshot. `pid` is therefore passed in separately, for the messages.
pub fn inject_bytes_with(
    proc: &RemoteProcess,
    pid: u32,
    image: &[u8],
    entry_symbol: &str,
    loader_wait: std::time::Duration,
    poll: std::time::Duration,
) -> Result<InjectionReport> {
    Ok(inject_bytes_inner(
        proc,
        pid,
        image,
        entry_symbol,
        loader_wait,
        poll,
        true,
    )?
    .report)
}

/// The one implementation both entry points share.
///
/// `run_entry` is the whole difference between them; see
/// [`inject_bytes_suspended`] for why that difference is worth having.
fn inject_bytes_inner(
    proc: &RemoteProcess,
    pid: u32,
    image: &[u8],
    entry_symbol: &str,
    loader_wait: std::time::Duration,
    poll: std::time::Duration,
    run_entry: bool,
) -> Result<PreparedInjection> {
    let pe = PeImage::parse(image)?;
    if !pe.info.is_dll {
        bail!(
            "{} is not a DLL (IMAGE_FILE_DLL is not set)",
            child_image_hint(image)
        );
    }
    let entry_rva = resolve_entry_rva(&pe, image, entry_symbol)?;

    // Synchronising with the target's loader used to be a guess: wait for the
    // module list to stop changing, which needs a settle interval long enough
    // to be right and therefore long enough (~100 ms) to lose against a target
    // that spawns immediately.
    //
    // The actual precondition is much narrower and directly observable: every
    // module *this* image imports has to be mapped, so that `resolve_imports`
    // can find an address for each of them. So we wait for a cheap "there is
    // something to resolve against" signal, then keep retrying the real work
    // until it succeeds, re-reading the module list each time. The common case
    // exits on the first or second pass, in single-digit milliseconds.
    let started = std::time::Instant::now();
    let deadline = started + loader_wait;

    let mut modules = proc
        .poll_modules_ready(poll, loader_wait)
        .with_context(|| format!("waiting for the loader in pid {pid}"))?;

    // Allocated once: retrying the resolution must not leak a reservation per
    // attempt, and the payload's preferred base is nowhere the loader maps
    // system DLLs, so re-allocating would only risk disagreeing with what is
    // already reserved.
    let (base, reloc_delta) = allocate_image(proc, &pe)?;
    let mut mapped = pe.map(reloc_delta)?;

    let (patch_count, discovered) = loop {
        let snapshot = RemoteModules::from_snapshot(modules);
        match resolve_imports(proc, &snapshot, &pe, &mut mapped) {
            Ok(count) => break (count, snapshot),
            Err(err) => {
                // Every failure is retryable, not just a missing module. Mid
                // loader, a module can be *listed* but not yet readable, and the
                // thunk walk then dereferences a half-built address instead of
                // reporting anything honest - `ReadProcessMemory` at an address
                // like `0x7ffee39c0000`, `ERROR_PARTIAL_COPY`. Treating only
                // `ModuleNotMapped` as transient turned that into a hard failure
                // where the old settle loop had simply waited it out.
                //
                // Retrying is safe: nothing is written to the target until
                // resolution succeeds, and `mapped` is re-resolved from scratch
                // on every attempt because its import slots are patched in place.
                if std::time::Instant::now() >= deadline {
                    return if err.downcast_ref::<ModuleNotMapped>().is_some() {
                        Err(err).with_context(|| {
                            format!(
                                "pid {pid} never mapped every module the payload imports \
                                 within {}ms",
                                loader_wait.as_millis()
                            )
                        })
                    } else {
                        Err(err).with_context(|| {
                            format!(
                                "pid {pid} never became resolvable within {}ms",
                                loader_wait.as_millis()
                            )
                        })
                    };
                }
                std::thread::sleep(poll);
                // Re-read: whatever was missing or unreadable is exactly what may
                // have appeared since.
                modules = proc.poll_modules_ready(poll, deadline - std::time::Instant::now())?;
            }
        }
    };
    let loader_wait_ms = started.elapsed().as_millis() as u64;

    // Where the time actually goes. The whole point of the suspended-injection
    // split is that this number has to be small compared to how fast the target
    // spawns its first child, so it is worth measuring per stage rather than
    // arguing about it.
    let trace = std::env::var_os("WBWPTY_TRACE_LOADER").is_some();
    let after_poll = std::time::Instant::now();
    if trace {
        eprintln!(
            "wbwpty: pid {pid} stage loader-wait {}ms",
            after_poll.elapsed().as_millis()
        );
    }

    // Imports are written straight into the mapped image, so the payload is
    // fully self-contained by the time `DllMain` is called and the in-target
    // trampoline only has to make the call.
    proc.write_bytes(base, &mapped)?;

    let entry = PreparedEntry {
        base,
        entry_rva,
        job: stub::build_job(base, entry_rva),
    };
    // Whether to call the entry point is the caller's decision, not ours: a target
    // that is still suspended cannot run a remote thread, and asking it to is how
    // `run_thread` ends up blocked forever (AGENTS pitfall 31).
    if run_entry {
        entry.call_entry(proc)?;
    }
    if trace {
        eprintln!(
            "wbwpty: pid {pid} stage resolve+write {}ms, entry {}ms, total {}ms",
            after_poll.elapsed().as_millis(),
            std::time::Instant::now().elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }

    Ok(PreparedInjection {
        entry,
        report: InjectionReport {
            image_base: base,
            entry_rva,
            patch_count,
            reloc_delta,
            module_count: discovered.len(),
            module_source: discovered.source(),
            loader_wait_ms,
        },
    })
}

/// A payload mapped into a *suspended* target, with its imports unresolved.
///
/// # Why this exists
///
/// Injection cannot be made fast by tuning. Measured on this machine, `cmd.exe`
/// resumes, finishes its own loader at about 25 ms, and calls `CreateProcess` at
/// about 31 ms. Everything the injector does after the resume is therefore
/// already too late: the substitution was live at 39 ms having reported zero
/// calls.
///
/// So the work that does not need the target to be running is moved before it.
/// Mapping is pure data movement - `VirtualAllocEx` plus `WriteProcessMemory` -
/// and both work against a suspended process, so the image can be in place before
/// the target executes a single instruction. What genuinely needs a running
/// target is small: resolving the payload's imports needs `PEB->Ldr`, and calling
/// `DllMain` needs a thread to run it.
///
/// Concretely, this moves the 276 KB image write off the critical path, leaving
/// only an import-table write, one remote thread, and the entry patch after the
/// resume.
///
/// # What it cannot do
///
/// The payload is *unusable* between [`Self::map_suspended`] and
/// [`Self::finish`]: its import table still holds whatever the file had. Nothing
/// may call into it in that window, and [`Self::finish`] is what makes it real.
/// Ordering them the other way round is the whole point; calling `DllMain`
/// before the imports are resolved would jump through nulls inside someone
/// else's process.
pub struct SuspendedMapping {
    /// The payload file, kept so the PE can be parsed again in `finish`.
    image: Vec<u8>,
    /// Where the image was mapped in the target.
    base: u64,
    /// Distance between the preferred base and the mapped one.
    reloc_delta: i64,
    /// RVA of the entry point to call.
    entry_rva: u32,
    /// The mapped image with relocations applied but imports untouched.
    mapped: Vec<u8>,
}

impl SuspendedMapping {
    /// Parses, relocates and writes `image` into `proc`, which must be suspended.
    ///
    /// Calls no remote thread and reads no loader state, so it works against a
    /// process that has never run an instruction.
    pub fn map_suspended(proc: &RemoteProcess, image: &[u8], entry_symbol: &str) -> Result<Self> {
        let pe = PeImage::parse(image)?;
        if !pe.info.is_dll {
            bail!(
                "{} is not a DLL (IMAGE_FILE_DLL is not set)",
                child_image_hint(image)
            );
        }
        let entry_rva = resolve_entry_rva(&pe, image, entry_symbol)?;

        // Allocation and relocation need nothing from the target but a handle.
        let (base, reloc_delta) = allocate_image(proc, &pe)?;
        let mapped = pe.map(reloc_delta)?;
        proc.write_bytes(base, &mapped)
            .context("writing the mapped image into the suspended target")?;

        Ok(Self {
            image: image.to_vec(),
            base,
            reloc_delta,
            entry_rva,
            mapped,
        })
    }

    /// Where the image was mapped, for publishing words into it.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// RVA of the entry point that will be called.
    pub fn entry_rva(&self) -> u32 {
        self.entry_rva
    }

    /// Resolves the imports, writes the image again, and calls the entry point.
    ///
    /// The image is written twice in total across the two phases. The second
    /// write is needed because import resolution patches the IAT *inside* the
    /// mapped image, and it is small relative to the first: the import table of a
    /// payload this size is a few hundred bytes.
    pub fn finish(
        self,
        proc: &RemoteProcess,
        pid: u32,
        loader_wait: std::time::Duration,
        poll: std::time::Duration,
        run_entry: bool,
    ) -> Result<InjectionReport> {
        let started = std::time::Instant::now();
        let deadline = started + loader_wait;
        let mut pe = PeImage::parse(&self.image)?;
        let mut mapped = self.mapped;

        let mut modules = proc
            .poll_modules_ready(poll, loader_wait)
            .with_context(|| format!("waiting for the loader in pid {pid}"))?;

        let (patch_count, discovered) = loop {
            let snapshot = RemoteModules::from_snapshot(modules);
            match resolve_imports(proc, &snapshot, &pe, &mut mapped) {
                Ok(count) => break (count, snapshot),
                Err(err) => {
                    // Every failure here is retryable, for the reason given in
                    // `inject_bytes_inner`: mid-loader a module can be listed but
                    // not yet readable, and treating only `ModuleNotMapped` as
                    // transient made this fail whenever the machine was busy.
                    if std::time::Instant::now() >= deadline {
                        return if err.downcast_ref::<ModuleNotMapped>().is_some() {
                            Err(err).with_context(|| {
                                format!(
                                    "pid {pid} never mapped every module the payload imports \
                                     within {}ms",
                                    loader_wait.as_millis()
                                )
                            })
                        } else {
                            Err(err).with_context(|| {
                                format!(
                                    "pid {pid} never became resolvable within {}ms",
                                    loader_wait.as_millis()
                                )
                            })
                        };
                    }
                    std::thread::sleep(poll);
                    modules =
                        proc.poll_modules_ready(poll, deadline - std::time::Instant::now())?;
                }
            }
        };
        let loader_wait_ms = started.elapsed().as_millis() as u64;

        proc.write_bytes(self.base, &mapped)?;

        if run_entry {
            PreparedEntry {
                base: self.base,
                entry_rva: self.entry_rva,
                job: stub::build_job(self.base, self.entry_rva),
            }
            .call_entry(proc)?;
        }

        // Keep the borrow of `pe` alive until the resolution is done with it.
        drop(pe);
        let _ = self.reloc_delta;

        Ok(InjectionReport {
            image_base: self.base,
            entry_rva: self.entry_rva,
            patch_count,
            reloc_delta: self.reloc_delta,
            module_count: discovered.len(),
            module_source: discovered.source(),
            loader_wait_ms,
        })
    }
}

/// A mapped, self-contained payload whose entry point has not been called yet.
///
/// The split exists because mapping and calling have different requirements.
/// Mapping is pure data - `VirtualAllocEx` plus `WriteProcessMemory` - and works
/// against a suspended process. Calling needs the target's threads to run, so it
/// can only happen after the target is resumed. Keeping them apart is what lets
/// the payload be in place *before* the target gets to run any code at all.
pub struct PreparedEntry {
    base: u64,
    entry_rva: u32,
    /// Trampoline bytes that set up `DllMain(hinst, DLL_PROCESS_ATTACH, NULL)`.
    job: Vec<u8>,
}

impl PreparedEntry {
    /// Runs `DllMain` in the target and waits for it to return.
    ///
    /// Returns the payload's exit code. Fails if it returns non-zero, because a
    /// payload that refused to attach must not be mistaken for one that did.
    pub fn call_entry(&self, proc: &RemoteProcess) -> Result<()> {
        let job_addr = proc.allocate(self.job.len())?;
        proc.write_bytes(job_addr, &self.job)?;
        let stub_addr = proc.allocate(stub::build_stub(0).len())?;
        proc.write_bytes(stub_addr, &stub::build_stub(job_addr))?;
        let exit = proc.run_thread(stub_addr)?;
        if exit != 0 {
            bail!(
                "payload entry at rva {:#x} returned {exit:#x}",
                self.entry_rva
            );
        }
        Ok(())
    }

    /// The base the payload is mapped at, for callers that publish words into it.
    pub fn base(&self) -> u64 {
        self.base
    }
}

/// Resumes `child` if needed, waits for its loader, then maps the DLL.
///
/// Keeping the resume here (rather than in [`inject_bytes`]) documents the
/// required ordering at the call site: the loader has to run before imports can
/// be resolved.
pub fn inject_into_child(child: &Child, dll: &Path, entry_symbol: &str) -> Result<InjectionReport> {
    child.resume()?;
    inject_dll(child, dll, entry_symbol)
}

/// Reserves the mapped base and returns it with the relocation delta it implies.
///
/// The region is genuinely *reserved*, not merely probed: `VirtualQueryEx`
/// happily reports a `MEM_FREE` hole that cannot be written to, so the old
/// "is it free?" check produced a base that `WriteProcessMemory` then rejected
/// with `ERROR_INVALID_ADDRESS`. Every return path here is backed by a real
/// allocation.
fn allocate_image(proc: &RemoteProcess, pe: &PeImage) -> Result<(u64, i64)> {
    let size = pe.info.size_of_image as u64;
    let delta_of = |base: u64| base as i64 - pe.info.image_base as i64;

    // Best case: the image loads exactly where it wants to, so no relocation is
    // applied at all.
    if let Some(base) = proc.reserve_at(pe.info.image_base, size as usize) {
        return Ok((base, delta_of(base)));
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
            if let Some(base) = proc.reserve_at(candidate, size as usize) {
                return Ok((base, delta_of(base)));
            }
        }
    }

    let base = proc.allocate(size as usize)?;
    Ok((base, delta_of(base)))
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
pub fn find_export_rva(image: &[u8], name: &str) -> Result<Option<u32>> {
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
            let rva = pe::u32_at(
                pe.read_rva(functions_rva + (ordinal_index as u32) * 4, 4)?,
                0,
            )?;
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

        // IMAGE_THUNK_DATA64 is exactly one u64 wide: AddressOfData (or the
        // ordinal flag) followed by the reserved slot that only exists as a
        // separate field in the 32-bit layout.
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let mut index = 0usize;
        loop {
            let thunk_off = lookup_rva as usize + index * THUNK_SIZE;
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

            let slot = first_thunk as usize + index * THUNK_SIZE;
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

/// Size of one x64 import thunk (`IMAGE_THUNK_DATA64`) and of one IAT slot.
/// Both are a single `u64`; the 16-byte stride belongs to the 32-bit layout and
/// silently walks into the middle of the *next* thunk if used here.
const THUNK_SIZE: usize = 8;

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
        Self {
            proc,
            modules,
            exports: HashMap::new(),
        }
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
            // Read the module's export directory from its file when the loader
            // recorded a path, and only fall back to reading it out of the
            // process.
            //
            // This is worth the branch. `load_exports` walks *every* export in the
            // module and reads each forwarder string individually, and it does
            // that with `ReadProcessMemory`, against a target that is still
            // starting. `kernel32.dll` has roughly 1500 exports; doing that across
            // a process boundary measured at about 40 ms, which was the whole
            // margin this mechanism is trying to win. The same bytes are on disk,
            // and the RVAs in them are a property of the file - only the base comes
            // from the target, and that is already known here.
            let from_file = self
                .modules
                .path_for_base(base)
                .and_then(|path| {
                    exports::load_exports_from_file(std::path::Path::new(&path), &self.module_view(base)).ok()
                })
                .filter(|table| !table.is_empty());

            let table = match from_file {
                Some(table) => table,
                None => {
                    let module = self.module_view(base);
                    exports::load_exports(self.proc, &module)
                        .with_context(|| format!("loading exports at {base:#x}"))?
                }
            };
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

    fn resolve_depth(&mut self, base: u64, what: &exports::ImportBy, depth: u32) -> Result<u64> {
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
                let target = self
                    .module_base_for(&dll)
                    .with_context(|| format!("forwarder {text} points at an unmapped module"))?;
                self.resolve_depth(target, &exports::ImportBy::Name(symbol), depth + 1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::child::{ChildSpec, Stdio};

    /// `GetExitCodeProcess` reports this for a process that has not exited yet.
    const STILL_ACTIVE: u32 = 259;

    /// A full round trip against a real child process: parse the built DLL, map
    /// it, and run its `DllMain`.
    ///
    /// The target is an interactive `cmd.exe` whose stdin is a pipe nobody ever
    /// writes to, so it blocks on input for as long as the test needs - no
    /// timers, no network probes, and it keeps the same std handles a real
    /// session uses.
    #[test]
    fn injects_into_a_running_cmd() {
        use crate::pipe::PipePair;

        let Some(dll) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };

        let mut pipes = PipePair::new(0x11_0001).unwrap();
        let stdio = pipes.open_target_stdio().unwrap();
        let spec = ChildSpec::new("cmd.exe").stdio(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        });

        let child = Child::spawn(&spec).unwrap();
        let report = inject_into_child(&child, &dll, "DllMain").expect("manual map failed");

        assert!(report.image_base != 0, "image must be mapped somewhere");
        assert!(
            report.patch_count > 0,
            "KERNEL32/msvcrt imports must be patched"
        );
        assert!(report.entry_rva != 0);
        assert_eq!(
            report.module_source,
            ModuleSource::Peb,
            "imports come from the target PEB"
        );

        // The payload must not have taken the target down with it.
        assert!(
            child.is_running(),
            "target died after the payload's DllMain ran"
        );
        child.terminate().unwrap();
    }

    /// A *running* target has a populated `PEB->Ldr`, which is the situation the
    /// PEB walk is designed for. (A suspended one has not run the loader yet.)
    ///
    /// `wait_until_loader_ready` is what the injector relies on, so it is
    /// exercised against a real target here.
    #[test]
    fn peb_walk_works_once_the_target_is_running() {
        use crate::pipe::PipePair;

        let mut pipes = PipePair::new(0x11_0002).unwrap();
        let stdio = pipes.open_target_stdio().unwrap();
        let child = Child::spawn(&ChildSpec::new("cmd.exe").stdio(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        }))
        .unwrap();
        child.resume().unwrap();

        let proc = RemoteProcess::new(child.process_handle());
        proc.wait_until_loader_ready(std::time::Duration::from_secs(10))
            .expect("loader never initialised in the target");

        let modules = proc.walk_modules().unwrap();
        assert!(modules
            .iter()
            .any(|m| m.base_name.eq_ignore_ascii_case("kernel32.dll")));
        let _ = child.terminate();
    }

    /// Pins the hard constraint the injector is built around: a target's entry
    /// point may NOT be rewritten while the process is suspended.
    ///
    /// Measured on Windows 11 / cmd.exe (a `GUARD_CF` image):
    ///
    /// | what the host writes into the suspended target | exit code |
    /// | --- | --- |
    /// | nothing | `0` |
    /// | RWX page + dispatcher code near the image | `0` |
    /// | 8 bytes anywhere in `.text` (restored afterwards) | `0` |
    /// | `E9 rel32` at the entry point | `0x103` (`STATUS_POSSIBLE_DEADLOCK`) |
    ///
    /// So the entry point specifically is off limits until the loader has run,
    /// which rules out the "patch the entry point, resume, let the loader stop
    /// there" trampoline. Injection therefore happens *after* `PEB->Ldr`
    /// becomes walkable (see [`inject_bytes`]); std handles are handed over by
    /// `STARTF_USESTDHANDLES` so nothing depends on winning a race with the
    /// target's CRT.
    #[test]
    fn suspended_entry_point_cannot_be_rewritten() {
        use crate::manual_map::remote::RemoteProcess;

        let run = |patch_entry: bool| -> u32 {
            let child = Child::spawn(&ChildSpec::new("cmd.exe").args(["/c", "exit", "0"])).unwrap();
            let proc = RemoteProcess::new(child.process_handle());
            if patch_entry {
                let image_base = proc.image_base().unwrap();
                let exe_bytes = std::fs::read(&child.image).unwrap();
                let exe = PeImage::parse(&exe_bytes).unwrap();
                let oep = image_base + exe.info.entry_rva as u64;
                let scratch = proc.allocate_near(oep, 0x1000).unwrap();
                // `jmp self`: reaching it would hang instead of exiting cleanly,
                // so a clean exit proves the entry point was never executed.
                proc.write_bytes(scratch, &[0xeb, 0xfe]).unwrap();
                // Hand-assemble `E9 rel32`; the encoder that used to live here
                // went away with the dispatcher, and this test is about the
                // *consequence* of patching, not about encoding it.
                let rel = (scratch as i64 - (oep as i64 + 5)) as i32;
                let mut patch = [0xe9u8; 5];
                patch[1..].copy_from_slice(&rel.to_le_bytes());
                proc.write_bytes(oep, &patch).unwrap();
            }

            child.resume().unwrap();
            let mut exit = 0u32;
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // SAFETY: live handle, live out parameter.
                unsafe {
                    windows_sys::Win32::System::Threading::GetExitCodeProcess(
                        proc.handle(),
                        &mut exit,
                    )
                };
                if exit != STILL_ACTIVE {
                    break;
                }
            }
            if exit == STILL_ACTIVE {
                let _ = child.terminate();
            }
            exit
        };

        assert_eq!(
            run(false),
            0,
            "an untouched suspended target runs to completion"
        );
        assert_ne!(
            run(true),
            0,
            "rewriting the entry point must not be assumed to work: see README 5.3"
        );
    }
/// Bisect probe: mapping the image and running a trivial export must work.
    ///
    /// `wbwpty_probe` only stores a magic into the payload's own writable data,
    /// so a failure here localises the fault to the manual map itself (relocations,
    /// section copying, or the remote call) rather than to anything `DllMain`
    /// happens to do.
    #[test]
    fn mapped_image_runs_a_trivial_export() {
        use crate::manual_map::remote::RemoteProcess;

        let Some(dll) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };
        let file = std::fs::read(&dll).unwrap();
        let _pe = PeImage::parse(&file).unwrap();
        let status_rva = find_export_rva(&file, "WBWPTY_STATUS")
            .expect("payload must export WBWPTY_STATUS")
            .expect("WBWPTY_STATUS must be in the export table");
        eprintln!("DIAG status_rva={status_rva:#x}");

        // The target must outlive the injection, and a `cmd.exe` with no stdin
        // exits immediately, so it gets a pipe nobody ever writes to.
        let mut pipes = crate::pipe::PipePair::new(0x11_0004).unwrap();
        let mut stdio = pipes.open_target_stdio().unwrap();
        let child = Child::spawn(&ChildSpec::new("cmd.exe").stdio(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        }))
        .unwrap();
        stdio.release();
        let report = inject_into_child(&child, &dll, "wbwpty_probe").expect("probe injection");
        eprintln!("DIAG probe report image_base={:#x} entry_rva={:#x} wait={}ms",
            report.image_base, report.entry_rva, report.loader_wait_ms);

        let proc = RemoteProcess::new(child.process_handle());
        let bytes = proc.read_bytes(report.image_base + status_rva as u64, 4).unwrap();
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(
            val, 0xc0de_cafe,
            "probe wrote its marker, got {val:#x}"
        );
        assert!(child.is_running(), "target survived");
        let _ = child.terminate();
    }

    /// Call `DllMain` directly (no `stdio::install`) and read back the status.
    ///
    /// `DllMain` now only does `WBWPTY_STATUS = PROBE_MARKER | (reason << 16)`.
    /// If this test passes the status will be `0xc0de_0100` (reason=1, marker=0xc0decafe);
    /// if it AVs we will get a panic instead.
    #[test]
    fn dllmain_runs_without_fauling() {
        use crate::manual_map::remote::RemoteProcess;

        let Some(dll) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };
        let file = std::fs::read(&dll).unwrap();
        let status_rva = find_export_rva(&file, "WBWPTY_STATUS")
            .expect("payload must export WBWPTY_STATUS")
            .expect("WBWPTY_STATUS must be in the export table");

        let mut pipes = crate::pipe::PipePair::new(0x11_0006).unwrap();
        let mut stdio = pipes.open_target_stdio().unwrap();
        let child = Child::spawn(&ChildSpec::new("cmd.exe").stdio(Stdio {
            stdin: stdio.stdin,
            stdout: stdio.stdout,
            stderr: stdio.stderr,
        }))
        .unwrap();
        stdio.release();
        let report = inject_into_child(&child, &dll, "DllMain").expect("DllMain injection");
        eprintln!("DIAG dllmain report image_base={:#x} entry_rva={:#x} wait={}ms",
            report.image_base, report.entry_rva, report.loader_wait_ms);

        let proc = RemoteProcess::new(child.process_handle());
        let bytes = proc.read_bytes(report.image_base + status_rva as u64, 4).unwrap();
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        eprintln!("DIAG dllmain status={val:#x} (non-zero (DllMain ran))");
        if val == 0 {
            panic!("DllMain did not write status at all (crashed in prologue?)");
        }
        // Any value >= 10 means DllMain entered the attach branch.
        // Value 99 = past install(). Values 10-22 = inside install().
assert!(val != 0, "DllMain must write to status; got {val:#x}");
        assert!(child.is_running(), "target survived DllMain");
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
        candidates
            .iter()
            .find(|c| c.is_file())
            .map(|c| c.canonicalize().unwrap_or_else(|_| c.clone()))
    }
}
