//! Export table lookup inside the *target's* modules.
//!
//! The injector cannot use `GetProcAddress` on a foreign process, so it reads
//! the module's export directory through `ReadProcessMemory` and resolves
//! names itself. Forwarded exports matter here: on Windows 10 most of
//! `kernel32.dll`'s console API entries are `KERNELBASE.*` forwarders, so
//! following them is mandatory, not an optimisation.
//!
//! `IMAGE_EXPORT_DIRECTORY` (winnt.h): Characteristics@0x00 TimeDateStamp@0x04
//! Major/Minor@0x08 Name@0x0C Base@0x10 NumberOfFunctions@0x14
//! NumberOfNames@0x18 AddressOfFunctions@0x1C AddressOfNames@0x20
//! AddressOfNameOrdinals@0x24.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use super::pe::{u16_at, u32_at, DataDirectory, IMAGE_NT_OPTIONAL_HDR64_MAGIC};
use super::remote::{RemoteModule, RemoteProcess};

const MAX_EXPORT_NAME: usize = 512;
/// Upper bound on a module's export arrays; the largest system DLLs sit far
/// below this, so anything larger means we mis-parsed the directory.
const MAX_EXPORTS: usize = 0x10000;

#[derive(Debug, Clone)]
pub enum ExportTarget {
    /// Regular export: module_base + rva.
    Rva(u32),
    /// Forwarder string such as `KERNELBASE.WriteConsoleW`.
    Forwarder(String),
}

#[derive(Debug, Default)]
pub struct ExportTable {
    by_name: HashMap<String, ExportTarget>,
    by_ordinal: HashMap<u16, ExportTarget>,
}

impl ExportTable {
    pub fn by_name(&self, name: &str) -> Option<&ExportTarget> {
        self.by_name.get(name)
    }

    pub fn by_ordinal(&self, ordinal: u16) -> Option<&ExportTarget> {
        self.by_ordinal.get(&ordinal)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// Reads and indexes the export directory of a remote module.
///
/// Everything is fetched as its own `ReadProcessMemory` rather than as one
/// blob: the three arrays are addressed by *absolute* RVA, and the name strings
/// may live past `IMAGE_EXPORT_DIRECTORY.Size`, so a single window computed
/// from `dir.size` is not guaranteed to cover them.
pub fn load_exports(proc: &RemoteProcess, module: &RemoteModule) -> Result<ExportTable> {
    let Some(dir) = read_export_directory(proc, module)? else {
        return Ok(ExportTable::default());
    };

    let base = module.base;
    let at = |rva: u32, len: usize| -> Result<Vec<u8>> {
        proc.read_bytes(base + rva as u64, len)
            .with_context(|| format!("reading {:#x} bytes at rva {rva:#x} of {}", len, module.base_name))
    };

    // IMAGE_EXPORT_DIRECTORY header.
    let header = at(dir.virtual_address, 0x28)?;
    let base_index = u32_at(&header, 0x10)?;
    let number_of_functions = u32_at(&header, 0x14)? as usize;
    let number_of_names = u32_at(&header, 0x18)? as usize;
    let functions_rva = u32_at(&header, 0x1c)?;
    let names_rva = u32_at(&header, 0x20)?;
    let ordinals_rva = u32_at(&header, 0x24)?;

    if number_of_functions == 0 || number_of_functions > MAX_EXPORTS {
        bail!("implausible export function count {number_of_functions} in {}", module.base_name);
    }
    if number_of_names > MAX_EXPORTS {
        bail!("implausible export name count {number_of_names} in {}", module.base_name);
    }

    let functions = at(functions_rva, number_of_functions * 4)?;
    let names = at(names_rva, number_of_names * 4)?;
    let ordinals = at(ordinals_rva, number_of_names * 2)?;

    let dir_start = dir.virtual_address;
    let dir_end = dir_start + dir.size;
    let classify = |rva: u32| -> Result<ExportTarget> {
        if (dir_start..dir_end).contains(&rva) {
            // Inside the export directory => ASCII forwarder string.
            let blob = at(rva, MAX_EXPORT_NAME)?;
            let end = blob.iter().position(|&b| b == 0).unwrap_or(MAX_EXPORT_NAME);
            Ok(ExportTarget::Forwarder(
                String::from_utf8_lossy(&blob[..end]).into_owned(),
            ))
        } else {
            Ok(ExportTarget::Rva(rva))
        }
    };

    let mut table = ExportTable::default();
    for i in 0..number_of_functions {
        let rva = u32_at(&functions, i * 4)?;
        if rva == 0 {
            continue;
        }
        let ordinal = (i as u32 + base_index) as u16;
        table.by_ordinal.insert(ordinal, classify(rva)?);
    }

    for i in 0..number_of_names {
        let name_rva = u32_at(&names, i * 4)?;
        let index = u16_at(&ordinals, i * 2)? as usize;
        if index >= number_of_functions {
            continue;
        }
        let blob = at(name_rva, MAX_EXPORT_NAME)?;
        let end = blob.iter().position(|&b| b == 0).unwrap_or(0);
        let name = String::from_utf8_lossy(&blob[..end]).into_owned();
        let rva = u32_at(&functions, index * 4)?;
        if rva != 0 {
            table.by_name.insert(name, classify(rva)?);
        }
    }

    Ok(table)
}

fn read_export_directory(
    proc: &RemoteProcess,
    module: &RemoteModule,
) -> Result<Option<DataDirectory>> {
    // The export directory RVA lives in the first page of the image; find it by
    // reading the DOS/NT headers out of the target.
    let head = proc.read_bytes(module.base, 0x1000)?;
    let e_lfanew = u32_at(&head, 0x3c)? as usize;
    let oh = e_lfanew + 4 + 20;
    if u16_at(&head, oh)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        bail!("{:#x} does not look like a PE32+ image", module.base);
    }
    let number_of_dirs = u32_at(&head, oh + 0x6c)? as usize;
    if number_of_dirs < 1 {
        return Ok(None);
    }
    let dir_off = oh + 0x70;
    let virtual_address = u32_at(&head, dir_off)?;
    let size = u32_at(&head, dir_off + 4)?;
    // Exes and data-only images leave the directory slot zeroed; that is "no
    // exports", not an empty directory to be parsed.
    if virtual_address == 0 || size < 0x28 {
        return Ok(None);
    }
    Ok(Some(DataDirectory { virtual_address, size }))
}

/// Splits `KERNELBASE.WriteConsoleW` into `(module, symbol)`.
pub fn split_forwarder(forwarder: &str) -> Result<(String, String)> {
    let (module, symbol) = forwarder
        .split_once('.')
        .with_context(|| format!("malformed forwarder string {forwarder:?}"))?;
    if module.is_empty() || symbol.is_empty() {
        bail!("malformed forwarder string {forwarder:?}");
    }
    Ok((module.to_string(), symbol.to_string()))
}

/// How an import is named in a descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportBy {
    Name(String),
    Ordinal(u64),
}

impl ImportBy {
    pub fn describe(&self) -> String {
        match self {
            ImportBy::Name(n) => n.clone(),
            ImportBy::Ordinal(o) => format!("#{o}"),
        }
    }
}