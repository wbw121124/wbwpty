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
pub fn load_exports(proc: &RemoteProcess, module: &RemoteModule) -> Result<ExportTable> {
    let Some(dir) = read_export_directory(proc, module)? else {
        return Ok(ExportTable::default());
    };

    // Read a generous window: headers, arrays and name strings all live in it.
    let window = dir.size.max(0x400) as usize;
    let blob = proc
        .read_bytes(module.base + dir.virtual_address as u64, window)
        .with_context(|| format!("reading export directory of {}", module.base_name))?;

    let base_index = u32_at(&blob, 0x10)?;
    let number_of_functions = u32_at(&blob, 0x14)? as usize;
    let number_of_names = u32_at(&blob, 0x18)? as usize;
    let functions_rva = u32_at(&blob, 0x1c)? as usize;
    let names_rva = u32_at(&blob, 0x20)? as usize;
    let ordinals_rva = u32_at(&blob, 0x24)? as usize;

    if number_of_functions == 0 || number_of_functions > 0x10000 || number_of_names > 0x10000 {
        bail!("implausible export counts in {}", module.base_name);
    }

    // The function address array is the one thing we always index directly.
    let mut function_rvas = Vec::with_capacity(number_of_functions);
    for i in 0..number_of_functions {
        function_rvas.push(u32_at(&blob, functions_rva + i * 4)?);
    }

    let dir_start = dir.virtual_address;
    let dir_end = dir_start + dir.size;
    let classify = |rva: u32| -> ExportTarget {
        if rva >= dir_start && rva < dir_end {
            // Inside the export directory => ASCII forwarder string.
            let at = rva as usize - dir_start as usize;
            let end = blob[at..].iter().position(|&b| b == 0).unwrap_or(MAX_EXPORT_NAME - 1);
            ExportTarget::Forwarder(
                String::from_utf8_lossy(&blob[at..at + end.min(MAX_EXPORT_NAME)]).into_owned(),
            )
        } else {
            ExportTarget::Rva(rva)
        }
    };

    let mut table = ExportTable::default();
    for (index, rva) in function_rvas.iter().enumerate() {
        if *rva == 0 {
            continue;
        }
        if index < 0xffff {
            let ordinal = (index as u32 + base_index) as u16;
            table.by_ordinal.insert(ordinal, classify(*rva));
        }
    }

    for i in 0..number_of_names {
        let name_ptr = u32_at(&blob, names_rva + i * 4)?;
        let ordinal_index = u16_at(&blob, ordinals_rva + i * 2)? as usize;
        if ordinal_index >= function_rvas.len() {
            continue;
        }
        let name = read_cstr(&blob, name_ptr as usize)?;
        table.by_name.insert(name, classify(function_rvas[ordinal_index]));
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
    Ok(Some(DataDirectory {
        virtual_address: u32_at(&head, dir_off)?,
        size: u32_at(&head, dir_off + 4)?,
    }))
}

fn read_cstr(blob: &[u8], at: usize) -> Result<String> {
    let slice = blob
        .get(at..at + MAX_EXPORT_NAME)
        .ok_or_else(|| anyhow::anyhow!("export name at {at:#x} is outside the export window"))?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(0);
    Ok(String::from_utf8_lossy(&slice[..end]).into_owned())
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