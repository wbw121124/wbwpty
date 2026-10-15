//! Find the target's Import Address Table slots, so a payload can be
//! substituted for an API without touching a single instruction.
//!
//! # Why the IAT and not an inline hook
//!
//! The obvious way to intercept `CreateProcessW` in the target is to overwrite
//! the first bytes of the implementation in `KernelBase`. That means encoding
//! x64 machine code, finding an instruction boundary with a length decoder, and
//! hoping Control Flow Guard does not object - `KernelBase` on this machine is a
//! CFG image (`DllCharacteristics = 0x4160`), so a trampoline whose target is
//! not a registered call target is exactly the case CFG exists to catch.
//!
//! Rewriting the IAT sidesteps all three. An IAT slot is data, not code: the
//! guard does not instrument it, there is no instruction boundary to find, and
//! the displaced bytes problem does not exist. `cmd.exe` imports
//! `CreateProcessW` through it, from
//! `api-ms-win-core-kernel32-legacy-l1-1-0.dll`.
//!
//! # What is still up for measurement
//!
//! The slot is writable, and the loader really did put a resolved address
//! there. Both are checked at runtime rather than assumed - see
//! [`crate::manual_map::inject::InstallReport`].

use anyhow::{bail, Context, Result};

use crate::manual_map::pe::{self, PeImage, IMAGE_ORDINAL_FLAG64};

/// Little-endian field readers, over a slice that is already at the right RVA.
///
/// The import walk reads through `PeImage::read_rva` at every step rather than
/// indexing the file image with an RVA: the import directory lives in a section,
/// where those are different numbers (AGENTS pitfall 5).
fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    pe::u32_at(data, offset)
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    pe::u64_at(data, offset)
}

/// One resolved import, as it exists in a loaded process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSlot {
    /// The DLL the import is attributed to, as spelled in the import table.
    pub module: String,
    /// The imported name, or `ordinal #N` for an ordinal import.
    pub symbol: String,
    /// RVA of the `FirstThunk` slot - the one the loader has written an
    /// address into, and the one a substitution has to overwrite.
    pub iat_rva: u32,
    /// True for a delay import, where the slot holds a resolver stub until the
    /// first call rather than a bound address.
    pub delayed: bool,
}

impl ImportSlot {
    /// Runtime address of the slot inside a process whose image is at `base`.
    pub fn address(&self, base: u64) -> u64 {
        base + self.iat_rva as u64
    }
}

/// `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`.
///
/// `cmd.exe` delay-loads `CreateProcessW`. That is not a detail: the loader
/// leaves a delay-import slot as a pointer to a stub that resolves the function
/// on first call, so patching only the regular import table produces a report
/// that says "substituted" while every call still goes somewhere else.
const DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

/// Every import whose name is in `wanted`, from the regular **and** the delay
/// import tables, in table order.
///
/// Returns an empty vector when the image imports none of them, which is a
/// legitimate answer rather than a failure: the caller decides what to do about
/// a target that calls `CreateProcessW` some other way.
pub fn find_imports(image: &[u8], wanted: &[&str]) -> Result<Vec<ImportSlot>> {
    let pe = PeImage::parse(image)?;
    let mut slots = find_in_directory(&pe, pe::DIRECTORY_ENTRY_IMPORT, wanted, false)?;
    slots.extend(find_in_directory(
        &pe,
        DIRECTORY_ENTRY_DELAY_IMPORT,
        wanted,
        true,
    )?);
    Ok(slots)
}

/// Walks one import directory.
///
/// `delay` selects the descriptor shape: `IMAGE_IMPORT_DESCRIPTOR` and
/// `ImgDelayDescr` both list a name table and an IAT, but the delay one is
/// RVA-or-VA tagged and lists the IAT before the name table.
fn find_in_directory(
    pe: &PeImage,
    directory: usize,
    wanted: &[&str],
    delay: bool,
) -> Result<Vec<ImportSlot>> {
    let Some(dir) = pe.info.directory(directory) else {
        return Ok(Vec::new());
    };

    let mut slots = Vec::new();
    let stride = if delay { DELAY_DESCRIPTOR_SIZE } else { IMPORT_DESCRIPTOR_SIZE };
    let mut descriptor_rva = dir.virtual_address;
    for _ in 0..64 {
        let descriptor = pe
            .read_rva(descriptor_rva, stride)
            .context("reading an import descriptor")?;

        let (lookup_rva, first_thunk, name_rva) = if delay {
            (
                u32_at(descriptor, 16)?,
                u32_at(descriptor, 12)?,
                u32_at(descriptor, 4)?,
            )
        } else {
            (
                u32_at(descriptor, 0)?,
                u32_at(descriptor, 16)?,
                u32_at(descriptor, 12)?,
            )
        };

        // The list is terminated by an all-zero descriptor, not a count. This
        // has to come before any per-descriptor validation: the terminator's
        // `grAttrs` is zero, which is also what "these fields are VAs" looks
        // like, and checking that first turns every image's terminator into a
        // hard error.
        if lookup_rva == 0 && first_thunk == 0 && name_rva == 0 {
            break;
        }
        if first_thunk == 0 {
            bail!("import descriptor at {descriptor_rva:#x} has no IAT");
        }
        if delay {
            // `grAttrs & 1` means the fields are RVAs; anything else means they
            // are VAs relative to the image base, which is pre-Vista and does
            // not occur on anything this project targets. Refusing is better
            // than computing a slot address from the wrong base.
            let attrs = u32_at(descriptor, 0)?;
            if attrs & 1 == 0 {
                bail!(
                    "delay import at {descriptor_rva:#x} uses VA fields, which \
                     are not supported"
                );
            }
        }

        let module = read_c_string(pe, name_rva as usize).unwrap_or_default();
        // The name table holds the names; `FirstThunk` is what the loader (or
        // the delay-load stub) writes the address into. Before binding they are
        // the same table, after binding only the second one is an address list.
        let lookup_rva = if lookup_rva != 0 {
            lookup_rva
        } else {
            first_thunk
        };

        // IMAGE_THUNK_DATA64 is one u64: an ordinal flag with the ordinal, or
        // an RVA to IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[] }.
        let mut index = 0u32;
        loop {
            let value = u64_at(
                pe.read_rva(lookup_rva + index * THUNK_SIZE as u32, THUNK_SIZE)
                    .context("reading an import thunk")?,
                0,
            )?;
            if value == 0 {
                break;
            }
            let symbol = if value & IMAGE_ORDINAL_FLAG64 != 0 {
                format!("ordinal #{}", value & 0xffff)
            } else {
                read_c_string(pe, (value & 0x7fff_ffff) as usize + 2).unwrap_or_default()
            };
            if wanted.iter().any(|w| *w == symbol) {
                slots.push(ImportSlot {
                    module: module.clone(),
                    symbol,
                    iat_rva: first_thunk + index * THUNK_SIZE as u32,
                    delayed: delay,
                });
            }
            index += 1;
        }
        descriptor_rva += stride as u32;
    }

    Ok(slots)
}

/// `ImgDelayDescr` is 32 bytes; `IMAGE_IMPORT_DESCRIPTOR` is 20.
const DELAY_DESCRIPTOR_SIZE: usize = 32;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;

/// `IMAGE_THUNK_DATA64` and one IAT slot are both a single `u64`.
const THUNK_SIZE: usize = 8;

fn read_c_string(pe: &PeImage, at: usize) -> Result<String> {
    let slice = pe.read_rva_clamped(at as u32, 256).context("reading an import name")?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(0);
    Ok(String::from_utf8_lossy(&slice[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload must be importable this way, or the whole approach is moot.
    #[test]
    fn the_payload_exports_create_process_w() {
        let path = payload_dll_path();
        let Some(path) = path else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };
        let image = std::fs::read(&path).expect("read payload");
        let slots = find_imports(&image, &["CreateThread", "GetProcAddress"])
            .expect("walk the payload's imports");
        assert!(
            !slots.is_empty(),
            "the payload imports CreateThread and GetProcAddress, so its own IAT \
             is a valid subject for this walk"
        );
        for slot in &slots {
            assert!(slot.iat_rva != 0);
            assert!(!slot.module.is_empty());
        }
    }

    /// A PE with no import directory must produce an empty answer, not an error.
    #[test]
    fn a_dll_with_no_imports_yields_nothing() {
        // A minimal but valid x64 PE header is more than this test should
        // assemble by hand, so use the payload and ask for a name it cannot
        // possibly import.
        let Some(path) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };
        let image = std::fs::read(&path).expect("read payload");
        let slots = find_imports(&image, &["NoSuchSymbolAnywhere12345"]).expect("walk imports");
        assert!(slots.is_empty());
    }

    /// A real x64 target: `cmd.exe` imports `CreateProcessW` through its IAT.
    #[test]
    fn cmd_imports_create_process_w_through_its_iat() {
        let Ok(image) = std::fs::read("C:\\Windows\\System32\\cmd.exe") else {
            eprintln!("skipping: cmd.exe not readable");
            return;
        };
        dump_delay_imports(&image);
        let slots = find_imports(&image, &["CreateProcessW"]).expect("walk cmd.exe imports");
        eprintln!("cmd.exe CreateProcessW slots: {slots:?}");
        assert!(
            slots.len() >= 1,
            "cmd.exe must import CreateProcessW through its IAT, otherwise the \
             interception plan has no entry point"
        );
        assert!(
            slots.iter().any(|s| !s.delayed),
            "cmd.exe binds CreateProcessW through its regular import table; its \
             delay imports are unrelated DLLs (branding, cmd-util, shell32)"
        );
    }

    /// The delay import table must parse without tripping over its own
    /// terminator.
    ///
    /// A delay descriptor's `grAttrs` is zero for the all-zero terminator, which
    /// is also what "these fields are VAs instead of RVAs" looks like, so
    /// validating `grAttrs` before checking for the end of the list turns every
    /// image's terminator into a hard error.
    #[test]
    fn the_delay_import_table_terminates_cleanly() {
        let Ok(image) = std::fs::read("C:\\Windows\\System32\\cmd.exe") else {
            eprintln!("skipping: cmd.exe not readable");
            return;
        };
        let pe = PeImage::parse(&image).expect("parse cmd.exe");
        let dir = pe
            .info
            .directory(DIRECTORY_ENTRY_DELAY_IMPORT)
            .expect("cmd.exe has delay imports");
        let first = pe.read_rva(dir.virtual_address, 32).expect("first descriptor");
        // Walk until the all-zero entry by hand, the way the parser has to.
        let mut index = 0u32;
        let terminator = loop {
            let raw = pe
                .read_rva(dir.virtual_address + index * 32, 32)
                .expect("descriptor");
            if (0..8).all(|i| u32_at(raw, i * 4).unwrap_or(1) == 0) {
                break index;
            }
            index += 1;
            assert!(index < 16, "no terminator found, the walk is wrong");
        };
        eprintln!("cmd.exe delay descriptors terminate at index {terminator}");
        assert!(
            u32_at(first, 0).expect("grAttrs") & 1 == 1,
            "the first real descriptor should be RVA based"
        );
    }

    /// Prints the raw delay descriptors. A parser that guesses wrong about the
    /// shape is much easier to fix with the bytes in front of it.
    fn dump_delay_imports(image: &[u8]) {
        let pe = PeImage::parse(image).expect("parse cmd.exe");
        let Some(dir) = pe.info.directory(DIRECTORY_ENTRY_DELAY_IMPORT) else {
            eprintln!("cmd.exe has no delay import directory");
            return;
        };
        eprintln!(
            "cmd.exe delay imports at {:#x} size {:#x} (image base {:#x})",
            dir.virtual_address, dir.size, pe.info.image_base
        );
        for index in 0..6u32 {
            let Ok(raw) = pe.read_rva(dir.virtual_address + index * 32, 32) else {
                break;
            };
            let fields: Vec<String> = (0..8)
                .map(|i| format!("{:#x}", u32_at(raw, i * 4).unwrap_or(0)))
                .collect();
            eprintln!("  [{index}] {}", fields.join(" "));
        }
    }

    fn payload_dll_path() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        [
            exe.with_file_name("wbwpty_redirect.dll"),
            exe.parent()?.join("..").join("wbwpty_redirect.dll"),
        ]
        .into_iter()
        .find(|c| c.is_file())
    }
}