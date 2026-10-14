//! Minimal PE32+ reader plus the "map it locally" step of the injector.
//!
//! Only the pieces the injector needs are implemented, and every field read is
//! bounds checked so a malformed DLL produces an error instead of a panic.
//! Layout constants come from `winnt.h`:
//!
//! ```text
//!   DOS_HEADER           e_magic@0x00 e_lfanew@0x3C
//!   NT_HEADERS64         Signature@0x00 FileHeader@0x04 OptionalHeader@0x18
//!   IMAGE_FILE_HEADER    Machine@0x00 NumberOfSections@0x02 SizeOfOptionalHeader@0x10
//!   IMAGE_OPTIONAL_HEADER64 Magic@0x00 AddressOfEntryPoint@0x10 ImageBase@0x18
//!                        SizeOfImage@0x38 SizeOfHeaders@0x3C NumberOfRvaAndSizes@0x6C
//!                        DataDirectory@0x70
//!   IMAGE_SECTION_HEADER Name@0x00 VirtualSize@0x08 VirtualAddress@0x0C
//!                        SizeOfRawData@0x10 PointerToRawData@0x14
//! ```

use anyhow::{bail, Context, Result};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

pub const DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const DIRECTORY_ENTRY_BASERELOC: usize = 5;

pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
/// x64 toolchains emit `DIR64` (absolute 64-bit pointers), **not** `HIGHLOW`.
pub const IMAGE_REL_BASED_DIR64: u16 = 10;
pub const IMAGE_ORDINAL_FLAG64: u64 = 1 << 63;

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

/// Everything the injector needs to know about the payload image.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub machine: u16,
    /// `IMAGE_FILE_DLL` (0x2000) from the characteristics field.
    pub is_dll: bool,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_rva: u32,
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<SectionInfo>,
}

impl PeInfo {
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.directories.get(index).copied().filter(|d| d.size != 0)
    }

    /// `true` when the relocation directory is usable for rebasing.
    pub fn has_relocations(&self) -> bool {
        self.directory(DIRECTORY_ENTRY_BASERELOC).is_some()
    }
}

/// Parsed but not yet relocated view of a PE image.
pub struct PeImage<'a> {
    data: &'a [u8],
    pub info: PeInfo,
}

impl<'a> PeImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x40 || u16_at(data, 0)? != IMAGE_DOS_SIGNATURE {
            bail!("not a PE image: missing MZ signature");
        }
        let e_lfanew = u32_at(data, 0x3c)? as usize;
        if u32_at(data, e_lfanew)? != IMAGE_NT_SIGNATURE {
            bail!("not a PE image: missing PE signature");
        }

        let fh = e_lfanew + 4;
        let machine = u16_at(data, fh)?;
        let number_of_sections = u16_at(data, fh + 2)? as usize;
        let size_of_optional = u16_at(data, fh + 16)? as usize;
        let characteristics = u16_at(data, fh + 18)? as usize;

        let oh = fh + 20;
        let magic = u16_at(data, oh)?;
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            bail!("only PE32+ (x64) images are supported, magic = {magic:#x}");
        }
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            bail!("only x64 images are supported, machine = {machine:#x}");
        }

        let entry_rva = u32_at(data, oh + 0x10)?;
        let image_base = u64_at(data, oh + 0x18)?;
        let size_of_image = u32_at(data, oh + 0x38)?;
        let size_of_headers = u32_at(data, oh + 0x3c)?;
        let number_of_dirs = u32_at(data, oh + 0x6c)? as usize;

        let mut directories = Vec::with_capacity(number_of_dirs.min(16));
        for i in 0..number_of_dirs {
            let off = oh + 0x70 + i * 8;
            if off + 8 > data.len() {
                break;
            }
            directories.push(DataDirectory {
                virtual_address: u32_at(data, off)?,
                size: u32_at(data, off + 4)?,
            });
        }

        let mut sections = Vec::with_capacity(number_of_sections);
        let sh = oh + size_of_optional;
        for i in 0..number_of_sections {
            let off = sh + i * 40;
            let mut name = [0u8; 8];
            name.copy_from_slice(slice(data, off, 8)?);
            sections.push(SectionInfo {
                name: String::from_utf8_lossy(&name)
                    .trim_end_matches('\0')
                    .to_string(),
                virtual_size: u32_at(data, off + 0x08)?,
                virtual_address: u32_at(data, off + 0x0c)?,
                size_of_raw_data: u32_at(data, off + 0x10)?,
                pointer_to_raw_data: u32_at(data, off + 0x14)?,
                characteristics: u32_at(data, off + 0x24)?,
            });
        }

        let info = PeInfo {
            machine,
            is_dll: characteristics & 0x2000 != 0,
            image_base,
            size_of_image,
            size_of_headers,
            entry_rva,
            directories,
            sections,
        };

        Ok(Self { data, info })
    }

    /// Reads a virtual address out of the *file*, mapping through sections.
    pub fn read_rva(&self, rva: u32, len: usize) -> Result<&'a [u8]> {
        // Inside the headers?
        if rva as usize + len <= self.info.size_of_headers as usize {
            return slice(self.data, rva as usize, len).context("reading header rva");
        }
        for s in &self.info.sections {
            let start = s.virtual_address as usize;
            let size = (s.virtual_size.max(s.size_of_raw_data)) as usize;
            if rva as usize >= start && rva as usize + len <= start + size {
                let delta = rva as usize - start;
                if delta + len > s.size_of_raw_data as usize {
                    bail!("rva {rva:#x} is in the zero-filled tail of section {}", s.name);
                }
                return slice(self.data, s.pointer_to_raw_data as usize + delta, len)
                    .with_context(|| format!("reading rva {rva:#x}"));
            }
        }
        bail!("rva {rva:#x} (+{len}) is not inside any section")
    }

    /// Like [`read_rva`] but returns at most what the section still holds, which
    /// is what string reads near the end of a section need.
    pub fn read_rva_clamped(&self, rva: u32, max: usize) -> Result<&'a [u8]> {
        for s in &self.info.sections {
            let start = s.virtual_address as usize;
            let size = (s.virtual_size.max(s.size_of_raw_data)) as usize;
            let offset = rva as usize;
            if offset >= start && offset < start + size {
                let delta = offset - start;
                let available = (size - delta).min(s.size_of_raw_data as usize - delta);
                return slice(self.data, s.pointer_to_raw_data as usize + delta, available.min(max))
                    .with_context(|| format!("reading rva {rva:#x}"));
            }
        }
        bail!("rva {rva:#x} is not inside any section")
    }

    /// Builds the in-memory image: headers plus section data, with `reloc_delta`
    /// applied (delta 0 keeps the preferred base).
    pub fn map(&self, reloc_delta: i64) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.info.size_of_image as usize];
        let headers = self.info.size_of_headers as usize;
        out[..headers.min(self.data.len())]
            .copy_from_slice(&self.data[..headers.min(self.data.len())]);

        for s in &self.info.sections {
            if s.size_of_raw_data == 0 {
                continue;
            }
            let src = slice(
                self.data,
                s.pointer_to_raw_data as usize,
                s.size_of_raw_data as usize,
            )
            .with_context(|| format!("section {}", s.name))?;
            let dst_start = s.virtual_address as usize;
            let dst_end = dst_start + src.len();
            if dst_end > out.len() {
                bail!("section {} overflows SizeOfImage", s.name);
            }
            out[dst_start..dst_end].copy_from_slice(src);
        }

        self.apply_relocations(&mut out, reloc_delta)?;
        Ok(out)
    }

/// Walks `IMAGE_BASE_RELOCATION` blocks and patches the absolute-address slots.
///
/// Both relocation kinds are supported because real toolchains use each of them
/// depending on the architecture: `IMAGE_REL_BASED_HIGHLOW` (3) for 32-bit
/// fields and `IMAGE_REL_BASED_DIR64` (10) for the 64-bit absolute pointers an
/// x64 image is full of.
pub fn apply_relocations(&self, image: &mut [u8], delta: i64) -> Result<()> {
        if delta == 0 {
            return Ok(());
        }
        let Some(dir) = self.info.directory(DIRECTORY_ENTRY_BASERELOC) else {
            bail!("image has no relocation table and must be mapped at its preferred base");
        };

        let mut cursor = dir.virtual_address as usize;
        let end = cursor + dir.size as usize;
        let mut patched = 0usize;

        while cursor + 8 <= end {
            let page_rva = u32_at(image, cursor)?;
            let block_size = u32_at(image, cursor + 4)? as usize;
            if block_size < 8 || cursor + block_size > end {
                bail!("corrupt relocation block at {cursor:#x} (size {block_size})");
            }
            let entries = (block_size - 8) / 2;
            for i in 0..entries {
                let entry_off = cursor + 8 + i * 2;
                let value = u16_at(image, entry_off)?;
                let kind = value >> 12;
                let offset = (value & 0x0fff) as usize;
                if kind == 0 {
                    continue; // IMAGE_REL_BASED_ABSOLUTE (padding)
                }
                let slot = page_rva as usize + offset;
                match kind {
                    IMAGE_REL_BASED_HIGHLOW => {
                        if slot + 4 > image.len() {
                            bail!("relocation slot {slot:#x} outside image");
                        }
                        let current = u32_at(image, slot)?;
                        let moved = (current as i64 + delta) as u32;
                        image[slot..slot + 4].copy_from_slice(&moved.to_le_bytes());
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        if slot + 8 > image.len() {
                            bail!("relocation slot {slot:#x} outside image");
                        }
                        let current = u64_at(image, slot)?;
                        let moved = (current as i64 + delta) as u64;
                        image[slot..slot + 8].copy_from_slice(&moved.to_le_bytes());
                    }
                    other => bail!("unsupported relocation type {other} at {entry_off:#x}"),
                }
                patched += 1;
            }
            cursor += block_size;
        }

        if patched == 0 {
            bail!("relocation directory contained no usable entries");
        }
        Ok(())
    }
}

fn slice(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    data.get(off..off + len)
        .with_context(|| format!("read out of bounds: offset {off:#x} len {len:#x}"))
}

pub fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    let b = slice(data, off, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let b = slice(data, off, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn u64_at(data: &[u8], off: usize) -> Result<u64> {
    let b = slice(data, off, 8)?;
    Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses the real payload build; the synthetic fixtures below only cover
    /// the header arithmetic, not a real linker output.
    #[test]
    fn parses_the_built_payload() {
        let Some(path) = crate::manual_map::tests::payload_dll_path() else {
            eprintln!("skipping: payload not built");
            return;
        };
        let data = std::fs::read(&path).unwrap();
        let pe = PeImage::parse(&data).expect("parse");

        assert!(pe.info.is_dll, "the payload must be a DLL");
        assert_eq!(pe.info.machine, IMAGE_FILE_MACHINE_AMD64);
        assert!(pe.info.has_relocations(), "payload must be rebasable");
        assert!(pe.info.entry_rva != 0);
        assert!(pe.info.size_of_image > pe.info.size_of_headers);
        assert!(pe.info.directory(DIRECTORY_ENTRY_EXPORT).is_some());
        assert!(pe.info.directory(DIRECTORY_ENTRY_IMPORT).is_some());

        // Every section must fit inside SizeOfImage, otherwise the mapped image
        // would be written out of bounds.
        for s in &pe.info.sections {
            assert!(
                s.virtual_address as usize + s.virtual_size as usize
                    <= pe.info.size_of_image as usize,
                "section {} overflows SizeOfImage",
                s.name
            );
        }

        // The image must map cleanly at its preferred base and at a shifted one.
        pe.map(0).expect("map at preferred base");
        pe.map(0x1000).expect("map with relocations");
    }

    fn minimal_x64_dll() -> Vec<u8> {
        // DOS header (0x40) + PE sig + file header + optional header + 1 section.
        // The section's raw data lives at 0x200, so the buffer must reach 0x400
        // for the relocation block that lives inside it.
        let mut d = vec![0u8; 0x400];
        d[0x00..0x02].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        // file header
        d[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // sections
        d[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // size of optional header
        d[0x96..0x98].copy_from_slice(&0x2000u16.to_le_bytes()); // DLL
        // optional header
        d[0x98..0x9a].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        d[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes()); // entry rva
        d[0xb0..0xb8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        d[0xd0..0xd4].copy_from_slice(&0x4000u32.to_le_bytes()); // size of image
        d[0xd4..0xd8].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
        d[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // number of data dirs
        // section header at 0x98 + 240 = 0x188
        let sh = 0x188;
        d[sh..sh + 8].copy_from_slice(b".text\0\0\0");
        d[sh + 0x0c..sh + 0x10].copy_from_slice(&0x1000u32.to_le_bytes());
        d[sh + 0x10..sh + 0x14].copy_from_slice(&0x200u32.to_le_bytes());
        d[sh + 0x14..sh + 0x18].copy_from_slice(&0x200u32.to_le_bytes());
        d
    }

    #[test]
    fn parses_headers() {
        let d = minimal_x64_dll();
        let pe = PeImage::parse(&d).unwrap();
        assert_eq!(pe.info.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(pe.info.image_base, 0x1_8000_0000);
        assert_eq!(pe.info.size_of_image, 0x4000);
        assert_eq!(pe.info.entry_rva, 0x1000);
        assert_eq!(pe.info.sections.len(), 1);
        assert_eq!(pe.info.sections[0].name, ".text");
    }

    #[test]
    fn rejects_non_pe_and_non_x64() {
        assert!(PeImage::parse(b"nope").is_err());
        let mut d = minimal_x64_dll();
        d[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        assert!(PeImage::parse(&d).is_err());
    }

    #[test]
    fn relocates_highlow_entries() {
        let mut d = minimal_x64_dll();
        // Relocation directory entry #5 at optional header + 0x70 + 5*8.
        // The directory lives at rva 0x1100, i.e. file offset 0x200 + 0x100.
        let dir = 0x98 + 0x70 + 5 * 8;
        d[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        d[dir + 4..dir + 8].copy_from_slice(&24u32.to_le_bytes());
        // Block at rva 0x1100 (file 0x300): page rva 0x1000, size 24,
        // entries: HIGHLOW@0x20, DIR64@0x28, ABSOLUTE padding.
        d[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes());
        d[0x304..0x308].copy_from_slice(&24u32.to_le_bytes());
        d[0x308..0x30a]
            .copy_from_slice(&((IMAGE_REL_BASED_HIGHLOW << 12) | 0x20).to_le_bytes());
        d[0x30a..0x30c]
            .copy_from_slice(&((IMAGE_REL_BASED_DIR64 << 12) | 0x28).to_le_bytes());
        d[0x30c..0x30e].copy_from_slice(&0u16.to_le_bytes());
        d[0x30e..0x310].copy_from_slice(&0u16.to_le_bytes());
        d[0x310..0x312].copy_from_slice(&0u16.to_le_bytes());
        d[0x312..0x314].copy_from_slice(&0u16.to_le_bytes());
        d[0x314..0x316].copy_from_slice(&0u16.to_le_bytes());
        // Values at rva 0x1020/0x1028 live in the file at 0x200 + (rva - 0x1000).
        d[0x220..0x224].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        d[0x228..0x230].copy_from_slice(&0x2222_2222_3333_4444u64.to_le_bytes());

        let pe = PeImage::parse(&d).unwrap();
        assert!(pe.info.has_relocations());
        let image = pe.map(0x20).unwrap();
        assert_eq!(u32_at(&image, 0x1020).unwrap(), 0x1111_1131);
        assert_eq!(u64_at(&image, 0x1028).unwrap(), 0x2222_2222_3333_4464);
        // Mapping with delta 0 must not touch anything.
        let image0 = pe.map(0).unwrap();
        assert_eq!(u32_at(&image0, 0x1020).unwrap(), 0x1111_1111);
        assert_eq!(u64_at(&image0, 0x1028).unwrap(), 0x2222_2222_3333_4444);
    }

    #[test]
    fn refuses_to_map_without_relocations_at_other_bases() {
        let d = minimal_x64_dll();
        let pe = PeImage::parse(&d).unwrap();
        assert!(!pe.info.has_relocations());
        assert!(pe.map(0x1000).is_err());
    }
}