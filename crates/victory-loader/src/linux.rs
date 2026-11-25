use anyhow::{Result, anyhow, bail, ensure};
use victory_pe::ImageInfo;
use victory_pe::layout::{self, dir};

const PAGE: usize = 4096;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;
const REL_ABSOLUTE: u16 = 0;
const REL_DIR64: u16 = 10;

mod bind;

pub use bind::{BindReport, MissingImport};
mod teb;
#[cfg(test)]
mod title;
pub use teb::ThreadEnv;

#[derive(Debug)]
pub struct MappedImage {
    base: usize,
    info: ImageInfo,
}

impl MappedImage {
    pub fn base(&self) -> usize {
        self.base
    }

    pub fn info(&self) -> &ImageInfo {
        &self.info
    }

    pub fn export(&self, name: &str) -> Option<usize> {
        self.info
            .exports
            .iter()
            .find(|export| export.name.as_deref() == Some(name))
            .and_then(|export| export.rva)
            .map(|rva| self.base + rva as usize)
    }
}

pub fn map_image(bytes: &[u8]) -> Result<MappedImage> {
    map_image_at(bytes, None)
}

pub fn map_image_at(bytes: &[u8], at: Option<usize>) -> Result<MappedImage> {
    let info = ImageInfo::parse(bytes).map_err(|e| anyhow!("parsing the image: {e}"))?;
    let base = match at {
        Some(at) => at,
        None => usize::try_from(info.image_base)?,
    };
    ensure!(base % PAGE == 0, "image base {base:#x} is not page aligned");
    let size = (info.size_of_image as usize).next_multiple_of(PAGE);
    // SAFETY: MAP_FIXED_NOREPLACE never replaces an existing mapping; the
    // call fails instead.
    let mapped = unsafe {
        libc::mmap(
            base as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        bail!(
            "mapping {size:#x} bytes at {base:#x} failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if mapped as usize != base {
        // SAFETY: unmapping the mapping we just made.
        unsafe { libc::munmap(mapped, size) };
        bail!(
            "the kernel placed the image at {:#x}, not at {base:#x}",
            mapped as usize
        );
    }
    if let Err(error) = populate(base, size, &info, bytes) {
        // SAFETY: unmapping the mapping made above; nothing ran from it.
        unsafe { libc::munmap(mapped, size) };
        return Err(error);
    }
    Ok(MappedImage { base, info })
}

fn populate(base: usize, size: usize, info: &ImageInfo, bytes: &[u8]) -> Result<()> {
    let headers = info
        .sections
        .iter()
        .map(|section| section.rva as usize)
        .min()
        .unwrap_or(0)
        .min(bytes.len())
        .min(size);
    // SAFETY: `headers <= size`, inside the writable mapping.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, headers) };
    for section in &info.sections {
        let rva = section.rva as usize;
        let len = section.virtual_size.max(section.file_size) as usize;
        ensure!(rva % PAGE == 0, "section {} is not page aligned", section.name);
        ensure!(rva + len <= size, "section {} exceeds the image", section.name);
        let copy = if section.virtual_size == 0 {
            section.file_size
        } else {
            section.file_size.min(section.virtual_size)
        } as usize;
        let start = section.file_offset as usize;
        let raw = bytes
            .get(start..start + copy)
            .ok_or_else(|| anyhow!("section {} lies outside the file", section.name))?;
        // SAFETY: `rva + len <= size` and `copy <= len`, inside the mapping.
        unsafe { std::ptr::copy_nonoverlapping(raw.as_ptr(), (base + rva) as *mut u8, copy) };
    }
    relocate(base, info, bytes)?;
    protect(base, headers.next_multiple_of(PAGE), libc::PROT_READ)?;
    for section in &info.sections {
        let len = section.virtual_size.max(section.file_size) as usize;
        protect(
            base + section.rva as usize,
            len.next_multiple_of(PAGE),
            protection(section.characteristics),
        )?;
    }
    Ok(())
}

fn relocate(base: usize, info: &ImageInfo, bytes: &[u8]) -> Result<()> {
    let delta = base.wrapping_sub(info.image_base as usize);
    if delta == 0 {
        return Ok(());
    }
    ensure!(
        info.has_relocations,
        "the image has no relocations and cannot be moved from {:#x}",
        info.image_base
    );
    let entry = layout::data_directory_offset(bytes, dir::BASERELOC)
        .ok_or_else(|| anyhow!("no relocation directory"))?;
    let rva = layout::read_u32(bytes, entry).ok_or_else(|| anyhow!("no relocation RVA"))?;
    let len = layout::read_u32(bytes, entry + 4).ok_or_else(|| anyhow!("no relocation size"))?;
    let start = info
        .rva_to_file_offset(rva)
        .ok_or_else(|| anyhow!("relocation table is not backed by the file"))? as usize;
    let table = bytes
        .get(start..start + len as usize)
        .ok_or_else(|| anyhow!("relocation table lies outside the file"))?;
    let image_size = info.size_of_image as usize;
    let mut cursor = 0;
    while cursor + 8 <= table.len() {
        let page = u32::from_le_bytes(table[cursor..cursor + 4].try_into()?) as usize;
        let block = u32::from_le_bytes(table[cursor + 4..cursor + 8].try_into()?) as usize;
        ensure!(
            block >= 8 && cursor + block <= table.len(),
            "malformed relocation block"
        );
        for raw in table[cursor + 8..cursor + block].chunks_exact(2) {
            let entry = u16::from_le_bytes([raw[0], raw[1]]);
            let (kind, offset) = (entry >> 12, (entry & 0x0fff) as usize);
            match kind {
                REL_ABSOLUTE => {}
                REL_DIR64 => {
                    let at = page + offset;
                    ensure!(at + 8 <= image_size, "relocation at {at:#x} is outside the image");
                    let slot = (base + at) as *mut u64;
                    // SAFETY: `at + 8 <= image_size`, inside the writable mapping.
                    unsafe { slot.write_unaligned(slot.read_unaligned().wrapping_add(delta as u64)) };
                }
                other => bail!("unsupported relocation type {other}"),
            }
        }
        cursor += block;
    }
    Ok(())
}

fn protection(characteristics: u32) -> i32 {
    let mut prot = libc::PROT_NONE;
    if characteristics & SCN_MEM_READ != 0 {
        prot |= libc::PROT_READ;
    }
    if characteristics & SCN_MEM_WRITE != 0 {
        prot |= libc::PROT_WRITE;
    }
    if characteristics & SCN_MEM_EXECUTE != 0 {
        prot |= libc::PROT_EXEC;
    }
    prot
}

fn protect(start: usize, len: usize, prot: i32) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: `start..start + len` lies inside the mapping made by `map_image_at`.
    let ok = unsafe { libc::mprotect(start as *mut libc::c_void, len, prot) };
    if ok != 0 {
        bail!(
            "mprotect({start:#x}, {len:#x}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(variable: &str) -> Vec<u8> {
        let path = std::env::var(variable).unwrap_or_else(|_| panic!("{variable} is not set"));
        std::fs::read(path).unwrap()
    }

    #[test]
    #[ignore = "needs VICTORY_PROBE_DLL, a DLL exporting `add`"]
    fn a_windows_dll_maps_and_its_export_runs() {
        let image = map_image(&read("VICTORY_PROBE_DLL")).unwrap();
        let add = image.export("add").expect("no export named add");
        // SAFETY: `add` is `int add(int, int)` built for the Windows x64 ABI.
        let add = unsafe { std::mem::transmute::<usize, extern "win64" fn(i32, i32) -> i32>(add) };
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    #[ignore = "needs VICTORY_RELOC_DLL, a DLL exporting `get` with a relocated pointer"]
    fn a_moved_dll_is_relocated() {
        let bytes = read("VICTORY_RELOC_DLL");
        let info = ImageInfo::parse(&bytes).unwrap();
        assert!(info.has_relocations);
        let moved = info.image_base as usize + 0x10_0000;
        let image = map_image_at(&bytes, Some(moved)).unwrap();
        assert_ne!(image.base(), info.image_base as usize);
        let get = image.export("get").expect("no export named get");
        // SAFETY: `get` is `int get(void)` built for the Windows x64 ABI.
        let get = unsafe { std::mem::transmute::<usize, extern "win64" fn() -> i32>(get) };
        assert_eq!(get(), 7);
    }
}
