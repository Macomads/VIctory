use anyhow::{Result, anyhow, bail, ensure};
use victory_pe::ImageInfo;

const PAGE: usize = 4096;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

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
    let info = ImageInfo::parse(bytes).map_err(|e| anyhow!("parsing the image: {e}"))?;
    let base = usize::try_from(info.image_base)?;
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
    if let Err(error) = fill(base, size, &info, bytes) {
        // SAFETY: unmapping the mapping made above; nothing ran from it.
        unsafe { libc::munmap(mapped, size) };
        return Err(error);
    }
    Ok(MappedImage { base, info })
}

fn fill(base: usize, size: usize, info: &ImageInfo, bytes: &[u8]) -> Result<()> {
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
    protect(base, headers.next_multiple_of(PAGE), libc::PROT_READ)?;
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
        protect(
            base + rva,
            len.next_multiple_of(PAGE),
                protection(section.characteristics),
        )?;
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
    // SAFETY: `start..start + len` lies inside the mapping made by `map_image`.
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

    #[test]
    #[ignore = "needs VICTORY_PROBE_DLL, a DLL exporting `add`"]
    fn a_windows_dll_maps_and_its_export_runs() {
        let path = std::env::var("VICTORY_PROBE_DLL").expect("VICTORY_PROBE_DLL is not set");
        let bytes = std::fs::read(path).unwrap();
        let image = map_image(&bytes).unwrap();
        let add = image.export("add").expect("no export named add");
        // SAFETY: `add` is `int add(int, int)` built for the Windows x64 ABI.
        let add = unsafe { std::mem::transmute::<usize, extern "win64" fn(i32, i32) -> i32>(add) };
        assert_eq!(add(2, 3), 5);
    }
}
