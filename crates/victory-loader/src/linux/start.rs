use std::collections::HashSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use victory_pe::{ImageInfo, ImportSymbol};

use super::{MappedImage, PAGE, map_image, map_image_at};
use crate::{DLL_PROCESS_ATTACH, ImportResolver, Provenance, Resolution};

impl MappedImage {
    pub fn export_symbol(&self, symbol: &ImportSymbol) -> Option<usize> {
        match symbol {
            ImportSymbol::Name { name, .. } => self.export(name),
            ImportSymbol::Ordinal(ordinal) => self
                .info
                .exports
                .iter()
                .find(|export| export.ordinal == *ordinal)
                .and_then(|export| export.rva)
                .map(|rva| self.base + rva as usize),
        }
    }

    /// # Safety
    /// Runs title code. Imports must be bound first.
    pub unsafe fn run_tls_callbacks(&self, reason: u32) {
        let Some(tls) = &self.info.tls else { return };
        type TlsCallback = unsafe extern "win64" fn(*mut c_void, u32, *mut c_void);
        for &rva in &tls.callback_rvas {
            // SAFETY: the RVA came from the image's own TLS directory.
            let callback = unsafe {
                std::mem::transmute::<usize, TlsCallback>(self.base + rva as usize)
            };
            // SAFETY: the caller guarantees imports are bound.
            unsafe { callback(self.base as *mut c_void, reason, std::ptr::null_mut()) };
        }
    }

    /// # Safety
    /// Runs title code. Imports must be bound first, and the DLLs this one
    /// depends on attached.
    pub unsafe fn attach(&self) -> Result<()> {
        // SAFETY: forwarded from the caller.
        unsafe { self.run_tls_callbacks(DLL_PROCESS_ATTACH) };
        if !self.info.is_dll() || self.info.entry_rva == 0 {
            return Ok(());
        }
        type DllMain = unsafe extern "win64" fn(*mut c_void, u32, *mut c_void) -> i32;
        // SAFETY: the entry RVA came from the image header.
        let main = unsafe {
            std::mem::transmute::<usize, DllMain>(self.base + self.info.entry_rva as usize)
        };
        // SAFETY: forwarded from the caller.
        let ok = unsafe { main(self.base as *mut c_void, DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
        if ok == 0 {
            bail!("DllMain returned FALSE");
        }
        Ok(())
    }

    /// # Safety
    /// Runs title code on this thread, which must have a `ThreadEnv` installed.
    /// Imports must be bound first.
    pub unsafe fn run_entry(&self) -> Result<u32> {
        if self.info.entry_rva == 0 {
            bail!("image has no entry point");
        }
        type Entry = unsafe extern "win64" fn(*mut c_void) -> u32;
        // SAFETY: the entry RVA came from the image header.
        let entry = unsafe {
            std::mem::transmute::<usize, Entry>(self.base + self.info.entry_rva as usize)
        };
        // SAFETY: forwarded from the caller.
        Ok(unsafe { entry(std::ptr::null_mut()) })
    }
}

pub fn map_anywhere(bytes: &[u8]) -> Result<MappedImage> {
    if let Ok(image) = map_image(bytes) {
        return Ok(image);
    }
    let info = ImageInfo::parse(bytes).map_err(|e| anyhow!("parsing the image: {e}"))?;
    let size = (info.size_of_image as usize).next_multiple_of(PAGE);
    // SAFETY: a fresh inaccessible mapping, only used to learn a free address.
    let probe = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if probe == libc::MAP_FAILED {
        bail!("no free address range of {size:#x} bytes");
    }
    // SAFETY: unmapping the probe made above.
    unsafe { libc::munmap(probe, size) };
    map_image_at(bytes, Some(probe as usize))
}

pub fn map_title_dlls(
    main: &ImageInfo,
    title_dir: &Path,
    wanted: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, MappedImage)>> {
    let mut loaded = Vec::new();
    map_imports(main, title_dir, wanted, &mut HashSet::new(), &mut loaded)?;
    Ok(loaded)
}

fn map_imports(
    info: &ImageInfo,
    dir: &Path,
    wanted: &dyn Fn(&str) -> bool,
    seen: &mut HashSet<String>,
    loaded: &mut Vec<(String, MappedImage)>,
) -> Result<()> {
    for module in info.imports.iter().chain(&info.delay_imports) {
        map_dll(&module.dll, dir, wanted, seen, loaded)?;
    }
    Ok(())
}

fn map_dll(
    name: &str,
    dir: &Path,
    wanted: &dyn Fn(&str) -> bool,
    seen: &mut HashSet<String>,
    loaded: &mut Vec<(String, MappedImage)>,
) -> Result<()> {
    let name = name.to_ascii_lowercase();
    if !seen.insert(name.clone()) || !wanted(&name) {
        return Ok(());
    }
    let Some(path) = find_file(dir, &name) else {
        return Ok(());
    };
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let image = map_anywhere(&bytes).with_context(|| format!("mapping {}", path.display()))?;
    map_imports(image.info(), dir, wanted, seen, loaded)?;
    loaded.push((name, image));
    Ok(())
}

fn find_file(dir: &Path, lower: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().to_ascii_lowercase() == lower)
        })
}

pub struct WithMappedDlls<'a> {
    pub inner: &'a dyn ImportResolver,
    pub dlls: &'a [(String, MappedImage)],
}

impl ImportResolver for WithMappedDlls<'_> {
    fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Resolution {
        let found = self.inner.resolve(dll, symbol);
        if found != Resolution::Missing {
            return found;
        }
        self.dlls
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(dll))
            .and_then(|(_, image)| image.export_symbol(symbol))
            .map_or(Resolution::Missing, |address| Resolution::Found {
                address,
                provenance: Provenance::Title,
            })
    }
}
