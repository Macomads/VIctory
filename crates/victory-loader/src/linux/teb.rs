use anyhow::{Result, bail, ensure};

use super::{MappedImage, PAGE};

const ARCH_SET_GS: libc::c_long = 0x1001;
const TEB_LEN: usize = 0x2000;
const TEB_SELF: usize = 0x30;
const TEB_TLS_ARRAY: usize = 0x58;
const TLS_ARRAY_AT: usize = 0x1000;

pub struct ThreadEnv {
    teb: *mut u8,
    block: *mut u8,
    block_len: usize,
}

fn alloc(len: usize) -> Result<*mut u8> {
    // SAFETY: fresh anonymous mapping; no existing memory is touched.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        bail!("mmap failed: {}", std::io::Error::last_os_error());
    }
    Ok(base.cast())
}

impl MappedImage {
    fn tls_template(&self) -> Result<(usize, usize, usize)> {
        let Some(tls) = &self.info.tls else {
            return Ok((0, 0, 0));
        };
        let directory = (self.base + tls.directory_rva as usize) as *const u64;
        // SAFETY: the TLS directory lies inside the mapped image and was
        // relocated with it; reads are unaligned-safe.
        let (start, end, zero) = unsafe {
            (
                directory.read_unaligned() as usize,
                directory.add(1).read_unaligned() as usize,
                (directory.add(4) as *const u32).read_unaligned() as usize,
            )
        };
        let image_end = self.base + self.info.size_of_image as usize;
        ensure!(
            start >= self.base && start <= end && end <= image_end,
            "TLS template {start:#x}..{end:#x} is outside the image"
        );
        Ok((start, end - start, zero))
    }
}

impl ThreadEnv {
    pub fn new(image: Option<&MappedImage>) -> Result<Self> {
        let (start, template, zero) = match image {
            Some(image) => image.tls_template()?,
            None => (0, 0, 0),
        };
        let block_len = (template + zero).next_multiple_of(PAGE).max(PAGE);
        let block = alloc(block_len)?;
        if template > 0 {
            // SAFETY: `start..start + template` was checked to lie inside the
            // image, and the block is at least `template` bytes.
            unsafe { std::ptr::copy_nonoverlapping(start as *const u8, block, template) };
        }
        let teb = alloc(TEB_LEN)?;
        // SAFETY: offsets are inside the TEB mapping, 8-byte aligned.
        unsafe {
            (teb.add(TEB_SELF) as *mut usize).write(teb as usize);
            let array = teb.add(TLS_ARRAY_AT) as *mut usize;
            array.write(block as usize);
            (teb.add(TEB_TLS_ARRAY) as *mut usize).write(array as usize);
        }
        Ok(ThreadEnv {
            teb,
            block,
            block_len,
        })
    }

    pub fn install(&self) -> Result<()> {
        // SAFETY: points this thread's GS base at our TEB, which lives as long
        // as `self`; glibc does not use GS on x86-64.
        let result = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, self.teb as usize) };
        if result != 0 {
            bail!("arch_prctl(ARCH_SET_GS) failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn teb(&self) -> usize {
        self.teb as usize
    }

    pub fn tls_block(&self) -> *mut u8 {
        self.block
    }
}

impl Drop for ThreadEnv {
    fn drop(&mut self) {
        // SAFETY: unmapping the mappings made in `new`; the caller must not
        // run title code on this thread afterwards.
        unsafe {
            libc::munmap(self.teb.cast(), TEB_LEN);
            libc::munmap(self.block.cast(), self.block_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::map_image;

    #[test]
    #[ignore = "needs VICTORY_TLS_DLL, a DLL exporting `tls_read` and `teb_self`"]
    fn title_code_finds_its_tls_through_gs() {
        let path = std::env::var("VICTORY_TLS_DLL").expect("VICTORY_TLS_DLL is not set");
        let image = map_image(&std::fs::read(path).unwrap()).unwrap();
        let env = ThreadEnv::new(Some(&image)).unwrap();
        env.install().unwrap();
        // SAFETY: the block is writable and at least a page long.
        unsafe { (env.tls_block() as *mut i32).write(42) };
        let read = image.export("tls_read").expect("no export named tls_read");
        let own = image.export("teb_self").expect("no export named teb_self");
        // SAFETY: `tls_read` is `int tls_read(void)` for the Windows x64 ABI.
        let read = unsafe { std::mem::transmute::<usize, extern "win64" fn() -> i32>(read) };
        // SAFETY: `teb_self` is `uint64 teb_self(void)` for the Windows x64 ABI.
        let own = unsafe { std::mem::transmute::<usize, extern "win64" fn() -> u64>(own) };
        assert_eq!(read(), 42);
        assert_eq!(own() as usize, env.teb());
    }
}
