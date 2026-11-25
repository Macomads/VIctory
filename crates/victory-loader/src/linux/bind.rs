use std::sync::atomic::AtomicU64;

use anyhow::Result;
use victory_pe::ImportSymbol;

use super::{MappedImage, PAGE, protect, protection};
use crate::thunks::{ImportSite, ThunkBlock, UnimplementedPolicy};
use crate::{ImportResolver, Provenance, Resolution};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingImport {
    pub dll: String,
    pub symbol: String,
}

#[derive(Debug, Default, Clone)]
pub struct BindReport {
    pub hle: usize,
    pub host: usize,
    pub title: usize,
    pub missing: Vec<MissingImport>,
}

impl MappedImage {
    pub fn bind_imports(
        &self,
        resolver: &dyn ImportResolver,
        policy: UnimplementedPolicy,
    ) -> Result<BindReport> {
        let mut report = BindReport::default();
        let mut slots: Vec<(u32, usize)> = Vec::with_capacity(self.info.import_count());
        let mut unresolved: Vec<(u32, &str, &ImportSymbol)> = Vec::new();

        for module in self.info.imports.iter().chain(&self.info.delay_imports) {
            for entry in &module.entries {
                match resolver.resolve(&module.dll, &entry.symbol) {
                    Resolution::Found {
                        address,
                        provenance,
                    } => {
                        match provenance {
                            Provenance::Hle => report.hle += 1,
                            Provenance::Host => report.host += 1,
                            Provenance::Title => report.title += 1,
                        }
                        slots.push((entry.iat_slot_rva, address));
                    }
                    Resolution::Missing => {
                        unresolved.push((entry.iat_slot_rva, &module.dll, &entry.symbol));
                    }
                }
            }
        }

        if !unresolved.is_empty() {
            let mut block = ThunkBlock::new(unresolved.len())?;
            for (slot, dll, symbol) in unresolved {
                let site: &'static ImportSite = Box::leak(Box::new(ImportSite {
                    dll: dll.to_owned(),
                    symbol: symbol.to_string(),
                    policy,
                    calls: AtomicU64::new(0),
                }));
                slots.push((slot, block.emit(site)?));
                report.missing.push(MissingImport {
                    dll: site.dll.clone(),
                    symbol: site.symbol.clone(),
                });
            }
            block.seal()?;
        }

        self.write_slots(&slots)?;
        tracing::info!(
            hle = report.hle,
            host = report.host,
            missing = report.missing.len(),
            "imports bound"
        );
        Ok(report)
    }

    fn write_slots(&self, slots: &[(u32, usize)]) -> Result<()> {
        for &(rva, address) in slots {
            let slot = self.base + rva as usize;
            let page = slot & !(PAGE - 1);
            let restore = self.protection_at(rva as usize);
            protect(page, PAGE, libc::PROT_READ | libc::PROT_WRITE)?;
            // SAFETY: the parser only yields slots inside the image; the page
            // is writable now and the slot is 8-byte aligned by the PE format.
            unsafe { (slot as *mut u64).write_volatile(address as u64) };
            protect(page, PAGE, restore)?;
        }
        Ok(())
    }

    fn protection_at(&self, rva: usize) -> i32 {
        self.info
            .sections
            .iter()
            .find(|section| {
                let start = section.rva as usize;
                rva >= start && rva < start + section.virtual_size.max(section.file_size) as usize
            })
            .map_or(libc::PROT_READ, |section| protection(section.characteristics))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::map_image;

    struct Fixed(Option<usize>);

    impl ImportResolver for Fixed {
        fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Resolution {
            match self.0 {
                Some(address)
                    if dll.eq_ignore_ascii_case("host.dll")
                        && symbol.to_string() == "host_double" =>
                {
                    Resolution::Found {
                        address,
                        provenance: Provenance::Host,
                    }
                }
                _ => Resolution::Missing,
            }
        }
    }

    extern "win64" fn double(x: i32) -> i32 {
        x * 2
    }

    fn run_export(image: &MappedImage) -> extern "win64" fn(i32) -> i32 {
        let run = image.export("run").expect("no export named run");
        // SAFETY: `run` is `int run(int)` built for the Windows x64 ABI.
        unsafe { std::mem::transmute::<usize, extern "win64" fn(i32) -> i32>(run) }
    }

    fn load(variable: &str) -> MappedImage {
        let path = std::env::var(variable).unwrap_or_else(|_| panic!("{variable} is not set"));
        map_image(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    #[ignore = "needs VICTORY_IMPORT_DLL, a DLL importing host.dll!host_double"]
    fn an_import_is_bound_to_our_function() {
        let image = load("VICTORY_IMPORT_DLL");
        let ours = double as *const () as usize;
        let report = image
            .bind_imports(&Fixed(Some(ours)), UnimplementedPolicy::Trap)
            .unwrap();
        assert_eq!(report.host, 1);
        assert!(report.missing.is_empty());
        assert_eq!(run_export(&image)(20), 41);
    }

    #[test]
    #[ignore = "needs VICTORY_IMPORT_DLL2, the same DLL built at another base"]
    fn a_missing_import_reaches_a_reporting_stub() {
        let image = load("VICTORY_IMPORT_DLL2");
        let report = image
            .bind_imports(&Fixed(None), UnimplementedPolicy::ReturnZero)
            .unwrap();
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0].symbol, "host_double");
        assert_eq!(run_export(&image)(20), 1);
    }
}
