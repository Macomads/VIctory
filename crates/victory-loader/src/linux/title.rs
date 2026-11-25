use crate::linux::{ThreadEnv, map_image};

#[test]
#[ignore = "needs VICTORY_TITLE_EXE, the title's executable"]
fn the_title_executable_maps_with_its_tls() {
    let path = std::env::var("VICTORY_TITLE_EXE").expect("VICTORY_TITLE_EXE is not set");
    let bytes = std::fs::read(path).unwrap();
    let image = map_image(&bytes).unwrap();
    let info = image.info();
    println!(
        "base {:#x} size {:#x} sections {} imports {} delay {} exports {}",
        image.base(),
        info.size_of_image,
        info.sections.len(),
        info.import_count(),
        info.delay_imports.len(),
        info.exports.len()
    );
    println!(
        "relocations {} exception table {} load config {} tls {:?}",
        info.has_relocations, info.has_exception_table, info.has_load_config, info.tls
    );
    ThreadEnv::new(Some(&image)).unwrap();
}

#[test]
#[ignore = "needs VICTORY_TITLE_EXE, the title's executable"]
fn the_title_imports_by_dll() {
    let path = std::env::var("VICTORY_TITLE_EXE").expect("VICTORY_TITLE_EXE is not set");
    let info = victory_pe::ImageInfo::parse(&std::fs::read(path).unwrap()).unwrap();
    let mut modules: Vec<_> = info
        .imports
        .iter()
        .map(|module| (module.entries.len(), module.dll.to_ascii_lowercase()))
        .collect();
    modules.sort_by(|a, b| b.0.cmp(&a.0));
    for (count, dll) in modules {
        println!("{count:5} {dll}");
    }
}
