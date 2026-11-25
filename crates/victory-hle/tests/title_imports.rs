use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use victory_hle::{HleResolver, HostPolicy};
use victory_pe::ImageInfo;

#[test]
#[ignore = "needs VICTORY_TITLE_EXE, the title's executable"]
fn title_imports_missing_on_this_host() {
    let exe = PathBuf::from(std::env::var("VICTORY_TITLE_EXE").expect("VICTORY_TITLE_EXE is not set"));
    let dir = exe.parent().unwrap().to_path_buf();
    let shipped: HashMap<String, PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("dll")))
        .map(|path| (path.file_name().unwrap().to_string_lossy().to_ascii_lowercase(), path))
        .collect();
    let resolver = HleResolver::new(HostPolicy::none());
    let mut queue = vec![exe];
    let mut seen = HashSet::new();
    let mut missing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    while let Some(path) = queue.pop() {
        let Ok(info) = ImageInfo::parse(&std::fs::read(&path).unwrap()) else {
            continue;
        };
        for module in info.imports.iter().chain(&info.delay_imports) {
            let dll = module.dll.to_ascii_lowercase();
            if let Some(found) = shipped.get(&dll) {
                if seen.insert(dll) {
                    queue.push(found.clone());
                }
                continue;
            }
            for entry in &module.entries {
                if resolver.classify(&module.dll, &entry.symbol).is_none() {
                    missing.entry(dll.clone()).or_default().insert(entry.symbol.to_string());
                }
            }
        }
    }
    let mut counts: Vec<_> = missing.iter().map(|(dll, set)| (set.len(), dll)).collect();
    counts.sort_by(|a, b| b.cmp(a));
    for (count, dll) in &counts {
        println!("{count:5} {dll}");
    }
    println!("total {}", counts.iter().map(|(count, _)| count).sum::<usize>());
    if let Ok(report) = std::env::var("VICTORY_REPORT") {
        let lines: Vec<String> = missing
            .iter()
            .flat_map(|(dll, set)| set.iter().map(move |symbol| format!("{dll}!{symbol}")))
            .collect();
        std::fs::write(report, lines.join("\n")).unwrap();
    }
}
