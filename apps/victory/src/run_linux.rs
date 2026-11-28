use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use victory_hle::{HleResolver, HostPolicy};
use victory_loader::{
    BindReport, DLL_PROCESS_ATTACH, ThreadEnv, UnimplementedPolicy, WithMappedDlls, map_anywhere,
    map_title_dlls,
};

use crate::{Console, Unimplemented};

pub fn run(
    exe: &Path,
    unimplemented: Unimplemented,
    _strict: bool,
    execute: bool,
    _console: Console,
) -> Result<()> {
    let original = std::fs::read(exe).with_context(|| format!("reading {}", exe.display()))?;
    let image = map_anywhere(&original)?;
    println!(
        "mapped at      {:#x} (preferred {:#x})",
        image.base(),
        image.info().image_base
    );
    let resolver = HleResolver::new(HostPolicy::none());
    let title_dir = exe.parent().unwrap_or(Path::new("."));
    let wanted = |dll: &str| !victory_hle::registry().iter().any(|m| m.serves(dll));
    let dlls = map_title_dlls(image.info(), title_dir, &wanted)?;
    for (name, dll) in &dlls {
        println!("title dll      {name} at {:#x}", dll.base());
    }
    let policy = match unimplemented {
        Unimplemented::Trap => UnimplementedPolicy::Trap,
        Unimplemented::Zero => UnimplementedPolicy::ReturnZero,
    };
    let with_dlls = WithMappedDlls {
        inner: &resolver,
        dlls: &dlls,
    };
    let show = |name: &str, report: BindReport| {
        println!(
            "bound          {name}: {} hle, {} host, {} title, {} missing",
            report.hle,
            report.host,
            report.title,
            report.missing.len()
        );
        for m in &report.missing {
            println!("  missing      {}!{}", m.dll, m.symbol);
        }
    };
    for (name, dll) in &dlls {
        show(name, dll.bind_imports(&with_dlls, policy)?);
    }
    let exe_name = exe.file_name().unwrap_or_default().to_string_lossy();
    show(&exe_name, image.bind_imports(&with_dlls, policy)?);
    if !execute {
        println!("not executing (pass --execute to start the title)");
        return Ok(());
    }
    let stack = usize::try_from(image.info().stack_reserve)
        .unwrap_or(usize::MAX)
        .clamp(1 << 20, 1 << 30);
    let image = Arc::new(image);
    let main_image = image.clone();
    let main = std::thread::Builder::new()
        .name("title-main".into())
        .stack_size(stack)
        .spawn(move || -> Result<u32> {
            let env = ThreadEnv::new(Some(&*main_image))?;
            env.install()?;
            for (name, dll) in &dlls {
                // SAFETY: imports are bound; dependencies come first in `dlls`.
                unsafe { dll.attach() }.with_context(|| format!("attaching {name}"))?;
            }
            // SAFETY: imports of the image are bound.
            unsafe { main_image.run_tls_callbacks(DLL_PROCESS_ATTACH) };
            // SAFETY: this thread has its `ThreadEnv` installed.
            unsafe { main_image.run_entry() }
        })
        .context("spawning title main thread")?;
    let code = main
        .join()
        .map_err(|_| anyhow!("title main thread panicked"))??;
    println!("title exited with {code}");
    Ok(())
}
