// Ensure the Windows build has DYNAMIC_BASE (relocations) so the image can be
// rebased when loaded at a non-preferred address (e.g., under Wine).
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/DYNAMICBASE");
    }
}