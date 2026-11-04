// ADR-0013: the app ACL manifest. Every app command needs an explicit `allow-<command>`
// permission in a capability that matches the calling window, local origin or not.
include!("src/guard/table.rs");

fn main() {
    let names: Vec<&'static str> = COMMANDS.iter().map(|(name, _)| *name).collect();
    let names: &'static [&'static str] = Box::leak(names.into_boxed_slice());
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(names));
    if let Err(e) = tauri_build::try_build(attributes) {
        panic!("tauri-build failed: {e:#}");
    }
}
