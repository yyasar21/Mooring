// ADR-0013: the app ACL manifest. Every app command needs an explicit `allow-<command>`
// permission in a capability that matches the calling window, local origin or not.
include!("src/guard/table.rs");
// ADR-0028 §1: the build channel (`cfg(mooring_release)`).
include!("src/build_channel.rs");

fn main() {
    channel();
    let names: Vec<&'static str> = COMMANDS.iter().map(|(name, _)| *name).collect();
    let names: &'static [&'static str] = Box::leak(names.into_boxed_slice());
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(names));
    if let Err(e) = tauri_build::try_build(attributes) {
        panic!("tauri-build failed: {e:#}");
    }
}

/// Emit `cfg(mooring_release)` for a release build; refuse a half-release build.
fn channel() {
    // Build-script protocol lines go to stdout by definition (cargo reads them).
    #[allow(clippy::print_stdout)]
    fn emit(line: &str) {
        println!("{line}");
    }
    emit("cargo:rustc-check-cfg=cfg(mooring_release)");
    // ADR-0022: set by the release pipeline for Developer-ID-signed macOS builds (Touch ID).
    emit("cargo:rustc-check-cfg=cfg(mooring_signed_build)");
    emit("cargo:rerun-if-env-changed=TAURI_CONFIG");
    emit(&format!("cargo:rerun-if-env-changed={RELEASE_ENV}"));
    emit("cargo:rerun-if-changed=tauri.conf.json");
    let dir = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let base = std::fs::read_to_string(dir.join("tauri.conf.json"))
        .unwrap_or_else(|e| panic!("tauri.conf.json: {e}"));
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let platform = platform_file(&target_os).and_then(|name| {
        emit(&format!("cargo:rerun-if-changed={name}"));
        std::fs::read_to_string(dir.join(name)).ok()
    });
    let tauri_config = std::env::var("TAURI_CONFIG").ok();
    let flag = std::env::var(RELEASE_ENV).ok();
    match channel_of(&base, platform.as_deref(), tauri_config.as_deref(), flag.as_deref()) {
        Ok((id, channel)) => {
            emit(&format!("cargo:rustc-env=MOORING_EFFECTIVE_IDENTIFIER={id}"));
            if channel == BuildChannel::Release {
                emit("cargo:rustc-cfg=mooring_release");
            }
        }
        Err(e) => panic!("ADR-0028 build identity: {e}"),
    }
}
