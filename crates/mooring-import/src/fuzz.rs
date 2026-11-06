//! Panic-free entry points for the cargo-fuzz targets (ADR-0019 test plan), one per parser
//! plus `detect`. Oracle on every accepted plan: the caps hold, every item passed the core
//! validators (re-checked here), folder and credential keys resolve, and no secret rides
//! along unless the opt-in byte was set (never for mRemoteNG, `PuTTY`, Royal TS or RDM).
//!
//! | target | entry |
//! | --- | --- |
//! | `import_royalts` | [`fuzz_royalts`] |
//! | `import_rdm` | [`fuzz_rdm`] |
//! | `import_termius_csv` | [`fuzz_termius_csv`] |
//! | `import_termius_json` | [`fuzz_termius_json`] |
//! | `import_mremoteng` | [`fuzz_mremoteng`] |
//! | `import_putty_reg` | [`fuzz_putty_reg`] |
//! | `import_putty_session` | [`fuzz_putty_session`] |
//! | `import_ssh_config` | [`fuzz_ssh_config`] |
//! | `import_detect` | [`fuzz_detect`] |

use mooring_core::{validate_host, validate_name, validate_tag, MAX_TAGS};

use crate::{ImportFormat, ImportOptions, ImportPlan, ImportSource, Limits};

/// Fuzz-time caps: the ADR structure caps with a 1 MiB input, so a run stays fast.
const FUZZ_LIMITS: Limits =
    Limits { max_input: 1024 * 1024, max_decompressed: 8 * 1024 * 1024, ..Limits::DEFAULT };

/// The first byte is the opt-in flag (odd = include plaintext secrets), the rest the file.
fn split(data: &[u8]) -> Option<(ImportOptions, &[u8])> {
    let (flag, body) = data.split_first()?;
    let opts = ImportOptions { include_plaintext_secrets: flag % 2 == 1, limits: FUZZ_LIMITS };
    Some((opts, body))
}

/// The oracle every accepted plan must satisfy.
pub fn check_plan(plan: &ImportPlan, opts: &ImportOptions, secrets_possible: bool) {
    let l = &opts.limits;
    assert!(plan.folders.len() <= l.max_folders);
    assert!(plan.connections.len() <= l.max_connections);
    assert!(plan.credentials.len() <= l.max_credentials);
    assert!(plan.skipped.len() <= l.max_notes && plan.warnings.len() <= l.max_notes);
    assert!(plan.is_consistent());
    for f in &plan.folders {
        assert_eq!(validate_name(&f.name).ok().as_deref(), Some(f.name.as_str()));
    }
    for c in &plan.connections {
        assert_eq!(validate_name(&c.name).ok().as_deref(), Some(c.name.as_str()));
        assert_eq!(validate_host(&c.host).ok().as_deref(), Some(c.host.as_str()));
        assert_ne!(c.port, Some(0));
        assert!(c.tags.len() <= MAX_TAGS);
        assert!(c.tags.iter().all(|t| validate_tag(t).ok().as_deref() == Some(t.as_str())));
    }
    for k in &plan.credentials {
        assert_eq!(validate_name(&k.name).ok().as_deref(), Some(k.name.as_str()));
        assert!(!k.has_secret() || (secrets_possible && opts.include_plaintext_secrets));
    }
}

fn run_file(format: ImportFormat, name: &str, data: &[u8]) {
    let Some((opts, body)) = split(data) else { return };
    if let Ok(plan) = crate::parse(format, ImportSource::File { name, bytes: body }, &opts) {
        check_plan(&plan, &opts, format.secrets_possible());
    }
}

/// Royal TS `.rtsx` / `.rtsz`.
pub fn fuzz_royalts(data: &[u8]) {
    run_file(ImportFormat::RoyalTs, "x.rtsx", data);
}

/// RDM `.rdm`.
pub fn fuzz_rdm(data: &[u8]) {
    run_file(ImportFormat::Rdm, "x.rdm", data);
}

/// Termius CSV.
pub fn fuzz_termius_csv(data: &[u8]) {
    run_file(ImportFormat::Termius, "x.csv", data);
}

/// Termius JSON.
pub fn fuzz_termius_json(data: &[u8]) {
    run_file(ImportFormat::Termius, "x.json", data);
}

/// mRemoteNG `confCons.xml`; never a secret.
pub fn fuzz_mremoteng(data: &[u8]) {
    run_file(ImportFormat::Mremoteng, "confCons.xml", data);
}

/// `PuTTY` `.reg`.
pub fn fuzz_putty_reg(data: &[u8]) {
    run_file(ImportFormat::Putty, "x.reg", data);
}

/// `PuTTY` `~/.putty/sessions/*`: the body is split on NUL into `(name, content)` pairs.
pub fn fuzz_putty_session(data: &[u8]) {
    let Some((opts, body)) = split(data) else { return };
    let mut files = Vec::new();
    let mut parts = body.split(|b| *b == 0);
    while let (Some(name), Some(content)) = (parts.next(), parts.next()) {
        files.push((String::from_utf8_lossy(name).into_owned(), content.to_vec()));
        if files.len() >= 64 {
            break;
        }
    }
    if let Ok(plan) = crate::parse(ImportFormat::Putty, ImportSource::Dir(&files), &opts) {
        check_plan(&plan, &opts, false);
    }
}

/// OpenSSH `~/.ssh/config`.
pub fn fuzz_ssh_config(data: &[u8]) {
    run_file(ImportFormat::Openssh, "config", data);
}

/// `detect`: the first byte selects a file name, the rest is the content; a detected format
/// must parse without panicking under the same caps.
pub fn fuzz_detect(data: &[u8]) {
    const NAMES: [&str; 8] =
        ["x.rtsz", "x.rdm", "x.csv", "x.json", "confCons.xml", "x.reg", "config", "blob"];
    let Some((sel, body)) = data.split_first() else { return };
    let name = NAMES[usize::from(*sel) % NAMES.len()];
    if let Some(format) = crate::detect(body, name) {
        let opts = ImportOptions { include_plaintext_secrets: false, limits: FUZZ_LIMITS };
        if let Ok(plan) = crate::parse(format, ImportSource::File { name, bytes: body }, &opts) {
            check_plan(&plan, &opts, format.secrets_possible());
        }
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use super::*;

    #[test]
    fn entries_accept_the_fixtures_and_refuse_garbage() {
        let cases: [(fn(&[u8]), &[u8]); 8] = [
            (fuzz_royalts, include_bytes!("../tests/fixtures/royal.rtsx")),
            (fuzz_rdm, include_bytes!("../tests/fixtures/export.rdm")),
            (fuzz_termius_csv, include_bytes!("../tests/fixtures/termius.csv")),
            (fuzz_termius_json, include_bytes!("../tests/fixtures/termius.json")),
            (fuzz_mremoteng, include_bytes!("../tests/fixtures/confCons.xml")),
            (fuzz_putty_reg, include_bytes!("../tests/fixtures/putty.reg")),
            (fuzz_ssh_config, include_bytes!("../tests/fixtures/ssh_config")),
            (fuzz_detect, include_bytes!("../tests/fixtures/ssh_config")),
        ];
        for (entry, fixture) in cases {
            for flag in [0u8, 1] {
                entry(&[&[flag], fixture].concat());
                entry(&[&[flag], b"\xFF\xFE\x00".as_slice()].concat());
            }
            entry(&[]);
        }
        fuzz_putty_session(b"\x01prod%20web\x00HostName=h.example.test\nProtocol=ssh\n\x00x\x00");
        fuzz_putty_session(&[]);
    }
}
