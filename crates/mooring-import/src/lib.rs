//! Mooring importers (ADR-0019): Royal TS, Remote Desktop Manager, Termius, mRemoteNG,
//! PuTTY and OpenSSH exports into a dry-run [`ImportPlan`]. Pure: no I/O, no store; the
//! Tauri shell picks the file, keeps the plan under a `planId` and applies it.
//!
//! Every input is hostile (T3). Each parser runs under [`Limits`], refuses `<!DOCTYPE`,
//! validates every item with the `mooring-core` validators (an invalid item is `skipped`, not
//! an error) and has a fuzz entry in [`fuzz`]. Secrets leave a parser only inside a
//! [`SecretBundle`], only from a plaintext field and only with
//! [`ImportOptions::include_plaintext_secrets`] (owner decision 16); mRemoteNG passwords are
//! never imported (owner decision 17).

#![forbid(unsafe_code)]

pub mod creds;
mod csv;
mod error;
pub mod fuzz;
mod gzip;
mod limits;
mod mremoteng;
mod openssh;
mod plan;
mod putty;
mod rdm;
mod royalts;
mod termius;
mod text;
mod xml;

use serde::{Deserialize, Serialize};

pub use error::{ImportError, Result};
pub use limits::Limits;
pub use plan::{
    Counts, ImportPlan, NewConnection, NewCredential, PlanBuilder, PlanConnection,
    PlanCredential, PlanFolder, SecretBundle, SkipReason, Skipped, Warning, WarningCode,
};

/// The file formats (ADR-0019 §2). Wire names are `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    /// Royal TS `.rtsx` / `.rtsz`.
    RoyalTs,
    /// Remote Desktop Manager `.rdm` XML export.
    Rdm,
    /// Termius CSV or JSON export.
    Termius,
    /// mRemoteNG `confCons.xml`.
    Mremoteng,
    /// PuTTY `.reg` export or `~/.putty/sessions/*`.
    Putty,
    /// OpenSSH `~/.ssh/config`.
    Openssh,
}

impl ImportFormat {
    /// Every format, in picker order.
    pub const ALL: [Self; 6] =
        [Self::RoyalTs, Self::Rdm, Self::Termius, Self::Mremoteng, Self::Putty, Self::Openssh];

    /// Stable wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RoyalTs => "royal_ts",
            Self::Rdm => "rdm",
            Self::Termius => "termius",
            Self::Mremoteng => "mremoteng",
            Self::Putty => "putty",
            Self::Openssh => "openssh",
        }
    }

    /// Human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RoyalTs => "Royal TS",
            Self::Rdm => "Remote Desktop Manager",
            Self::Termius => "Termius",
            Self::Mremoteng => "mRemoteNG",
            Self::Putty => "PuTTY",
            Self::Openssh => "OpenSSH config",
        }
    }

    /// File extensions of the picker filter (empty: a known location).
    #[must_use]
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::RoyalTs => &["rtsx", "rtsz"],
            Self::Rdm => &["rdm", "xml"],
            Self::Termius => &["csv", "json"],
            Self::Mremoteng => &["xml"],
            Self::Putty => &["reg"],
            Self::Openssh => &[],
        }
    }

    /// Whether the format can carry plaintext secrets the user may opt into.
    #[must_use]
    pub const fn secrets_possible(self) -> bool {
        matches!(self, Self::Termius | Self::Openssh)
    }

    /// Parse by wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    /// The importer.
    #[must_use]
    pub fn importer(self) -> &'static dyn Importer {
        match self {
            Self::RoyalTs => &royalts::RoyalTs,
            Self::Rdm => &rdm::Rdm,
            Self::Termius => &termius::Termius,
            Self::Mremoteng => &mremoteng::Mremoteng,
            Self::Putty => &putty::Putty,
            Self::Openssh => &openssh::Openssh,
        }
    }
}

/// What a parser receives: one file, or the files of a directory (`~/.putty/sessions`).
#[derive(Debug, Clone, Copy)]
pub enum ImportSource<'a> {
    /// One file.
    File {
        /// File name (extension hint only).
        name: &'a str,
        /// Content.
        bytes: &'a [u8],
    },
    /// Directory members as `(file name, content)`.
    Dir(&'a [(String, Vec<u8>)]),
}

/// Parse options.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportOptions {
    /// Owner decision 16: plaintext secrets of plaintext formats ride in the plan.
    pub include_plaintext_secrets: bool,
    /// Caps.
    pub limits: Limits,
}

/// One format's parser.
pub trait Importer: Send + Sync {
    /// Which format.
    fn format(&self) -> ImportFormat;
    /// Whether the first bytes look like this format (a picker hint, never trusted).
    fn sniff(&self, head: &[u8]) -> bool;
    /// Dry run: the plan, or an error that names no content.
    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<ImportPlan>;
}

/// First 4 KiB used by [`detect`] and [`Importer::sniff`].
pub const SNIFF_LEN: usize = 4096;

/// Guess the format from the file name, then the content. `None` when nothing matches.
#[must_use]
pub fn detect(bytes: &[u8], filename: &str) -> Option<ImportFormat> {
    let lower = filename.rsplit(['/', '\\']).next().unwrap_or(filename).to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e.to_owned()).unwrap_or_default();
    let by_name = match (lower.as_str(), ext.as_str()) {
        (_, "rtsx" | "rtsz") => Some(ImportFormat::RoyalTs),
        (_, "rdm") => Some(ImportFormat::Rdm),
        (_, "reg") => Some(ImportFormat::Putty),
        ("confcons.xml", _) => Some(ImportFormat::Mremoteng),
        ("config" | "ssh_config", _) => Some(ImportFormat::Openssh),
        _ => None,
    };
    if by_name.is_some() {
        return by_name;
    }
    let head = &bytes[..bytes.len().min(SNIFF_LEN)];
    ImportFormat::ALL.into_iter().find(|f| f.importer().sniff(head))
}

/// Check the raw size cap(s) of a source.
pub(crate) fn check_input_size(src: &ImportSource<'_>, limits: &Limits) -> Result<()> {
    let too_large = match src {
        ImportSource::File { bytes, .. } => bytes.len() > limits.max_input,
        ImportSource::Dir(files) => {
            files.iter().any(|(_, b)| b.len() > limits.max_input)
                || files.iter().map(|(_, b)| b.len()).sum::<usize>() > limits.max_input
        }
    };
    if too_large {
        return Err(ImportError::TooLarge { max: limits.max_input });
    }
    Ok(())
}

/// Parse `src` as `format`.
pub fn parse(format: ImportFormat, src: ImportSource<'_>, opts: &ImportOptions) -> Result<ImportPlan> {
    check_input_size(&src, &opts.limits)?;
    format.importer().parse(src, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for f in ImportFormat::ALL {
            assert_eq!(ImportFormat::parse(f.name()), Some(f));
            assert_eq!(f.importer().format(), f);
            assert_eq!(serde_json::to_value(f).expect("json"), f.name());
        }
        assert_eq!(ImportFormat::parse("zip"), None);
    }

    #[test]
    fn detect_by_name_then_content() {
        assert_eq!(detect(b"", "x.RTSZ"), Some(ImportFormat::RoyalTs));
        assert_eq!(detect(b"", "/home/u/Export.rdm"), Some(ImportFormat::Rdm));
        assert_eq!(detect(b"", "C:\\x\\confCons.xml"), Some(ImportFormat::Mremoteng));
        assert_eq!(detect(b"", "config"), Some(ImportFormat::Openssh));
        assert_eq!(detect(b"", "sessions.reg"), Some(ImportFormat::Putty));
        assert_eq!(detect(b"\x1F\x8B\x08", "blob"), Some(ImportFormat::RoyalTs));
        assert_eq!(detect(b"<mrng:Connections", "x.xml"), Some(ImportFormat::Mremoteng));
        assert_eq!(detect(b"<ArrayOfConnection>", "x.xml"), Some(ImportFormat::Rdm));
        assert_eq!(detect(b"Windows Registry Editor Version 5.00", "x"), Some(ImportFormat::Putty));
        assert_eq!(detect(b"Host web\n  HostName h", "x"), Some(ImportFormat::Openssh));
        assert_eq!(detect(b"Groups,Label,Hostname\n", "x"), Some(ImportFormat::Termius));
        assert_eq!(detect(b"\x00\x01\x02", "x.bin"), None);
    }

    #[test]
    fn size_cap_applies_to_files_and_dirs() {
        let mut opts = ImportOptions::default();
        opts.limits.max_input = 4;
        let big = ImportSource::File { name: "a", bytes: b"12345" };
        assert_eq!(parse(ImportFormat::Openssh, big, &opts).err(), Some(ImportError::TooLarge { max: 4 }));
        let files = vec![("a".to_owned(), vec![0; 3]), ("b".to_owned(), vec![0; 3])];
        assert_eq!(check_input_size(&ImportSource::Dir(&files), &opts.limits), Err(ImportError::TooLarge { max: 4 }));
        let small = ImportSource::File { name: "a", bytes: b"1234" };
        assert!(parse(ImportFormat::Openssh, small, &opts).is_ok());
    }
}
