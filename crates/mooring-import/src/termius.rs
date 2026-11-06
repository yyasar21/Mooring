//! stub
use crate::{ImportFormat, ImportOptions, ImportSource, Importer, Result};

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Termius;

impl Importer for Termius {
    fn format(&self) -> ImportFormat {
        ImportFormat::Termius
    }

    fn sniff(&self, _head: &[u8]) -> bool {
        false
    }

    fn parse(&self, _src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        Ok(crate::PlanBuilder::new(&opts.limits).finish())
    }
}
