//! Linux (and every other non-macOS, non-Windows target): biometric unlock is not offered
//! (ADR-0022 §1). Secret Service has no biometric ACL and `fprintd` gates sessions, not items,
//! so no store could promise that a same-user process (T2) cannot read the key silently.
//! Every call answers `no_acl`; Settings explains why.

use mooring_vault::Uuid;
use zeroize::Zeroizing;

use super::{BioError, BiometricStore, Unavailable, KEY_LEN};

/// The store that refuses everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStore;

impl BiometricStore for NoStore {
    fn platform(&self) -> &'static str {
        "linux"
    }
    fn label(&self) -> Option<&'static str> {
        None
    }
    fn available(&self) -> Result<(), Unavailable> {
        Err(Unavailable::NoAcl)
    }
    fn create(&self, _: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
        Err(BioError::Unavailable(Unavailable::NoAcl))
    }
    fn get(&self, _: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
        Err(BioError::Unavailable(Unavailable::NoAcl))
    }
    fn delete(&self, _: Uuid) -> Result<(), BioError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_is_no_acl_and_delete_is_a_no_op() {
        let s = NoStore;
        assert_eq!(s.platform(), "linux");
        assert_eq!(s.label(), None);
        assert_eq!(s.available(), Err(Unavailable::NoAcl));
        let id = Uuid::from_u128(1);
        assert_eq!(s.create(id).err(), Some(BioError::Unavailable(Unavailable::NoAcl)));
        assert_eq!(s.get(id).err(), Some(BioError::Unavailable(Unavailable::NoAcl)));
        assert_eq!(s.delete(id), Ok(()));
    }
}
