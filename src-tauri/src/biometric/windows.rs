//! Windows: Windows Hello through `KeyCredentialManager` (ADR-0022 §1), safe `WinRT`
//! projections of the `windows` crate only (no raw pointers, no `unsafe` here).
//!
//! Nothing readable is stored: the key `io.github.yyasar21.mooring/<vault_id>` lives in the
//! TPM / KSP and every signature needs the Hello gesture. The wrap key is
//! `HKDF-SHA256(RequestSignAsync(challenge).Result, salt = vault_id, info = "mooring hello v1")`
//! over the fixed challenge `"mooring-hello-v1" ‖ vault_id` (PKCS#1 v1.5 RSA signatures are
//! deterministic, so the same key comes back on every unlock). A Hello container reset makes
//! `OpenAsync` answer `NotFound` → `biometry_changed`.
//!
//! Every `WinRT` call is joined synchronously; the command layer runs it off the IPC thread.

use mooring_vault::Uuid;
use ::windows::core::HSTRING;
use ::windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use ::windows::Storage::Streams::{DataReader, DataWriter, IBuffer};
use zeroize::Zeroizing;

use super::{hello_challenge, wrap_key_from_signature, BioError, BiometricStore, Unavailable, KEY_LEN, SERVICE};

/// Longest signature accepted from the KSP (RSA-4096 = 512 bytes; anything larger is not a
/// Hello key).
const MAX_SIGNATURE: u32 = 1024;

/// The Windows Hello store.
#[derive(Debug, Default, Clone, Copy)]
pub struct HelloStore;

fn key_name(vault_id: Uuid) -> HSTRING {
    HSTRING::from(format!("{SERVICE}/{vault_id}"))
}

/// Map a `WinRT` failure to a fixed error; only the `HRESULT` is logged.
fn winrt(e: &::windows::core::Error, op: &'static str) -> BioError {
    tracing::warn!(op, hresult = e.code().0, "windows hello call failed");
    BioError::Failed
}

/// Map a `KeyCredentialStatus` to a fixed error (`Success` is `Ok`).
fn status(s: KeyCredentialStatus, op: &'static str) -> Result<(), BioError> {
    match s {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled => Err(BioError::Cancelled),
        KeyCredentialStatus::NotFound => Err(BioError::NotFound),
        KeyCredentialStatus::UserPrefersPassword | KeyCredentialStatus::SecurityDeviceLocked => {
            tracing::warn!(op, status = s.0, "windows hello refused");
            Err(BioError::Unavailable(Unavailable::KeychainUnavailable))
        }
        other => {
            tracing::warn!(op, status = other.0, "windows hello failed");
            Err(BioError::Failed)
        }
    }
}

fn buffer_of(bytes: &[u8]) -> Result<IBuffer, BioError> {
    let w = DataWriter::new().map_err(|e| winrt(&e, "buffer"))?;
    w.WriteBytes(bytes).map_err(|e| winrt(&e, "buffer"))?;
    w.DetachBuffer().map_err(|e| winrt(&e, "buffer"))
}

fn bytes_of(buffer: &IBuffer) -> Result<Zeroizing<Vec<u8>>, BioError> {
    let r = DataReader::FromBuffer(buffer).map_err(|e| winrt(&e, "signature"))?;
    let len = r.UnconsumedBufferLength().map_err(|e| winrt(&e, "signature"))?;
    if len == 0 || len > MAX_SIGNATURE {
        tracing::warn!(len, "windows hello signature has an unexpected size");
        return Err(BioError::Failed);
    }
    let mut out = Zeroizing::new(vec![0u8; len as usize]);
    r.ReadBytes(out.as_mut_slice()).map_err(|e| winrt(&e, "signature"))?;
    Ok(out)
}

/// Sign the fixed challenge of `vault_id` with `credential` (Hello prompts) and derive.
fn derive(credential: &KeyCredential, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
    let challenge = buffer_of(&hello_challenge(vault_id))?;
    let op = credential.RequestSignAsync(&challenge).map_err(|e| winrt(&e, "sign"))?;
    let result = op.join().map_err(|e| winrt(&e, "sign"))?;
    status(result.Status().map_err(|e| winrt(&e, "sign"))?, "sign")?;
    let signature = bytes_of(&result.Result().map_err(|e| winrt(&e, "sign"))?)?;
    Ok(wrap_key_from_signature(&signature, vault_id))
}

impl BiometricStore for HelloStore {
    fn platform(&self) -> &'static str {
        "windows"
    }

    fn label(&self) -> Option<&'static str> {
        Some("Windows Hello")
    }

    fn available(&self) -> Result<(), Unavailable> {
        let supported = KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .map_err(|e| {
                tracing::warn!(hresult = e.code().0, "windows hello support query failed");
                Unavailable::KeychainUnavailable
            })?;
        if supported {
            Ok(())
        } else {
            Err(Unavailable::KeychainUnavailable)
        }
    }

    fn create(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
        self.available().map_err(BioError::Unavailable)?;
        let op = KeyCredentialManager::RequestCreateAsync(
            &key_name(vault_id),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .map_err(|e| winrt(&e, "create"))?;
        let result = op.join().map_err(|e| winrt(&e, "create"))?;
        status(result.Status().map_err(|e| winrt(&e, "create"))?, "create")?;
        let credential = result.Credential().map_err(|e| winrt(&e, "create"))?;
        derive(&credential, vault_id)
    }

    fn get(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
        let op = KeyCredentialManager::OpenAsync(&key_name(vault_id)).map_err(|e| winrt(&e, "open"))?;
        let result = op.join().map_err(|e| winrt(&e, "open"))?;
        status(result.Status().map_err(|e| winrt(&e, "open"))?, "open")?;
        let credential = result.Credential().map_err(|e| winrt(&e, "open"))?;
        derive(&credential, vault_id)
    }

    fn delete(&self, vault_id: Uuid) -> Result<(), BioError> {
        match KeyCredentialManager::DeleteAsync(&key_name(vault_id)).and_then(|op| op.join()) {
            Ok(()) => Ok(()),
            Err(e) => {
                // A key that is already gone is the wanted end state.
                tracing::debug!(hresult = e.code().0, "windows hello delete answered an error");
                Ok(())
            }
        }
    }
}
