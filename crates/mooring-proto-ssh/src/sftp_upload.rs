//! SFTP upload through a part file (security review 4, L-16).
//!
//! The data goes to `<dir>/.<name>.mooring-part-<8 hex>` (created exclusively) and is renamed
//! onto `<dir>/<name>` only when complete: with `posix-rename@openssh.com` when the server
//! advertises it (atomic replace), otherwise `remove` + `rename` (a short window without the
//! file, never a truncated one). A failed upload removes the part file before returning; a
//! cancelled one (the future dropped) closes the handle and removes the part file from a
//! background task that owns a clone of the client. The existing remote file is never opened
//! for writing, so a cancel or failure leaves it intact.
//!
//! Mode (review 4, L-19): the part file is created with `0600` and set to `0600` again right
//! after the open (for servers that ignore open attributes), so the data is private while it
//! is in flight. Before the rename it gets the permission bits of the file it replaces (`stat`
//! before the upload; `0600` for a new file or when the target cannot be stat'ed), limited to
//! `0777` (no setuid/setgid/sticky). If the server refuses that `fsetstat`, the part file's
//! actual mode is checked and the upload fails rather than leave a file more permissive than
//! the one it replaces.

use mooring_core::MooringError;
use rand_core::{OsRng, RngCore};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};

use crate::local_path::LocalPath;
use crate::sftp::{check_remote, sftp_err, SftpClient};
use crate::sftp_transfer::blocking;

/// OpenSSH's atomic-replace rename extension.
pub(crate) const POSIX_RENAME: &str = "posix-rename@openssh.com";
/// Marker in part file names.
pub const PART_MARKER: &str = ".mooring-part-";
/// Mode of a new remote file, and of every part file while data is written (L-19).
pub const NEW_FILE_MODE: u32 = 0o600;
/// Permission bits carried over from a replaced file (no setuid/setgid/sticky).
const MODE_BITS: u32 = 0o777;

fn mode_attrs(mode: u32) -> FileAttributes {
    let mut a = FileAttributes::empty();
    a.permissions = Some(mode);
    a
}

/// Whether a file with `actual` permission bits grants nothing that `allowed` does not.
pub(crate) fn within(actual: u32, allowed: u32) -> bool {
    actual & MODE_BITS & !allowed == 0
}

/// `<dir>/.<name>.mooring-part-<suffix>` for `remote` = `<dir>/<name>`.
pub(crate) fn part_path(remote: &str, suffix: &str) -> String {
    let (dir, name) = match remote.rfind('/') {
        Some(i) => remote.split_at(i + 1),
        None => ("", remote),
    };
    format!("{dir}.{name}{PART_MARKER}{suffix}")
}

fn random_suffix() -> String {
    format!("{:08x}", OsRng.next_u32())
}

/// Removes the part file (closing its handle first) unless disarmed.
struct PartGuard {
    client: SftpClient,
    path: String,
    handle: Option<String>,
    armed: bool,
}

impl PartGuard {
    async fn cleanup_now(mut self) {
        self.armed = false;
        cleanup(self.client.clone(), self.handle.take(), self.path.clone()).await;
    }
}

async fn cleanup(client: SftpClient, handle: Option<String>, path: String) {
    if let Some(h) = handle {
        let _ = client.raw.close(h).await;
    }
    if let Err(e) = client.raw.remove(path).await {
        tracing::debug!(error = %e, "part file cleanup failed");
    }
}

impl Drop for PartGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (client, handle, path) = (self.client.clone(), self.handle.take(), self.path.clone());
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(cleanup(client, handle, path));
        }
    }
}

impl SftpClient {
    /// Upload `local` (inside the caller's base directory) to `remote`, creating it or
    /// replacing it once the data is complete. `progress` gets `(bytes_done, Some(total))`
    /// after every block.
    pub async fn upload(
        &self,
        local: &LocalPath,
        remote: &str,
        mut progress: impl FnMut(u64, Option<u64>),
    ) -> Result<u64, MooringError> {
        check_remote(remote)?;
        let part = part_path(remote, &random_suffix());
        check_remote(&part)?;
        let source = local.resolve_existing_file()?;
        let (src, total) = blocking(move || {
            let f = std::fs::File::open(source)?;
            let len = f.metadata()?.len();
            Ok((f, len))
        })
        .await?;
        let mode = self.target_mode(remote).await;
        let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
        let attrs = mode_attrs(NEW_FILE_MODE);
        let file = self.open_remote_with(&part, flags, attrs).await?;
        let mut guard = PartGuard {
            client: self.clone(),
            path: part.clone(),
            handle: Some(file.handle.clone()),
            armed: true,
        };
        // best effort: a server that ignored the open attributes still gets a private part file
        let _ = self.raw.fsetstat(file.handle.as_str(), mode_attrs(NEW_FILE_MODE)).await;
        let mut result = self.upload_from(&file.handle, remote, src, total, &mut progress).await;
        if result.is_ok() {
            if let Err(e) = self.set_final_mode(&file.handle, mode, remote).await {
                result = Err(e);
            }
        }
        let closed = file.close().await;
        guard.handle = None;
        let done = match (result, closed) {
            (Ok(n), Ok(())) => n,
            (Err(e), _) => {
                guard.cleanup_now().await;
                return Err(e);
            }
            (Ok(_), Err(e)) => {
                guard.cleanup_now().await;
                return Err(sftp_err(&e, remote));
            }
        };
        if let Err(e) = self.replace(&part, remote).await {
            guard.cleanup_now().await;
            return Err(e);
        }
        guard.armed = false;
        Ok(done)
    }

    /// Permission bits for the uploaded file: those of the file it replaces, else `0600`.
    async fn target_mode(&self, remote: &str) -> u32 {
        match self.raw.stat(remote).await {
            Ok(a) => a.attrs.permissions.map_or(NEW_FILE_MODE, |p| p & MODE_BITS),
            // NoSuchFile (a new file) or anything else: the private default
            Err(_) => NEW_FILE_MODE,
        }
    }

    /// Give the part file `mode`. If the server refuses, accept the part file only when its
    /// actual mode grants nothing beyond `mode`.
    async fn set_final_mode(
        &self,
        handle: &str,
        mode: u32,
        remote: &str,
    ) -> Result<(), MooringError> {
        let Err(e) = self.raw.fsetstat(handle, mode_attrs(mode)).await else {
            return Ok(());
        };
        let actual = self.raw.fstat(handle).await.ok().and_then(|a| a.attrs.permissions);
        match actual {
            Some(p) if within(p, mode) => Ok(()),
            _ => Err(sftp_err(&e, remote)),
        }
    }

    /// Move the finished part file onto `remote`.
    async fn replace(&self, part: &str, remote: &str) -> Result<(), MooringError> {
        if self.posix_rename {
            let data = posix_rename_payload(part, remote);
            let reply = self.raw.extended(POSIX_RENAME, data).await;
            return match reply {
                Ok(russh_sftp::protocol::Packet::Status(s)) if s.status_code == StatusCode::Ok => {
                    Ok(())
                }
                Ok(russh_sftp::protocol::Packet::Status(s)) => {
                    Err(sftp_err(&SftpError::Status(s), remote))
                }
                Ok(_) => Err(sftp_err(&SftpError::UnexpectedPacket, remote)),
                Err(e) => Err(sftp_err(&e, remote)),
            };
        }
        match self.raw.remove(remote).await {
            Ok(_) => {}
            Err(SftpError::Status(s)) if s.status_code == StatusCode::NoSuchFile => {}
            Err(e) => return Err(sftp_err(&e, remote)),
        }
        self.raw.rename(part, remote).await.map(drop).map_err(|e| sftp_err(&e, remote))
    }
}

/// `posix-rename@openssh.com` data: two SSH strings (old path, new path). Both paths passed
/// `check_remote` (≤ 4096 bytes), so the lengths fit a `u32`.
fn posix_rename_payload(from: &str, to: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + from.len() + to.len());
    for s in [from, to] {
        out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_paths_sit_next_to_the_target_and_are_hidden() {
        assert_eq!(part_path("/in/big.bin", "0a1b2c3d"), "/in/.big.bin.mooring-part-0a1b2c3d");
        assert_eq!(part_path("rel", "00000000"), ".rel.mooring-part-00000000");
        assert_eq!(part_path("/f", "x"), "/.f.mooring-part-x");
        let s = random_suffix();
        assert_eq!(s.len(), 8);
        assert!(s.bytes().all(|b| b.is_ascii_hexdigit()), "{s}");
    }

    #[test]
    fn within_compares_permission_bits_only() {
        assert!(within(0o100_600, 0o600));
        assert!(within(0o400, 0o600));
        assert!(!within(0o644, 0o600));
        assert!(!within(0o100_660, 0o640));
        assert!(within(0o4755, 0o755), "setuid is ignored, never carried");
        assert_eq!(mode_attrs(0o600).permissions, Some(0o600));
    }

    #[test]
    fn posix_rename_payload_is_two_ssh_strings() {
        let data = posix_rename_payload("/a", "/bc");
        assert_eq!(data, [0, 0, 0, 2, b'/', b'a', 0, 0, 0, 3, b'/', b'b', b'c']);
    }
}
