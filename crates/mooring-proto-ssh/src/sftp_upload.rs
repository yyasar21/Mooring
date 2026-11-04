//! SFTP upload through a part file (security review 4, L-16).
//!
//! The data goes to `<dir>/.<name>.mooring-part-<8 hex>` (created exclusively) and is renamed
//! onto `<dir>/<name>` only when complete: with `posix-rename@openssh.com` when the server
//! advertises it (atomic replace), otherwise `remove` + `rename` (a short window without the
//! file, never a truncated one). A failed upload removes the part file before returning; a
//! cancelled one (the future dropped) closes the handle and removes the part file from a
//! background task that owns a clone of the client. The existing remote file is never opened
//! for writing, so a cancel or failure leaves it intact.

use mooring_core::MooringError;
use rand_core::{OsRng, RngCore};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{OpenFlags, StatusCode};

use crate::local_path::LocalPath;
use crate::sftp::{check_remote, sftp_err, SftpClient};
use crate::sftp_transfer::blocking;

/// OpenSSH's atomic-replace rename extension.
pub(crate) const POSIX_RENAME: &str = "posix-rename@openssh.com";
/// Marker in part file names.
pub const PART_MARKER: &str = ".mooring-part-";

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
        let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
        let file = self.open_remote(&part, flags).await?;
        let mut guard = PartGuard {
            client: self.clone(),
            path: part.clone(),
            handle: Some(file.handle.clone()),
            armed: true,
        };
        let result = self.upload_from(&file.handle, remote, src, total, &mut progress).await;
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
    fn posix_rename_payload_is_two_ssh_strings() {
        let data = posix_rename_payload("/a", "/bc");
        assert_eq!(data, [0, 0, 0, 2, b'/', b'a', 0, 0, 0, 3, b'/', b'b', b'c']);
    }
}
