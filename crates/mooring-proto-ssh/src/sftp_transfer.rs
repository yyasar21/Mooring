//! SFTP file transfers, streamed in [`TRANSFER_BLOCK`] blocks: each block is sent as several
//! pipelined wire requests, written out, reported through the progress callback and dropped,
//! so memory use is bounded by one block whatever the file size.
//!
//! Downloads go to a temporary file in the target directory and are renamed into place only
//! when complete; a failed download leaves no partial file behind. Uploads do the same on the
//! server side (`sftp_upload`).

use std::io::{Read, Write};
use std::path::PathBuf;

use mooring_core::MooringError;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::task::JoinSet;

use crate::local_path::LocalPath;
use crate::sftp::{check_remote, sftp_err, SftpClient, MAX_IN_FLIGHT, TRANSFER_BLOCK};

/// Bytes moved per block for a wire chunk of `chunk` bytes: at most [`MAX_IN_FLIGHT`]
/// requests, never more than [`TRANSFER_BLOCK`].
pub(crate) fn block_len(chunk: u32) -> usize {
    TRANSFER_BLOCK.min(MAX_IN_FLIGHT.saturating_mul((chunk as usize).max(1)))
}

/// Largest file size accepted from a server's `stat` for progress (sanity bound only).
const MAX_REPORTED_SIZE: u64 = 1 << 50;

fn local_io(_: std::io::Error) -> MooringError {
    MooringError::Transport("local file error".into())
}

fn joined<T>(r: Result<T, tokio::task::JoinError>) -> Result<T, MooringError> {
    r.map_err(|_| MooringError::Transport("transfer task failed".into()))
}

/// Run a blocking local file operation off the async runtime.
pub(crate) async fn blocking<T, F>(f: F) -> Result<T, MooringError>
where
    T: Send + 'static,
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
{
    joined(tokio::task::spawn_blocking(f).await)?.map_err(local_io)
}

/// One remote file handle, closed on every path out of a transfer.
pub(crate) struct RemoteFile<'a> {
    client: &'a SftpClient,
    pub(crate) handle: String,
}

impl RemoteFile<'_> {
    pub(crate) async fn close(self) -> Result<(), SftpError> {
        self.client.raw.close(self.handle).await.map(|_| ())
    }
}

/// Removes the temporary download file when a transfer is dropped mid-way (cancel). The
/// `NamedTempFile` may be owned by an in-flight blocking write at that moment and would only
/// be deleted once that write returns; this guard deletes the path at once, so "cancelled"
/// means "no partial file" without a race (review 4, N-15).
struct RemoveOnDrop(Option<PathBuf>);

impl RemoveOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            // Best effort: already gone when the NamedTempFile was dropped first.
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Where a download lands.
struct Target {
    parent: PathBuf,
    path: PathBuf,
    overwrite: bool,
}

/// Outcome of reading one block: the bytes in order, and whether EOF was reached.
struct Block {
    data: Vec<u8>,
    eof: bool,
}

impl SftpClient {
    pub(crate) async fn open_remote(
        &self,
        path: &str,
        flags: OpenFlags,
    ) -> Result<RemoteFile<'_>, MooringError> {
        let handle = self
            .raw
            .open(path, flags, FileAttributes::empty())
            .await
            .map_err(|e| sftp_err(&e, path))?
            .handle;
        Ok(RemoteFile { client: self, handle })
    }

    /// Read up to one block starting at `offset` with pipelined requests. A short read
    /// ends the block early; the caller continues from the returned length.
    async fn read_block(&self, handle: &str, offset: u64) -> Result<Block, SftpError> {
        let chunk = self.read_chunk as usize;
        let block = block_len(self.read_chunk);
        let mut set = JoinSet::new();
        for i in 0..block.div_ceil(chunk) {
            let raw = std::sync::Arc::clone(&self.raw);
            let (handle, at) = (handle.to_owned(), offset + (i * chunk) as u64);
            let len = self.read_chunk;
            set.spawn(async move { (i, raw.read(handle, at, len).await) });
        }
        let mut parts: Vec<Option<Result<Vec<u8>, SftpError>>> = Vec::new();
        parts.resize_with(set.len(), || None);
        while let Some(done) = set.join_next().await {
            let Ok((i, result)) = done else {
                return Err(SftpError::UnexpectedBehavior("read task failed".into()));
            };
            if let Some(slot) = parts.get_mut(i) {
                *slot = Some(result.map(|d| d.data));
            }
        }
        let mut data = Vec::with_capacity(block);
        for part in parts {
            match part {
                Some(Ok(bytes)) => {
                    if bytes.len() > chunk {
                        return Err(SftpError::UnexpectedBehavior("oversized read".into()));
                    }
                    let short = bytes.len() < chunk;
                    data.extend_from_slice(&bytes);
                    if short {
                        // Later requests may hold data past a gap; re-read from here.
                        return Ok(Block { eof: bytes.is_empty(), data });
                    }
                }
                Some(Err(SftpError::Status(s))) if s.status_code == StatusCode::Eof => {
                    return Ok(Block { eof: true, data });
                }
                Some(Err(e)) => return Err(e),
                None => return Err(SftpError::UnexpectedBehavior("missing read".into())),
            }
        }
        Ok(Block { data, eof: false })
    }

    /// Download `remote` to `local` (inside the caller's base directory), replacing an
    /// existing file. `progress` gets `(bytes_done, bytes_total)` after every block; the total
    /// comes from the server and is only a hint. Returns the number of bytes written.
    pub async fn download(
        &self,
        remote: &str,
        local: &LocalPath,
        progress: impl FnMut(u64, Option<u64>),
    ) -> Result<u64, MooringError> {
        self.download_to(remote, local, true, progress).await
    }

    /// [`download`](Self::download); with `overwrite == false` an existing target (also one
    /// created while the transfer ran) is never replaced: the result is the
    /// [`TARGET_EXISTS`](crate::TARGET_EXISTS) refusal and the temporary file is removed.
    pub async fn download_to(
        &self,
        remote: &str,
        local: &LocalPath,
        overwrite: bool,
        mut progress: impl FnMut(u64, Option<u64>),
    ) -> Result<u64, MooringError> {
        check_remote(remote)?;
        local.check_target(overwrite)?;
        let (parent, target) = local.resolve_new_file()?;
        let file = self.open_remote(remote, OpenFlags::READ).await?;
        let total = self
            .raw
            .fstat(file.handle.as_str())
            .await
            .ok()
            .and_then(|a| a.attrs.size)
            .filter(|s| *s <= MAX_REPORTED_SIZE);
        let to = Target { parent, path: target, overwrite };
        let result = self.download_into(&file.handle, remote, to, total, &mut progress).await;
        let closed = file.close().await;
        let done = result?;
        closed.map_err(|e| sftp_err(&e, remote))?;
        Ok(done)
    }

    async fn download_into(
        &self,
        handle: &str,
        remote: &str,
        to: Target,
        total: Option<u64>,
        progress: &mut impl FnMut(u64, Option<u64>),
    ) -> Result<u64, MooringError> {
        let Target { parent, path: target, overwrite } = to;
        let mut tmp = Some(blocking(move || tempfile::NamedTempFile::new_in(parent)).await?);
        let mut guard = RemoveOnDrop(tmp.as_ref().map(|t| t.path().to_path_buf()));
        let mut done = 0u64;
        progress(0, total);
        loop {
            let block = self.read_block(handle, done).await.map_err(|e| sftp_err(&e, remote))?;
            if !block.data.is_empty() {
                let mut file =
                    tmp.take().ok_or_else(|| local_io(std::io::ErrorKind::Other.into()))?;
                let data = block.data;
                let len = data.len() as u64;
                file = blocking(move || file.write_all(&data).map(|()| file)).await?;
                tmp = Some(file);
                done += len;
                progress(done, total);
            }
            if block.eof {
                break;
            }
        }
        let file = tmp.ok_or_else(|| local_io(std::io::ErrorKind::Other.into()))?;
        let persisted = joined(
            tokio::task::spawn_blocking(move || {
                file.as_file().sync_all()?;
                if overwrite {
                    file.persist(&target).map(drop).map_err(|e| e.error)
                } else {
                    file.persist_noclobber(&target).map(drop).map_err(|e| e.error)
                }
            })
            .await,
        )?;
        match persisted {
            Ok(()) => {
                guard.disarm();
                Ok(done)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(MooringError::Invalid {
                field: "local path",
                reason: crate::TARGET_EXISTS.to_owned(),
            }),
            Err(e) => Err(local_io(e)),
        }
    }

    pub(crate) async fn upload_from(
        &self,
        handle: &str,
        remote: &str,
        src: std::fs::File,
        total: u64,
        progress: &mut impl FnMut(u64, Option<u64>),
    ) -> Result<u64, MooringError> {
        let mut src = Some(src);
        let mut done = 0u64;
        progress(0, Some(total));
        let len = block_len(self.write_chunk);
        loop {
            let file = src.take().ok_or_else(|| local_io(std::io::ErrorKind::Other.into()))?;
            let (file, block) = blocking(move || {
                let mut file = file;
                let mut block = Vec::with_capacity(len);
                (&mut file).take(len as u64).read_to_end(&mut block)?;
                Ok((file, block))
            })
            .await?;
            src = Some(file);
            if block.is_empty() {
                break;
            }
            self.write_block(handle, done, &block).await.map_err(|e| sftp_err(&e, remote))?;
            done += block.len() as u64;
            progress(done, Some(total));
        }
        Ok(done)
    }

    async fn write_block(&self, handle: &str, offset: u64, block: &[u8]) -> Result<(), SftpError> {
        let mut set = JoinSet::new();
        for (i, chunk) in block.chunks(self.write_chunk as usize).enumerate() {
            let raw = std::sync::Arc::clone(&self.raw);
            let at = offset + (i * self.write_chunk as usize) as u64;
            let (handle, data) = (handle.to_owned(), chunk.to_vec());
            set.spawn(async move { raw.write(handle, at, data).await });
        }
        while let Some(done) = set.join_next().await {
            match done {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(SftpError::UnexpectedBehavior("write task failed".into())),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_is_bounded_by_in_flight_requests() {
        assert_eq!(block_len(1), MAX_IN_FLIGHT);
        assert_eq!(block_len(0), MAX_IN_FLIGHT, "a zero chunk never divides by zero");
        assert_eq!(block_len(1024), MAX_IN_FLIGHT * 1024);
        assert_eq!(block_len(32 * 1024), TRANSFER_BLOCK);
        assert_eq!(block_len(u32::MAX), TRANSFER_BLOCK);
        for chunk in [1u32, 7, 1000, 32 * 1024] {
            assert!(block_len(chunk).div_ceil(chunk as usize) <= MAX_IN_FLIGHT);
        }
    }
}
