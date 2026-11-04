//! Minimal SFTP server for the tests: `russh_sftp::server` over a tempdir root.
//! Paths are confined to the root (no `..`); handles live in a map. Like a server that ignores
//! open attributes, `open` creates files with the process umask; `fsetstat` / `setstat` apply
//! permission bits (Unix) unless `SftpStats::refuse_setstat` is set.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh_sftp::extensions::{LimitsExtension, LIMITS};
use russh_sftp::protocol::{
    Attrs, Data, ExtendedReply, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status,
    StatusCode, Version,
};

/// Entries returned per READDIR reply.
const BATCH: usize = 200;

enum Open {
    File(std::fs::File),
    Dir(Vec<File>),
}

/// What the SFTP server saw (read/write request counts and largest lengths), plus switches.
#[derive(Debug, Default)]
pub struct SftpStats {
    pub reads: usize,
    pub writes: usize,
    pub max_read_len: u32,
    pub max_write_len: usize,
    /// Answer `fsetstat` / `setstat` with `OpUnsupported` (L-19 fallback).
    pub refuse_setstat: bool,
}

pub struct SftpFs {
    root: PathBuf,
    handles: HashMap<String, Open>,
    next: u64,
    /// `limits@openssh.com` max read/write length to advertise, if any.
    limits: Option<u64>,
    stats: Arc<Mutex<SftpStats>>,
}

impl SftpFs {
    pub fn new(root: PathBuf, limits: Option<u64>, stats: Arc<Mutex<SftpStats>>) -> Self {
        Self { root, handles: HashMap::new(), next: 0, limits, stats }
    }

    fn map(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let mut out = self.root.clone();
        for c in Path::new(path).components() {
            match c {
                Component::Normal(p) => out.push(p),
                Component::RootDir | Component::CurDir => {}
                _ => return Err(StatusCode::PermissionDenied),
            }
        }
        Ok(out)
    }

    fn handle(&mut self, open: Open) -> String {
        self.next += 1;
        let h = format!("h{}", self.next);
        self.handles.insert(h.clone(), open);
        h
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn io(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

/// Apply the permission bits of `attrs`, if any, to the file `f`.
fn set_mode(f: &std::fs::File, attrs: &FileAttributes) -> Result<(), StatusCode> {
    #[cfg(unix)]
    if let Some(mode) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode & 0o7777);
        f.set_permissions(perms).map_err(|e| io(&e))?;
    }
    #[cfg(not(unix))]
    let _ = (f, attrs);
    Ok(())
}

fn attrs(meta: &std::fs::Metadata) -> FileAttributes {
    let mut a = FileAttributes::from(meta);
    if meta.file_type().is_symlink() {
        a.permissions = Some(0o120_777);
    }
    a
}

impl russh_sftp::server::Handler for SftpFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut v = Version::new();
        if self.limits.is_some() {
            v.extensions.insert(LIMITS.to_owned(), "1".to_owned());
        }
        Ok(v)
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        _data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        match (request.as_str(), self.limits) {
            (LIMITS, Some(len)) => {
                let limits = LimitsExtension {
                    max_packet_len: 256 * 1024,
                    max_read_len: len,
                    max_write_len: len,
                    max_open_handles: 0,
                };
                let data = russh_sftp::ser::to_bytes(&limits).map_err(|_| StatusCode::Failure)?;
                Ok(Packet::ExtendedReply(ExtendedReply { id, data: data.to_vec() }))
            }
            _ => Err(StatusCode::OpUnsupported),
        }
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.map(&filename)?;
        let file = std::fs::OpenOptions::new()
            .read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE))
            .create(pflags.contains(OpenFlags::CREATE))
            .truncate(pflags.contains(OpenFlags::TRUNCATE))
            .open(path)
            .map_err(|e| io(&e))?;
        Ok(Handle { id, handle: self.handle(Open::File(file)) })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle).map(|_| ok(id)).ok_or(StatusCode::Failure)
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        if let Ok(mut s) = self.stats.lock() {
            s.reads += 1;
            s.max_read_len = s.max_read_len.max(len);
        }
        let Some(Open::File(f)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        f.seek(SeekFrom::Start(offset)).map_err(|e| io(&e))?;
        let mut data = Vec::new();
        f.take(u64::from(len)).read_to_end(&mut data).map_err(|e| io(&e))?;
        if data.is_empty() {
            return Err(StatusCode::Eof);
        }
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if let Ok(mut s) = self.stats.lock() {
            s.writes += 1;
            s.max_write_len = s.max_write_len.max(data.len());
        }
        let Some(Open::File(f)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        f.seek(SeekFrom::Start(offset)).map_err(|e| io(&e))?;
        f.write_all(&data).map_err(|e| io(&e))?;
        Ok(ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if self.stats.lock().is_ok_and(|s| s.refuse_setstat) {
            return Err(StatusCode::OpUnsupported);
        }
        let f = std::fs::File::open(self.map(&path)?).map_err(|e| io(&e))?;
        set_mode(&f, &attrs).map(|()| ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if self.stats.lock().is_ok_and(|s| s.refuse_setstat) {
            return Err(StatusCode::OpUnsupported);
        }
        let Some(Open::File(f)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        set_mode(f, &attrs).map(|()| ok(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let meta = f.metadata().map_err(|e| io(&e))?;
        Ok(Attrs { id, attrs: attrs(&meta) })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(self.map(&path)?).map_err(|e| io(&e))?;
        Ok(Attrs { id, attrs: attrs(&meta) })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::symlink_metadata(self.map(&path)?).map_err(|e| io(&e))?;
        Ok(Attrs { id, attrs: attrs(&meta) })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let dir = self.map(&path)?;
        let mut files = vec![File::new(".", FileAttributes::empty())];
        for entry in std::fs::read_dir(dir).map_err(|e| io(&e))? {
            let entry = entry.map_err(|e| io(&e))?;
            let meta = entry.metadata().map_err(|e| io(&e))?;
            files.push(File::new(entry.file_name().to_string_lossy(), attrs(&meta)));
        }
        files.reverse();
        Ok(Handle { id, handle: self.handle(Open::Dir(files)) })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir(files)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        if files.is_empty() {
            return Err(StatusCode::Eof);
        }
        let take = files.len().min(BATCH);
        let batch = files.split_off(files.len() - take);
        Ok(Name { id, files: batch })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        std::fs::create_dir(self.map(&path)?).map(|()| ok(id)).map_err(|e| io(&e))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.map(&path)?).map(|()| ok(id)).map_err(|e| io(&e))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(self.map(&filename)?).map(|()| ok(id)).map_err(|e| io(&e))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let (from, to) = (self.map(&oldpath)?, self.map(&newpath)?);
        std::fs::rename(from, to).map(|()| ok(id)).map_err(|e| io(&e))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name { id, files: vec![File::dummy(path)] })
    }
}
