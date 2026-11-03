//! Minimal SFTP server for the tests: `russh_sftp::server` over a tempdir root.
//! Paths are confined to the root (no `..`); handles live in a map.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

/// Entries returned per READDIR reply.
const BATCH: usize = 200;

enum Open {
    File(std::fs::File),
    Dir(Vec<File>),
}

pub struct SftpFs {
    root: PathBuf,
    handles: HashMap<String, Open>,
    next: u64,
}

impl SftpFs {
    pub fn new(root: PathBuf) -> Self {
        Self { root, handles: HashMap::new(), next: 0 }
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
        Ok(Version::new())
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
        let Some(Open::File(f)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        f.seek(SeekFrom::Start(offset)).map_err(|e| io(&e))?;
        f.write_all(&data).map_err(|e| io(&e))?;
        Ok(ok(id))
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
