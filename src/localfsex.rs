//! Local filesystem access.
//!
//! This implementation is stateless. So the easiest way to use it
//! is to create a new instance in your handler every time
//! you need one.

use std::any::Any;
//use std::collections::VecDeque;
//use std::future::Future;
//use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
//use std::io::{Read, Seek, SeekFrom, Write};
use std::io::SeekFrom;

#[cfg(not(target_os = "windows"))]
use { 
    std::os::unix::ffi::OsStrExt, 
    std::os::unix::fs::DirBuilderExt,
    std::os::unix::fs::MetadataExt,
    std::os::unix::fs::OpenOptionsExt,
    std::os::unix::fs::PermissionsExt};
#[cfg(target_os = "windows")]
use std::os::windows::prelude::*;
use std::path::{Path, PathBuf};
//use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
//use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes, BytesMut};
use futures::{future, FutureExt};
//use pin_utils::pin_mut;
use tokio::task;

use libc;

use crate::davpath::DavPath;
use crate::fs::*;
//use crate::localfs_macos::DUCacheBuilder;

const RUNTIME_TYPE_BASIC: u32 = 1;
const RUNTIME_TYPE_THREADPOOL: u32 = 2;
static RUNTIME_TYPE: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
#[repr(u32)]
enum RuntimeType {
    Basic      = RUNTIME_TYPE_BASIC,
    ThreadPool = RUNTIME_TYPE_THREADPOOL,
}

impl RuntimeType {
    #[inline]
    fn get() -> RuntimeType {
        match RUNTIME_TYPE.load(Ordering::Relaxed) {
            RUNTIME_TYPE_BASIC => RuntimeType::Basic,
            RUNTIME_TYPE_THREADPOOL => RuntimeType::ThreadPool,
            _ => {
                let dbg = format!("{:?}", tokio::runtime::Handle::current());
                let rt = if dbg.contains("ThreadPool") {
                    RuntimeType::ThreadPool
                } else {
                    RuntimeType::Basic
                };
                RUNTIME_TYPE.store(rt as u32, Ordering::SeqCst);
                rt
            },
        }
    }
}

// Run some code via block_in_place() or spawn_blocking().
//
// There's also a method on LocalFs for this, use the freestanding
// function if you do not want the fs_access_guard() closure to be used.
#[inline]
async fn blocking<F, R>(func: F) -> R
where
    F: FnOnce() -> R,
    F: Send + 'static,
    R: Send + 'static,
{
    match RuntimeType::get() {
        RuntimeType::Basic => task::spawn_blocking(func).await.unwrap(),
        RuntimeType::ThreadPool => task::block_in_place(func),
    }
}

#[derive(Clone)]
struct LocalFsMetaDataEx(WIN32_FILE_ATTRIBUTE_DATA);

impl std::fmt::Debug for LocalFsMetaDataEx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("")
         .field("dwFileAttributes", &self.0.dwFileAttributes)
         .field("ftCreationTime", &self.0.ftCreationTime)
         .finish()
    }
}

/// Local Filesystem implementation.
#[derive(Clone)]
pub struct LocalFsEx {
    pub(crate) inner: Arc<LocalFsInner>,
}

// inner struct.
pub(crate) struct LocalFsInner {
    pub basedir:          PathBuf,
    pub public:           bool,
    pub case_insensitive: bool,
    pub macos:            bool,
    pub is_file:          bool,
    pub fs_access_guard:  Option<Box<dyn Fn() -> Box<dyn Any> + Send + Sync + 'static>>,
}

#[derive(Debug)]
struct LocalFsFile {
    handle: isize,
}

#[derive(Debug)]
struct LocalFsFileEx {
    handle: isize,
}

struct LocalFsReadDir {
    inner: WIN32_FIND_DATAW,
    handle: isize,
}

struct LocalFsReadDirEx {
    inner: WIN32_FIND_DATAW,
    handle: isize,
}

struct LocalFsDirEntryEx(WIN32_FIND_DATAW);

enum PathType {
    Remote(PathBuf),
    Local(PathBuf),
}

impl LocalFsEx {
    /// Create a new LocalFsEx DavFileSystem, serving "base".
    ///
    /// If "public" is set to true, all files and directories created will be
    /// publically readable (mode 644/755), otherwise they will be private
    /// (mode 600/700). Umask stil overrides this.
    ///
    /// If "case_insensitive" is set to true, all filesystem lookups will
    /// be case insensitive. Note that this has a _lot_ of overhead!
    pub fn new<P: AsRef<Path>>(base: P, public: bool, case_insensitive: bool, macos: bool) -> Box<LocalFsEx> {
        let inner = LocalFsInner {
            basedir:          base.as_ref().to_path_buf(),
            public:           public,
            macos:            macos,
            case_insensitive: case_insensitive,
            is_file:          false,
            fs_access_guard:  None,
        };
        Box::new({
            LocalFsEx {
                inner: Arc::new(inner),
            }
        })
    }

    /// Create a new LocalFsEx DavFileSystem, serving "file".
    ///
    /// This is like `new()`, but it always serves this single file.
    /// The request path is ignored.
    pub fn new_file<P: AsRef<Path>>(file: P, public: bool) -> Box<LocalFsEx> {
        let inner = LocalFsInner {
            basedir:          file.as_ref().to_path_buf(),
            public:           public,
            macos:            false,
            case_insensitive: false,
            is_file:          true,
            fs_access_guard:  None,
        };
        Box::new({
            LocalFsEx {
                inner: Arc::new(inner),
            }
        })
    }

    // Like new() but pass in a fs_access_guard hook.
    #[doc(hidden)]
    pub fn new_with_fs_access_guard<P: AsRef<Path>>(
        base: P,
        public: bool,
        case_insensitive: bool,
        macos: bool,
        fs_access_guard: Option<Box<dyn Fn() -> Box<dyn Any> + Send + Sync + 'static>>,
    ) -> Box<LocalFsEx>
    {
        let inner = LocalFsInner {
            basedir:          base.as_ref().to_path_buf(),
            public:           public,
            macos:            macos,
            case_insensitive: case_insensitive,
            is_file:          false,
            fs_access_guard:  fs_access_guard,
        };
        Box::new({
            LocalFsEx {
                inner: Arc::new(inner),
            }
        })
    }

    fn fspath_dbg(&self, path: &DavPath) -> PathBuf {
        let mut pathbuf = self.inner.basedir.clone();
        if !self.inner.is_file {
            pathbuf.push(path.as_rel_ospath());
        }
        pathbuf
    }

    fn fspath(&self, path: &DavPath) -> PathBuf {
        if self.inner.case_insensitive {
            crate::localfs_windows::resolve(&self.inner.basedir, &path)
        } else {
            let mut pathbuf = self.inner.basedir.clone();
            if !self.inner.is_file {
                pathbuf.push(path.as_rel_ospath());
            }
            pathbuf
        }
    }

    fn fspath_ex(&self, path: &DavPath) -> PathType {
        {
            let pathbuf = path.as_rel_ospath();
            {
                let path = pathbuf.to_str().unwrap();
                let spath = if let Some(i) = path.find(|c: char| c == '/' || c == '\\') {
                    &path[..i]
                } else {
                    path
                };
                if spath.find('#').is_some() {
                    return PathType::Remote(PathBuf::from(String::from("\\\\") + path));
                }
            }
        }
        let mut pathbuf = self.inner.basedir.clone();
        if !self.inner.is_file {
            pathbuf.push(path.as_rel_ospath());
        }
        PathType::Local(pathbuf)
    }

    // threadpool::blocking() adapter, also runs the before/after hooks.
    #[doc(hidden)]
    pub async fn blocking<F, R>(&self, func: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let this = self.clone();
        blocking(move || {
            let _guard = this.inner.fs_access_guard.as_ref().map(|f| f());
            func()
        })
        .await
    }
}

// This implementation is basically a bunch of boilerplate to
// wrap the std::fs call in self.blocking() calls.

use winapi::um::fileapi::*;
use winapi::um::minwinbase::*;
use winapi::shared::minwindef::*;
use winapi::um::winnt::*;
use winapi::um::handleapi::*;
use winapi::shared::winerror::*;
use winapi::um::errhandlingapi::*;
use winapi::um::winbase::*;
//use winapi::shared::ntdef::*;

fn get_metadata(path : &Path, flag: u32) -> Result<WIN32_FILE_ATTRIBUTE_DATA, u32> {
    let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
    path.push(0);

    let mut fi : WIN32_FILE_ATTRIBUTE_DATA = Default::default();
    unsafe {
        let r = GetFileAttributesExW(path.as_ptr(), GetFileExInfoStandard, &mut fi as *mut WIN32_FILE_ATTRIBUTE_DATA as LPVOID);
        if r != 0 && (fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
            Ok(fi)
        } else if winapi::um::errhandlingapi::GetLastError() == ERROR_SHARING_VIOLATION {
            let mut fd : WIN32_FIND_DATAW = Default::default();
            let r = FindFirstFileW(path.as_ptr(), &mut fd );
            if r != INVALID_HANDLE_VALUE {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                && fd.dwReserved0 != IO_REPARSE_TAG_SYMLINK 
                && fd.dwReserved0 != IO_REPARSE_TAG_MOUNT_POINT {
                    fd.dwFileAttributes &= !FILE_ATTRIBUTE_REPARSE_POINT;
                }
                fi.dwFileAttributes = fd.dwFileAttributes;
                fi.ftCreationTime = fd.ftCreationTime;
                fi.ftLastAccessTime = fd.ftLastAccessTime;
                fi.ftLastWriteTime = fd.ftLastWriteTime;
                fi.nFileSizeHigh = fd.nFileSizeHigh;
                fi.nFileSizeLow = fd.nFileSizeLow;
                FindClose(r);
                Ok(fi)
            }
            else {
                Err(GetLastError())
            }
        } else {
            let mut bi : BY_HANDLE_FILE_INFORMATION = Default::default();
            let mut ti : FILE_ATTRIBUTE_TAG_INFO = Default::default();
      
            let h = CreateFileW(path.as_ptr(), 0, 0, 0 as LPSECURITY_ATTRIBUTES, OPEN_EXISTING, flag, 0 as LPVOID);
            if h != INVALID_HANDLE_VALUE {
                let result = GetFileInformationByHandle(h, &mut bi);
                if result != 0 {
                    let mut result = GetFileInformationByHandleEx(h, FileAttributeTagInfo, &mut ti as *mut FILE_ATTRIBUTE_TAG_INFO as LPVOID, std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32);
                    let error = GetLastError();
                    if result != 0 && error == ERROR_INVALID_PARAMETER {
                        ti.ReparseTag = 0;
                        result = 1;
                    }
                    CloseHandle(h);
                    if result != 0 {
                        if (bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                        && ti.ReparseTag != IO_REPARSE_TAG_SYMLINK 
                        && ti.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT {
                            bi.dwFileAttributes &= !FILE_ATTRIBUTE_REPARSE_POINT;
                        }
                        fi.dwFileAttributes = bi.dwFileAttributes;
                        fi.ftCreationTime = bi.ftCreationTime;
                        fi.ftLastAccessTime = bi.ftLastAccessTime;
                        fi.ftLastWriteTime = bi.ftLastWriteTime;
                        fi.nFileSizeHigh = bi.nFileSizeHigh;
                        fi.nFileSizeLow = bi.nFileSizeLow;
                        Ok(fi)
                    } else {
                        Err(error)
                    }
                } else {
                    CloseHandle(h);
                    Err(GetLastError())
                }
            } else {
                Err(GetLastError())
            }
        }
    }
}

impl DavFileSystem for LocalFsEx {

    fn metadata<'a>(&'a self, davpath: &'a DavPath) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            unsafe {
                match self.fspath_ex(davpath) {
                    PathType::Remote(path) => {
                        let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
                        path.push(0);
          
                        let mut fi : WIN32_FILE_ATTRIBUTE_DATA = Default::default();
                    
                        let func : extern "stdcall" fn(LPCWSTR, LPWIN32_FILE_ATTRIBUTE_DATA, DWORD)->BOOL = std::mem::transmute(crate::get_proc("GetFileAttributesEx_\0"));
                        let r = func(path.as_ptr(), &mut fi, FILE_FLAG_BACKUP_SEMANTICS);
                        if r  != 0 {
                            Ok(Box::new(LocalFsMetaDataEx(fi)) as Box<dyn DavMetaData>)
                        } else {
                            Err(FsError::NotFound)
                        }
                    },
                    PathType::Local(path) => {
                        if let Ok(meta) = get_metadata(&path, FILE_FLAG_BACKUP_SEMANTICS) {
                            Ok(Box::new(LocalFsMetaDataEx(meta)) as Box<dyn DavMetaData>)
                        }
                        else {
                            Err(FsError::NotFound)
                        }
                    }
                }
            }
        }
        .boxed()
    }

    fn symlink_metadata<'a>(&'a self, davpath: &'a DavPath) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            unsafe {
                match self.fspath_ex(davpath) {
                    PathType::Remote(path) => {
                        let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
                        path.push(0);
          
                        let mut fi : WIN32_FILE_ATTRIBUTE_DATA = Default::default();
                    
                        let func : extern "stdcall" fn(LPCWSTR, LPWIN32_FILE_ATTRIBUTE_DATA, DWORD)->BOOL = std::mem::transmute(crate::get_proc("GetFileAttributesEx_\0"));
                        let r = func(path.as_ptr(), &mut fi, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
                        if r  != 0 {
                            Ok(Box::new(LocalFsMetaDataEx(fi)) as Box<dyn DavMetaData>)
                        } else {
                            Err(FsError::NotFound)
                        }
                    },
                    PathType::Local(path) => {
                        if let Ok(meta) = get_metadata(&path, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT) {
                            Ok(Box::new(LocalFsMetaDataEx(meta)) as Box<dyn DavMetaData>)
                        }
                        else {
                            Err(FsError::NotFound)
                        }
                    }
                }
            }
        }
        .boxed()
    }

    // read_dir is a bit more involved - but not much - than a simple wrapper,
    // because it returns a stream.
    fn read_dir<'a>(
        &'a self,
        davpath: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<FsStream<Box<dyn DavDirEntry>>>
    {
        async move {
            unsafe {
                match self.fspath_ex(davpath) {
                    PathType::Remote(path) => {
                        let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
                        path.push(0);
          
                        let mut fd : WIN32_FIND_DATAW = Default::default();
                    
                        let func : extern "stdcall" fn(LPCWSTR, LPWIN32_FIND_DATAW)->BOOL = std::mem::transmute(crate::get_proc("FindFirstFile_\0"));
                        let r = func(path.as_ptr(), &mut fd);
                        if r  != 0 {
                            let it = LocalFsReadDirEx {
                                inner: fd,
                                handle: r as isize,
                            };
                            let strm = futures::stream::iter(it);
                            Ok(Box::pin(strm) as FsStream<Box<dyn DavDirEntry>>)
                        } else {
                            Err(FsError::NotFound)
                        }
                    },
                    PathType::Local(path) => {
                        let mut pattern = path.clone();
                        pattern.push("*");
                        let mut pattern = pattern.as_os_str().encode_wide().collect::<Vec<u16>>();
                        pattern.push(0);
                    
                        let mut fd : WIN32_FIND_DATAW = Default::default();
                        let h =  FindFirstFileW(pattern.as_ptr(), &mut fd);
                        if h == INVALID_HANDLE_VALUE {
                            let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
                            path.push(0);
                            let error = GetLastError();
                            let mut fa : WIN32_FILE_ATTRIBUTE_DATA = Default::default();
                            if error != ERROR_FILE_NOT_FOUND {
                                return Err(FsError::Forbidden);
                            }
                            else if GetFileAttributesExW(path.as_ptr(), GetFileExInfoStandard, &mut fa as *mut WIN32_FILE_ATTRIBUTE_DATA as LPVOID) != 0 {
                                return Err(FsError::Forbidden);
                            }
                            else if (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                                return Err(FsError::Forbidden);
                            }
                        }
                        let it = LocalFsReadDir {
                            inner: fd,
                            handle: h as isize,
                        };
                        let strm = futures::stream::iter(it);
                        Ok(Box::pin(strm) as FsStream<Box<dyn DavDirEntry>>)
                    }
                }
            }
        }
        .boxed()
    }

    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<Box<dyn DavFile>> {
        async move {
            unsafe {
                let mut access : DWORD = 0;
                // O_RDONLY, O_WRONLY, O_RDWR
                if options.read { // O_RDONLY
                    access |= GENERIC_READ;
                }
                if options.write {  
                    access |= GENERIC_WRITE;
                }

                if options.create || options.create_new {
                    access |= GENERIC_WRITE;
                }
                if options.append { // O_APPEND
                    access &= !GENERIC_WRITE;
                    access |= FILE_APPEND_DATA;
                }
                let createmode : DWORD;
                if options.create_new {
                    createmode = CREATE_NEW; // O_CREAT | O_EXCL
                } else if options.create && options.truncate {
                    createmode = CREATE_ALWAYS; // O_CREAT | O_TRUNC
                } else if options.create {
                    createmode = OPEN_ALWAYS; // O_CREAT
                } else if options.truncate {
                    createmode = TRUNCATE_EXISTING; // O_TRUNC
                } else {
                    createmode = OPEN_EXISTING;
                }
            
                match self.fspath_ex(path) {
                    PathType::Remote(path) => {
                        let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
                        path.push(0);
          
                        let func : extern "stdcall" fn(LPCWSTR, DWORD, DWORD, DWORD, DWORD)->HANDLE = std::mem::transmute(crate::get_proc("CreateFile_\0"));
                        let h = func(path.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, createmode, FILE_ATTRIBUTE_NORMAL);
                        if h == INVALID_HANDLE_VALUE {
                            //println!("FS: open fail {:?} {:?}", String::from_utf16(&path), options);
                            return Err(FsError::Forbidden);
                        }
                        //println!("FS: open {:?} {:?}", String::from_utf16(&path), options);
                        Ok(Box::new(LocalFsFileEx { handle: h as isize}) as Box<dyn DavFile>)
                    },
                    PathType::Local(path) => {
                        let mut path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
                        path.push(0);

                        let h = CreateFileW(path.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, 0 as LPSECURITY_ATTRIBUTES, createmode, FILE_ATTRIBUTE_NORMAL, 0 as HANDLE);
                        if h == INVALID_HANDLE_VALUE {
                            //println!("FS: open fail {:?} {:?}", String::from_utf16(&path), options);
                            return Err(FsError::Forbidden);
                        }
                        //println!("FS: open {:?} {:?}", String::from_utf16(&path), options);
                        Ok(Box::new(LocalFsFile { handle: h as isize}) as Box<dyn DavFile>)
                    }
                }
            }
        }
        .boxed()
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<()> {
        async move {
            trace!("FS: create_dir {:?}", self.fspath_dbg(path));
            // if self.is_forbidden(path) {
            //     return Err(FsError::Forbidden);
            // }
            #[cfg(not(target_os = "windows"))]
            let mode = if self.inner.public { 0o755 } else { 0o700 };
            let path = self.fspath(path);
            self.blocking(move || {
                #[cfg(not(target_os = "windows"))]
                {
                    std::fs::DirBuilder::new()
                    .mode(mode)
                    .create(path)
                    .map_err(|e| e.into()) 
                }
                #[cfg(target_os = "windows")]
                {
                    std::fs::DirBuilder::new()
                    //.mode(mode)
                    .create(path)
                    .map_err(|e| e.into()) 
                }
            })
            .await
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<()> {
        async move {
            trace!("FS: remove_dir {:?}", self.fspath_dbg(path));
            let path = self.fspath(path);
            self.blocking(move || std::fs::remove_dir(path).map_err(|e| e.into()))
                .await
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<()> {
        async move {
            trace!("FS: remove_file {:?}", self.fspath_dbg(path));
            // if self.is_forbidden(path) {
            //     return Err(FsError::Forbidden);
            // }
            let path = self.fspath(path);
            self.blocking(move || std::fs::remove_file(path).map_err(|e| e.into()))
                .await
        }
        .boxed()
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<()> {
        async move {
            unsafe {
                trace!("FS: rename {:?} {:?}", self.fspath_dbg(from), self.fspath_dbg(to));
                match (self.fspath_ex(from), self.fspath_ex(to)) {
                    (PathType::Local(frompath), PathType::Local(topath)) => {
                        let mut frompath = frompath.as_os_str().encode_wide().collect::<Vec<u16>>();
                        frompath.push(0);
                        let mut topath = topath.as_os_str().encode_wide().collect::<Vec<u16>>();
                        topath.push(0);
                        if MoveFileExW(frompath.as_ptr(), topath.as_ptr(), MOVEFILE_REPLACE_EXISTING) != 0 {
                            Ok(())
                        } else {
                            Err(FsError::Forbidden)   
                        }
                    },
                    _ => Err(FsError::Forbidden),
                }
            }
        }
        .boxed()
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<()> {
        async move {
            trace!("FS: copy {:?} {:?}", self.fspath_dbg(from), self.fspath_dbg(to));
            // if self.is_forbidden(from) || self.is_forbidden(to) {
            //     return Err(FsError::Forbidden);
            // }
            let path_from = self.fspath(from);
            let path_to = self.fspath(to);

            match self.blocking(move || std::fs::copy(path_from, path_to)).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    debug!(
                        "copy({:?}, {:?}) failed: {}",
                        self.fspath_dbg(from),
                        self.fspath_dbg(to),
                        e
                    );
                    Err(e.into())
                },
            }
        }
        .boxed()
    }
}

impl Drop for LocalFsReadDir {
    fn drop(&mut self) {
        unsafe {
            FindClose(self.handle as HANDLE);
        }
    }
}

impl Iterator for LocalFsReadDir {
    type Item = Box<dyn DavDirEntry>;
    
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.handle as HANDLE == INVALID_HANDLE_VALUE {
                return None;
            }
            let entry = Box::new(LocalFsDirEntryEx(self.inner));
            if FindNextFileW(self.handle as HANDLE, &mut self.inner) == 0 {
                FindClose(self.handle as HANDLE);
                self.handle = INVALID_HANDLE_VALUE as isize;
            }
            Some(entry)
        }
    }
}

impl Drop for LocalFsReadDirEx {
    fn drop(&mut self) {
        unsafe {
            if self.handle as HANDLE != INVALID_HANDLE_VALUE {
                let func : extern "stdcall" fn(HANDLE)->BOOL = std::mem::transmute(crate::get_proc("FindClose_\0"));
                func(self.handle as HANDLE);
                self.handle = INVALID_HANDLE_VALUE as isize;                
            }
        }
    }
}

impl Iterator for LocalFsReadDirEx {
    type Item = Box<dyn DavDirEntry>;
    
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.handle as HANDLE == INVALID_HANDLE_VALUE {
                return None;
            }
            let entry = Box::new(LocalFsDirEntryEx(self.inner));
            let func : extern "stdcall" fn(HANDLE, LPWIN32_FIND_DATAW)->BOOL = std::mem::transmute(crate::get_proc("FindNextFile_\0"));
            if func(self.handle as HANDLE, &mut self.inner) == 0 {
                let func : extern "stdcall" fn(HANDLE)->BOOL = std::mem::transmute(crate::get_proc("FindClose_\0"));
                func(self.handle as HANDLE);
                self.handle = INVALID_HANDLE_VALUE as isize;
            }
            Some(entry)
        }
    }
}

impl DavDirEntry for LocalFsDirEntryEx {
    fn metadata<'a>(&'a self) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            let mut fa = WIN32_FILE_ATTRIBUTE_DATA {
                dwFileAttributes: self.0.dwFileAttributes,
                ftCreationTime: self.0.ftCreationTime,
                ftLastAccessTime: self.0.ftLastAccessTime,
                ftLastWriteTime: self.0.ftLastWriteTime,
                nFileSizeHigh: self.0.nFileSizeHigh,
                nFileSizeLow: self.0.nFileSizeLow,
            };
            if (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            && self.0.dwReserved0 != IO_REPARSE_TAG_SYMLINK 
            && self.0.dwReserved0 != IO_REPARSE_TAG_MOUNT_POINT {
                fa.dwFileAttributes &= !FILE_ATTRIBUTE_REPARSE_POINT;
            }
            Ok(Box::new(LocalFsMetaDataEx(fa)) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn name(&self) -> Vec<u8> {
        let name = self.0.cFileName;
        let mut i = 0;
        while name[i] != 0 {
            i += 1;
        }
        String::from_utf16(&name[ .. i]).unwrap().as_bytes().to_vec()
    }

    fn is_dir<'a>(&'a self) -> FsFuture<bool> {
        let dir = (self.0.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        let sym = (self.0.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        && (self.0.dwReserved0 == IO_REPARSE_TAG_SYMLINK 
        || self.0.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
        Box::pin(future::ready(Ok(dir && !sym)))
    }

    fn is_file<'a>(&'a self) -> FsFuture<bool> {
        let dir = (self.0.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        let sym = (self.0.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        && (self.0.dwReserved0 == IO_REPARSE_TAG_SYMLINK 
        || self.0.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
        Box::pin(future::ready(Ok(!dir && !sym)))
    }

    fn is_symlink<'a>(&'a self) -> FsFuture<bool> {
        let sym = (self.0.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        && (self.0.dwReserved0 == IO_REPARSE_TAG_SYMLINK 
        || self.0.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
        Box::pin(future::ready(Ok(sym)))
    }
}

impl Drop for LocalFsFile {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle as HANDLE);
        }
    }
}

impl DavFile for LocalFsFile {
    fn metadata<'a>(&'a mut self) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            unsafe {
                let mut bi : BY_HANDLE_FILE_INFORMATION = Default::default();
                let mut ti : FILE_ATTRIBUTE_TAG_INFO = Default::default();
    
                let mut result = GetFileInformationByHandle(self.handle as HANDLE, &mut bi);
                if result != 0 {
                    result = GetFileInformationByHandleEx(self.handle as HANDLE, FileAttributeTagInfo, &mut ti as *mut FILE_ATTRIBUTE_TAG_INFO as LPVOID, std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32);
                    if result == 0 {
                        if GetLastError() == ERROR_INVALID_PARAMETER {
                            ti.ReparseTag = 0;
                        } else {
                            return Err(FsError::Forbidden);
                        }
                    }
                } else {
                    return Err(FsError::Forbidden);
                }
                let mut fa = WIN32_FILE_ATTRIBUTE_DATA {
                    dwFileAttributes: bi.dwFileAttributes,
                    ftCreationTime: bi.ftCreationTime,
                    ftLastAccessTime: bi.ftLastAccessTime,
                    ftLastWriteTime: bi.ftLastWriteTime,
                    nFileSizeHigh: bi.nFileSizeHigh,
                    nFileSizeLow: bi.nFileSizeLow,
                };
                if (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                && ti.ReparseTag != IO_REPARSE_TAG_SYMLINK 
                && ti.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT {
                    fa.dwFileAttributes &= !FILE_ATTRIBUTE_REPARSE_POINT;
                }
                Ok(Box::new(LocalFsMetaDataEx(fa)) as Box<dyn DavMetaData>)
            }
        }
        .boxed()
    }

    fn write_bytes<'a>(&'a mut self, buf: Bytes) -> FsFuture<()> {
        async move {
            unsafe {
                let mut total : usize = 0;
                while total < buf.len() {
                    let mut written : DWORD = 0;
                    let r = WriteFile(self.handle as HANDLE, (buf.as_ptr().add(total)) as LPCVOID, (buf.len() - total) as DWORD, &mut written, 0 as LPOVERLAPPED);
                    if r == 0 {
                        return Err(FsError::Forbidden);
                    }
                    total += written as usize;
                }
                Ok(())
            }
        }
        .boxed()
    }

    fn write_buf<'a>(&'a mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<()> {
        async move {
            unsafe {
                while buf.remaining() > 0 {
                    let mut written : DWORD = 0;
                    let r = WriteFile(self.handle as HANDLE, buf.chunk().as_ptr() as LPCVOID, buf.chunk().len() as DWORD, &mut written, 0 as LPOVERLAPPED);
                    if r == 0 {
                        return Err(FsError::Forbidden);
                    }
                    buf.advance(written as usize);
                }
                Ok(())
            }
        }
        .boxed()
    }

    fn read_bytes<'a>(&'a mut self, count: usize) -> FsFuture<Bytes> {
        async move {
            unsafe {
                let mut buf = BytesMut::with_capacity(count);
                buf.set_len(count);
                let mut n : DWORD = 0;
                let r = ReadFile(self.handle as HANDLE, buf.as_mut_ptr() as LPVOID, count as DWORD, &mut n, 0 as LPOVERLAPPED);
                if r == 0 {
                    return Err(FsError::Forbidden);
                }
                buf.set_len(n as usize);
                Ok(buf.freeze())
            }
        }
        .boxed()
    }

    fn seek<'a>(&'a mut self, pos: SeekFrom) -> FsFuture<u64> {
        async move {
            unsafe {
                let (m, distance) = match pos {
                    SeekFrom::Start(offset) => (FILE_BEGIN, offset  as i64),
                    SeekFrom::Current(offset) => (FILE_CURRENT, offset as i64),
                    SeekFrom::End(offset) => (FILE_END, offset as i64),
                };
                let mut n : LARGE_INTEGER = Default::default();
                let mut d : LARGE_INTEGER = Default::default();
                *d.QuadPart_mut() = distance;
                let r = SetFilePointerEx(self.handle as HANDLE, d, &mut n, m);
                if r == 0 {
                    return Err(FsError::Forbidden);
                }
                Ok(*n.QuadPart() as u64)
            }
        }
        .boxed()
    }

    fn flush<'a>(&'a mut self) -> FsFuture<()> {
        future::ok(()).boxed()
    }
}

impl Drop for LocalFsFileEx {
    fn drop(&mut self) {
        unsafe {
            if self.handle as HANDLE != INVALID_HANDLE_VALUE {
                let func : extern "stdcall" fn(HANDLE)->BOOL = std::mem::transmute(crate::get_proc("CloseHandle_\0"));
                func(self.handle as HANDLE);
                self.handle = INVALID_HANDLE_VALUE as isize;                
            }
        }
    }
}

impl DavFile for LocalFsFileEx {
    fn metadata<'a>(&'a mut self) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            unsafe {
                let mut fa : WIN32_FILE_ATTRIBUTE_DATA = Default::default();
                let func : extern "stdcall" fn(HANDLE, LPWIN32_FILE_ATTRIBUTE_DATA)->BOOL = std::mem::transmute(crate::get_proc("GetFileInformationByHandle_\0"));
                let result = func(self.handle as HANDLE, &mut fa);
                if result == 0 {
                    return Err(FsError::Forbidden);
                }
                Ok(Box::new(LocalFsMetaDataEx(fa)) as Box<dyn DavMetaData>)
            }
        }
        .boxed()
    }

    fn write_bytes<'a>(&'a mut self, _buf: Bytes) -> FsFuture<()> {
        async move {
            panic!();
        }
        .boxed()
    }

    fn write_buf<'a>(&'a mut self, mut _buf: Box<dyn Buf + Send>) -> FsFuture<()> {
        async move {
            panic!();
        }
        .boxed()
    }

    fn read_bytes<'a>(&'a mut self, count: usize) -> FsFuture<Bytes> {
        async move {
            unsafe {
                let mut buf = BytesMut::with_capacity(count);
                buf.set_len(count);
                let mut n : DWORD = 0;
                let func : extern "stdcall" fn(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)->BOOL = std::mem::transmute(crate::get_proc("ReadFile_\0"));
                let r = func(self.handle as HANDLE, buf.as_mut_ptr() as LPVOID, count as DWORD, &mut n, 0 as LPOVERLAPPED);
                if r == 0 {
                    return Err(FsError::Forbidden);
                }
                buf.set_len(n as usize);
                Ok(buf.freeze())
            }
        }
        .boxed()
    }

    fn seek<'a>(&'a mut self, pos: SeekFrom) -> FsFuture<u64> {
        async move {
            unsafe {
                let (m, distance) = match pos {
                    SeekFrom::Start(offset) => (FILE_BEGIN, offset  as i64),
                    SeekFrom::Current(offset) => (FILE_CURRENT, offset as i64),
                    SeekFrom::End(offset) => (FILE_END, offset as i64),
                };
                let mut n : LARGE_INTEGER = Default::default();
                let mut d : LARGE_INTEGER = Default::default();
                *d.QuadPart_mut() = distance;
                let func : extern "stdcall" fn(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD)->BOOL = std::mem::transmute(crate::get_proc("SetFilePointerEx_\0"));
                let r = func(self.handle as HANDLE, d, &mut n, m);
                if r == 0 {
                    return Err(FsError::Forbidden);
                }
                Ok(*n.QuadPart() as u64)
            }
        }
        .boxed()
    }

    fn flush<'a>(&'a mut self) -> FsFuture<()> {
        future::ok(()).boxed()
    }
}

impl DavMetaData for LocalFsMetaDataEx {
    fn len(&self) -> u64 {
        ((self.0.nFileSizeHigh as u64) << 32) + self.0.nFileSizeLow as u64
    }
    fn created(&self) -> FsResult<SystemTime> {
        Ok(UNIX_EPOCH + Duration::from_nanos((((self.0.ftCreationTime.dwHighDateTime as i64) << 32) +
        self.0.ftCreationTime.dwLowDateTime as i64 - 116444736000000000) as u64 * 100))
    }
    fn modified(&self) -> FsResult<SystemTime> {
        Ok(UNIX_EPOCH + Duration::from_nanos((((self.0.ftLastWriteTime.dwHighDateTime as i64) << 32) +
        self.0.ftLastWriteTime.dwLowDateTime as i64 - 116444736000000000) as u64 * 100))
    }
    fn accessed(&self) -> FsResult<SystemTime> {
        Ok(UNIX_EPOCH + Duration::from_nanos((((self.0.ftLastAccessTime.dwHighDateTime as i64) << 32) +
        self.0.ftLastAccessTime.dwLowDateTime as i64 - 116444736000000000) as u64 * 100))
    }

    fn status_changed(&self) -> FsResult<SystemTime> {
        Ok(UNIX_EPOCH + Duration::from_nanos((((self.0.ftCreationTime.dwHighDateTime as i64) << 32) +
        self.0.ftCreationTime.dwLowDateTime as i64 - 116444736000000000) as u64 * 100))
    }

    fn is_dir(&self) -> bool {
        (self.0.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == FILE_ATTRIBUTE_DIRECTORY
    }
    fn is_file(&self) -> bool {
        (self.0.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0
    }
    fn is_symlink(&self) -> bool {
        (self.0.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    fn executable(&self) -> FsResult<bool> {
        panic!();
    }

    // same as the default apache etag.
    fn etag(&self) -> Option<String> {
        let t = (((self.0.ftLastWriteTime.dwHighDateTime as i64) << 32) +
        self.0.ftLastWriteTime.dwLowDateTime as i64 - 116444736000000000) as u64 / 1000;
        if self.is_file() {
            Some(format!("{:x}-{:x}", self.len(), t))
        } else {
            Some(format!("{:x}", t))
        }
    }
}

// impl From<&io::Error> for FsError {
//     fn from(e: &io::Error) -> Self {
//         if let Some(errno) = e.raw_os_error() {
//             // specific errors.
//             #[cfg(not(target_os = "windows"))]
//             match errno {
//                 libc::EMLINK | libc::ENOSPC | libc::EDQUOT => return FsError::InsufficientStorage,
//                 libc::EFBIG => return FsError::TooLarge,
//                 libc::EACCES | libc::EPERM => return FsError::Forbidden,
//                 libc::ENOTEMPTY | libc::EEXIST => return FsError::Exists,
//                 libc::ELOOP => return FsError::LoopDetected,
//                 libc::ENAMETOOLONG => return FsError::PathTooLong,
//                 libc::ENOTDIR => return FsError::Forbidden,
//                 libc::EISDIR => return FsError::Forbidden,
//                 libc::EROFS => return FsError::Forbidden,
//                 libc::ENOENT => return FsError::NotFound,
//                 libc::ENOSYS => return FsError::NotImplemented,
//                 libc::EXDEV => return FsError::IsRemote,
//                 _ => {},
//             }
//             #[cfg(target_os = "windows")]
//             match errno {
//                 // libc::EMLINK | libc::ENOSPC | libc::EDQUOT => return FsError::InsufficientStorage,
//                 libc::EMLINK | libc::ENOSPC => return FsError::InsufficientStorage,
//                 libc::EFBIG => return FsError::TooLarge,
//                 libc::EACCES | libc::EPERM => return FsError::Forbidden,
//                 libc::ENOTEMPTY | libc::EEXIST => return FsError::Exists,
//                 libc::ELOOP => return FsError::LoopDetected,
//                 libc::ENAMETOOLONG => return FsError::PathTooLong,
//                 libc::ENOTDIR => return FsError::Forbidden,
//                 libc::EISDIR => return FsError::Forbidden,
//                 libc::EROFS => return FsError::Forbidden,
//                 libc::ENOENT => return FsError::NotFound,
//                 libc::ENOSYS => return FsError::NotImplemented,
//                 libc::EXDEV => return FsError::IsRemote,
//                 _ => {},
//             }
//         } else {
//             // not an OS error - must be "not implemented"
//             // (e.g. metadata().created() on systems without st_crtime)
//             return FsError::NotImplemented;
//         }
//         // generic mappings for-whatever is left.
//         match e.kind() {
//             ErrorKind::NotFound => FsError::NotFound,
//             ErrorKind::PermissionDenied => FsError::Forbidden,
//             _ => FsError::GeneralFailure,
//         }
//     }
// }

// impl From<io::Error> for FsError {
//     fn from(e: io::Error) -> Self {
//         (&e).into()
//     }
// }
