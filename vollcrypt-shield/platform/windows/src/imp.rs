use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, HANDLE, LUID, SetLastError,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_BACKUP_NAME,
    SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    BackupRead, BackupWrite, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileBasicInfo, FlushFileBuffers,
    GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL, ReadFile,
    SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use crate::{FileBasicMetadata, Result, WindowsBackupError};

const BUFFER_SIZE: usize = 128 * 1024;

pub fn capture_file(source: &Path, archive: &Path) -> Result<FileBasicMetadata> {
    let _privileges = PrivilegeGuard::enable_all()?;
    let handle = open_source(source)?;
    let basic = query_basic(handle.raw())?;
    validate_attributes(source, basic.FileAttributes)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(archive)?;
    backup_read_all(handle.raw(), &mut output)?;
    output.sync_all()?;
    Ok(basic.into())
}

pub fn restore_file(archive: &Path, destination: &Path, metadata: FileBasicMetadata) -> Result<()> {
    let _privileges = PrivilegeGuard::enable_all()?;
    let mut input = File::open(archive)?;
    let handle = create_destination(destination)?;
    let result = (|| {
        backup_write_all(handle.raw(), &mut input)?;
        // SAFETY: the synchronous destination handle remains valid and writable.
        unsafe { FlushFileBuffers(handle.raw()) }
            .map_err(|error| windows_error("FlushFileBuffers", error))?;
        set_basic(handle.raw(), metadata.into())
    })();
    drop(handle);
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

pub fn hash_default_stream(path: &Path, domain: &[u8]) -> Result<[u8; 32]> {
    let _privileges = PrivilegeGuard::enable_all()?;
    let handle = open_source(path)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let mut read = 0_u32;
        // SAFETY: the buffer and byte-count pointer remain valid and the
        // synchronous source handle stays open for the call.
        unsafe { ReadFile(handle.raw(), Some(&mut buffer), Some(&mut read), None) }
            .map_err(|error| windows_error("ReadFile", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read as usize]);
    }
    Ok(hasher.finalize().into())
}

pub fn validate_active_response_capability(directory: &Path) -> Result<()> {
    if !directory.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Windows capability probe directory does not exist",
        )
        .into());
    }
    let nonce = format!("{}-{}", std::process::id(), unix_nanos());
    let source = directory.join(format!(".vollcrypt-shield-windows-probe-{nonce}"));
    let archive = directory.join(format!(".vollcrypt-shield-windows-probe-{nonce}.backup"));
    let restored = directory.join(format!(".vollcrypt-shield-windows-probe-{nonce}.restored"));
    let restored_archive = directory.join(format!(
        ".vollcrypt-shield-windows-probe-{nonce}.restored.backup"
    ));
    let cleanup = ProbeCleanup(vec![
        source.clone(),
        archive.clone(),
        restored.clone(),
        restored_archive.clone(),
    ]);
    std::fs::write(&source, b"vollcrypt-shield-windows-capability-v1")?;
    std::fs::write(ads_path(&source), b"vollcrypt-shield-ads-v1")?;
    let metadata = capture_file(&source, &archive)?;
    restore_file(&archive, &restored, metadata)?;
    let restored_metadata = query_metadata(&restored)?;
    if restored_metadata != metadata {
        return Err(WindowsBackupError::PartialWrite);
    }
    if std::fs::read(&restored)? != b"vollcrypt-shield-windows-capability-v1" {
        return Err(WindowsBackupError::PartialWrite);
    }
    if std::fs::read(ads_path(&restored))? != b"vollcrypt-shield-ads-v1" {
        return Err(WindowsBackupError::PartialWrite);
    }
    let roundtrip_metadata = capture_file(&restored, &restored_archive)?;
    if roundtrip_metadata != metadata
        || std::fs::read(&restored_archive)? != std::fs::read(&archive)?
    {
        return Err(WindowsBackupError::PartialWrite);
    }
    drop(cleanup);
    Ok(())
}

pub fn validate_required_privileges() -> Result<()> {
    drop(PrivilegeGuard::enable_all()?);
    Ok(())
}

fn query_metadata(path: &Path) -> Result<FileBasicMetadata> {
    let _privileges = PrivilegeGuard::enable_all()?;
    let handle = open_source(path)?;
    Ok(query_basic(handle.raw())?.into())
}

fn ads_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(":vollcrypt-shield-probe");
    PathBuf::from(value)
}

fn open_source(path: &Path) -> Result<OwnedHandle> {
    let wide = wide_path(path)?;
    let access = FILE_GENERIC_READ.0 | READ_CONTROL.0 | ACCESS_SYSTEM_SECURITY;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: `wide` is NUL-terminated for the duration of the call. No optional
    // pointers are supplied and the returned handle is immediately owned.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|error| windows_error("CreateFileW(source)", error))?;
    Ok(OwnedHandle(handle))
}

fn create_destination(path: &Path) -> Result<OwnedHandle> {
    let wide = wide_path(path)?;
    let access = FILE_GENERIC_WRITE.0 | WRITE_DAC.0 | WRITE_OWNER.0 | ACCESS_SYSTEM_SECURITY;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: `wide` is NUL-terminated for the duration of the call. CREATE_NEW
    // enforces no-clobber semantics and the returned handle is immediately owned.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_READ,
            None,
            CREATE_NEW,
            flags,
            None,
        )
    }
    .map_err(|error| windows_error("CreateFileW(destination)", error))?;
    Ok(OwnedHandle(handle))
}

fn query_basic(handle: HANDLE) -> Result<FILE_BASIC_INFO> {
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: `info` is valid writable storage of exactly the declared size and
    // `handle` remains open for the call.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&raw mut info).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(|error| windows_error("GetFileInformationByHandleEx", error))?;
    Ok(info)
}

fn set_basic(handle: HANDLE, info: FILE_BASIC_INFO) -> Result<()> {
    // SAFETY: `info` is valid immutable storage of exactly the declared size and
    // `handle` remains open for the call.
    unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&raw const info).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(|error| windows_error("SetFileInformationByHandle", error))
}

fn backup_read_all(handle: HANDLE, output: &mut File) -> Result<()> {
    let mut context: *mut c_void = null_mut();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let result = (|| {
        loop {
            let mut read = 0_u32;
            // SAFETY: the buffer is writable, the byte-count pointer and context
            // pointer remain valid, and the synchronous handle stays open.
            unsafe { BackupRead(handle, &mut buffer, &mut read, false, true, &mut context) }
                .map_err(|error| windows_error("BackupRead", error))?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read as usize])?;
        }
        Ok(())
    })();
    abort_backup_read(handle, &mut context);
    result
}

fn backup_write_all(handle: HANDLE, input: &mut File) -> Result<()> {
    let mut context: *mut c_void = null_mut();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let result = (|| {
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let mut offset = 0;
            while offset < read {
                let mut written = 0_u32;
                // SAFETY: the source slice, byte-count pointer, and context
                // pointer remain valid, and the synchronous handle stays open.
                unsafe {
                    BackupWrite(
                        handle,
                        &buffer[offset..read],
                        &mut written,
                        false,
                        true,
                        &mut context,
                    )
                }
                .map_err(|error| windows_error("BackupWrite", error))?;
                if written == 0 {
                    return Err(WindowsBackupError::NoProgress("restore"));
                }
                offset += written as usize;
            }
        }
        Ok(())
    })();
    abort_backup_write(handle, &mut context);
    result
}

fn abort_backup_read(handle: HANDLE, context: &mut *mut c_void) {
    let mut ignored = 0_u32;
    // SAFETY: documented abort for a context created by BackupRead on this handle.
    let _ = unsafe { BackupRead(handle, &mut [], &mut ignored, true, true, context) };
}

fn abort_backup_write(handle: HANDLE, context: &mut *mut c_void) {
    let mut ignored = 0_u32;
    // SAFETY: documented abort for a context created by BackupWrite on this handle.
    let _ = unsafe { BackupWrite(handle, &[], &mut ignored, true, true, context) };
}

fn validate_attributes(path: &Path, attributes: u32) -> Result<()> {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || attributes & FILE_ATTRIBUTE_ENCRYPTED.0 != 0
    {
        return Err(WindowsBackupError::UnsupportedFile(
            path.display().to_string(),
        ));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows path contains an interior NUL",
        )
        .into());
    }
    wide.push(0);
    Ok(wide)
}

fn windows_error(operation: &'static str, error: windows::core::Error) -> WindowsBackupError {
    WindowsBackupError::Windows {
        operation,
        source: std::io::Error::other(error.to_string()),
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns a valid Win32 handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct PrivilegeGuard {
    token: OwnedHandle,
    previous: Vec<TOKEN_PRIVILEGES>,
}

impl PrivilegeGuard {
    fn enable_all() -> Result<Self> {
        let mut token = HANDLE::default();
        // SAFETY: `token` is valid writable storage and the process pseudo-handle
        // is valid in the current process.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        }
        .map_err(|error| windows_error("OpenProcessToken", error))?;
        let mut guard = Self {
            token: OwnedHandle(token),
            previous: Vec::new(),
        };
        for (name, label) in [
            (SE_BACKUP_NAME, "SeBackupPrivilege"),
            (SE_RESTORE_NAME, "SeRestorePrivilege"),
            (SE_SECURITY_NAME, "SeSecurityPrivilege"),
        ] {
            guard.enable(name, label)?;
        }
        Ok(guard)
    }

    fn enable(&mut self, name: PCWSTR, label: &'static str) -> Result<()> {
        let mut luid = LUID::default();
        // SAFETY: uses a static NUL-terminated privilege name and writes one LUID.
        unsafe { LookupPrivilegeValueW(None, name, &mut luid) }
            .map_err(|error| windows_error("LookupPrivilegeValueW", error))?;
        let requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut returned = 0_u32;
        // SAFETY: the token has adjustment/query access and all structures live
        // through the call.
        unsafe {
            SetLastError(ERROR_SUCCESS);
            AdjustTokenPrivileges(
                self.token.raw(),
                false,
                Some(&raw const requested),
                size_of::<TOKEN_PRIVILEGES>() as u32,
                Some(&raw mut previous),
                Some(&mut returned),
            )
        }
        .map_err(|error| windows_error("AdjustTokenPrivileges", error))?;
        // SAFETY: read immediately after AdjustTokenPrivileges as its contract requires.
        if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            return Err(WindowsBackupError::PrivilegeUnavailable(label));
        }
        self.previous.push(previous);
        Ok(())
    }
}

impl Drop for PrivilegeGuard {
    fn drop(&mut self) {
        for previous in self.previous.iter().rev() {
            // SAFETY: restores state returned for this same still-open token.
            let _ = unsafe {
                AdjustTokenPrivileges(self.token.raw(), false, Some(previous), 0, None, None)
            };
        }
    }
}

struct ProbeCleanup(Vec<PathBuf>);

impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos())
}

impl From<FILE_BASIC_INFO> for FileBasicMetadata {
    fn from(value: FILE_BASIC_INFO) -> Self {
        Self {
            creation_time: value.CreationTime,
            last_access_time: value.LastAccessTime,
            last_write_time: value.LastWriteTime,
            change_time: value.ChangeTime,
            attributes: value.FileAttributes,
        }
    }
}

impl From<FileBasicMetadata> for FILE_BASIC_INFO {
    fn from(value: FileBasicMetadata) -> Self {
        Self {
            CreationTime: value.creation_time,
            LastAccessTime: value.last_access_time,
            LastWriteTime: value.last_write_time,
            ChangeTime: value.change_time,
            FileAttributes: value.attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_privileges_fail_closed_or_roundtrip_succeeds() {
        let directory = tempfile::tempdir().unwrap();
        let result = validate_active_response_capability(directory.path());
        if let Err(error) = result {
            assert!(matches!(
                error,
                WindowsBackupError::PrivilegeUnavailable(_) | WindowsBackupError::Windows { .. }
            ));
        }
    }
}
