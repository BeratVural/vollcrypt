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
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileBasicInfo, FlushFileBuffers,
    GetFileInformationByHandleEx, GetVolumePathNameW, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_EXISTING, READ_CONTROL, ReadFile, SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use crate::{FileBasicMetadata, Result, WindowsBackupError};

const BUFFER_SIZE: usize = 128 * 1024;

pub fn capture_file(source: &Path, archive: &Path) -> Result<FileBasicMetadata> {
    let _privileges = PrivilegeGuard::enable_all()?;
    let handle = open_source(source)?;
    let initial = query_basic(handle.raw())?;
    validate_attributes(source, initial.FileAttributes)?;
    suppress_timestamp_updates(handle.raw())?;
    let guarded = query_basic(handle.raw())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(archive)?;
    backup_read_all(handle.raw(), &mut output)?;
    output.sync_all()?;
    let captured = query_basic(handle.raw())?;
    validate_attributes(source, captured.FileAttributes)?;
    if !stable_capture_metadata_equal(captured, guarded) {
        return Err(WindowsBackupError::PartialWrite(
            "source content metadata changed during BackupRead",
        ));
    }
    set_basic(handle.raw(), initial)?;
    if query_basic(handle.raw())? != initial {
        return Err(WindowsBackupError::PartialWrite(
            "source basic metadata could not be restored after capture",
        ));
    }
    Ok(initial.into())
}

pub fn restore_file(archive: &Path, destination: &Path, metadata: FileBasicMetadata) -> Result<()> {
    let _privileges = PrivilegeGuard::enable_all()?;
    let mut input = File::open(archive)?;
    let handle = create_destination(destination)?;
    let result = (|| {
        suppress_timestamp_updates(handle.raw())?;
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
        return Err(WindowsBackupError::PartialWrite(
            "restored basic metadata differs",
        ));
    }
    let roundtrip_metadata = capture_file(&restored, &restored_archive)?;
    if roundtrip_metadata != metadata {
        return Err(WindowsBackupError::PartialWrite(
            "round-trip basic metadata differs",
        ));
    }
    if std::fs::read(&restored_archive)? != std::fs::read(&archive)? {
        return Err(WindowsBackupError::PartialWrite(
            "round-trip backup stream differs",
        ));
    }
    if std::fs::read(&restored)? != b"vollcrypt-shield-windows-capability-v1" {
        return Err(WindowsBackupError::PartialWrite(
            "restored default stream differs",
        ));
    }
    if std::fs::read(ads_path(&restored))? != b"vollcrypt-shield-ads-v1" {
        return Err(WindowsBackupError::PartialWrite(
            "restored alternate stream differs",
        ));
    }
    drop(cleanup);
    Ok(())
}

pub fn validate_required_privileges() -> Result<()> {
    drop(PrivilegeGuard::enable_all()?);
    Ok(())
}

pub fn move_file_noreplace_durable(source: &Path, destination: &Path) -> Result<()> {
    let source_volume = volume_root(source)?;
    let destination_parent = destination.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "move destination has no parent",
        )
    })?;
    let destination_volume = volume_root(destination_parent)?;
    if !source_volume.eq_ignore_ascii_case(&destination_volume) {
        return Err(WindowsBackupError::CrossVolumeMove {
            source_path: source.display().to_string(),
            destination_path: destination.display().to_string(),
        });
    }
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: both paths are NUL-terminated for the duration of the call.
    // Omitting MOVEFILE_REPLACE_EXISTING makes the operation fail closed if a
    // racing process creates the destination. WRITE_THROUGH waits for the move
    // to reach durable storage before returning.
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| windows_error("MoveFileExW", error))
}

fn volume_root(path: &Path) -> Result<String> {
    let path = wide_path(path)?;
    let mut root = vec![0_u16; 32_768];
    // SAFETY: the input is NUL-terminated and the output slice is valid
    // writable storage for the duration of the call.
    unsafe { GetVolumePathNameW(PCWSTR(path.as_ptr()), &mut root) }
        .map_err(|error| windows_error("GetVolumePathNameW", error))?;
    let length = root.iter().position(|value| *value == 0).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows volume root is not NUL-terminated",
        )
    })?;
    Ok(String::from_utf16_lossy(&root[..length]))
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
    let access =
        FILE_GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0 | READ_CONTROL.0 | ACCESS_SYSTEM_SECURITY;
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

fn suppress_timestamp_updates(handle: HANDLE) -> Result<()> {
    // Windows documents -1 as the per-handle request to keep I/O from
    // updating these timestamps. This prevents BackupRead/BackupWrite from
    // manufacturing metadata drift while streams are copied.
    set_basic(
        handle,
        FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: -1,
            LastWriteTime: -1,
            ChangeTime: -1,
            FileAttributes: 0,
        },
    )
}

fn stable_capture_metadata_equal(left: FILE_BASIC_INFO, right: FILE_BASIC_INFO) -> bool {
    left.CreationTime == right.CreationTime
        && left.LastWriteTime == right.LastWriteTime
        && left.FileAttributes == right.FileAttributes
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

    fn qualification_required() -> bool {
        std::env::var_os("VOLLCRYPT_SHIELD_WINDOWS_ACTIVE_QUALIFICATION").is_some()
    }

    #[test]
    fn capture_metadata_filter_allows_only_system_managed_time_drift() {
        let expected = FILE_BASIC_INFO {
            CreationTime: 10,
            LastAccessTime: 20,
            LastWriteTime: 30,
            ChangeTime: 40,
            FileAttributes: 0x20,
        };
        let system_time_drift = FILE_BASIC_INFO {
            LastAccessTime: 21,
            ChangeTime: 41,
            ..expected
        };
        assert!(stable_capture_metadata_equal(system_time_drift, expected));
        assert!(!stable_capture_metadata_equal(
            FILE_BASIC_INFO {
                LastWriteTime: 31,
                ..expected
            },
            expected
        ));
        assert!(!stable_capture_metadata_equal(
            FILE_BASIC_INFO {
                FileAttributes: 0x21,
                ..expected
            },
            expected
        ));
    }

    fn privileged_host_available() -> bool {
        match validate_required_privileges() {
            Ok(()) => true,
            Err(error) if qualification_required() => {
                panic!("Windows active-response qualification requires privileges: {error}")
            }
            Err(_) => false,
        }
    }

    #[test]
    fn capability_probe_succeeds_or_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let result = validate_active_response_capability(directory.path());
        if qualification_required() {
            result.unwrap();
            return;
        }
        if let Err(error) = result {
            assert!(matches!(
                error,
                WindowsBackupError::PrivilegeUnavailable(_)
                    | WindowsBackupError::Windows { .. }
                    | WindowsBackupError::PartialWrite(_)
            ));
        }
    }

    #[test]
    fn durable_move_never_replaces_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("destination");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&destination, b"destination").unwrap();

        assert!(move_file_noreplace_durable(&source, &destination).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"source");
        assert_eq!(std::fs::read(&destination).unwrap(), b"destination");

        std::fs::remove_file(&destination).unwrap();
        move_file_noreplace_durable(&source, &destination).unwrap();
        assert!(!source.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"source");
    }

    #[test]
    fn locked_file_move_fails_without_modifying_the_source() {
        if !privileged_host_available() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("locked.conf");
        let destination = directory.path().join("locked.destination");
        std::fs::write(&source, b"locked").unwrap();
        let wide = wide_path(&source).unwrap();
        // SAFETY: the path is NUL-terminated and the returned handle is owned.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .unwrap();
        let lock = OwnedHandle(handle);

        assert!(move_file_noreplace_durable(&source, &destination).is_err());
        assert!(source.exists());
        assert!(!destination.exists());
        drop(lock);
        assert_eq!(std::fs::read(&source).unwrap(), b"locked");
    }

    #[test]
    fn file_and_directory_reparse_points_are_rejected() {
        if !privileged_host_available() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let target_file = directory.path().join("target.conf");
        let target_directory = directory.path().join("target-dir");
        let file_link = directory.path().join("file-link");
        let directory_link = directory.path().join("directory-link");
        std::fs::write(&target_file, b"target").unwrap();
        std::fs::create_dir(&target_directory).unwrap();

        let file_link_created =
            std::os::windows::fs::symlink_file(&target_file, &file_link).is_ok();
        if qualification_required() {
            assert!(
                file_link_created,
                "qualification host cannot create file symlink"
            );
        }
        if file_link_created {
            assert!(matches!(
                capture_file(&file_link, &directory.path().join("file.backup")),
                Err(WindowsBackupError::UnsupportedFile(_))
            ));
        }
        let directory_link_created =
            std::os::windows::fs::symlink_dir(&target_directory, &directory_link).is_ok();
        if qualification_required() {
            assert!(
                directory_link_created,
                "qualification host cannot create directory junction/reparse point"
            );
        }
        if directory_link_created {
            assert!(matches!(
                capture_file(&directory_link, &directory.path().join("directory.backup")),
                Err(WindowsBackupError::UnsupportedFile(_))
            ));
        }
    }

    #[test]
    fn cross_volume_move_fails_closed_and_preserves_source() {
        let primary = tempfile::tempdir().unwrap();
        let primary_root = primary.path().canonicalize().unwrap();
        let primary_prefix = primary_root.components().next();
        let mut secondary = None;
        for letter in b'C'..=b'Z' {
            let root = PathBuf::from(format!("{}:\\", letter as char));
            if !root.is_dir() || root.components().next() == primary_prefix {
                continue;
            }
            if let Ok(directory) = tempfile::Builder::new()
                .prefix("vollcrypt-shield-cross-volume-")
                .tempdir_in(&root)
                && !volume_root(directory.path())
                    .unwrap()
                    .eq_ignore_ascii_case(&volume_root(primary.path()).unwrap())
            {
                secondary = Some(directory);
                break;
            }
        }
        let Some(secondary) = secondary else {
            assert!(
                !qualification_required(),
                "qualification host requires two writable volumes"
            );
            return;
        };
        let source = primary.path().join("source");
        let destination = secondary.path().join("destination");
        std::fs::write(&source, b"cross-volume").unwrap();

        assert!(move_file_noreplace_durable(&source, &destination).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"cross-volume");
        assert!(!destination.exists());
    }
}
