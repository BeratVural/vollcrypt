#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(windows))]
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileBasicMetadata {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum WindowsBackupError {
    #[error("Windows backup support is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("Windows backup privilege is unavailable: {0}")]
    PrivilegeUnavailable(&'static str),
    #[error("Windows backup supports regular, non-reparse, non-EFS files only: {0}")]
    UnsupportedFile(String),
    #[error("Windows API {operation} failed: {source}")]
    Windows {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Windows backup stream made no progress during {0}")]
    NoProgress(&'static str),
    #[error("Windows backup validation failed: {0}")]
    PartialWrite(&'static str),
    #[error("durable move cannot cross Windows volumes: {source_path} -> {destination_path}")]
    CrossVolumeMove {
        source_path: String,
        destination_path: String,
    },
}

pub type Result<T> = std::result::Result<T, WindowsBackupError>;

#[cfg(windows)]
mod imp;

#[cfg(windows)]
pub use imp::{
    capture_file, hash_default_stream, move_file_noreplace_durable, restore_file,
    validate_active_response_capability, validate_required_privileges,
};

#[cfg(not(windows))]
pub fn capture_file(_source: &Path, _archive: &Path) -> Result<FileBasicMetadata> {
    Err(WindowsBackupError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn restore_file(
    _archive: &Path,
    _destination: &Path,
    _metadata: FileBasicMetadata,
) -> Result<()> {
    Err(WindowsBackupError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn hash_default_stream(_path: &Path, _domain: &[u8]) -> Result<[u8; 32]> {
    Err(WindowsBackupError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn validate_active_response_capability(_directory: &Path) -> Result<()> {
    Err(WindowsBackupError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn validate_required_privileges() -> Result<()> {
    Err(WindowsBackupError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn move_file_noreplace_durable(_source: &Path, _destination: &Path) -> Result<()> {
    Err(WindowsBackupError::UnsupportedPlatform)
}
