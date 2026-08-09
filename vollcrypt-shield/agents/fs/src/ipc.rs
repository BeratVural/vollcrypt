#[cfg(unix)]
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::error::{AgentError, Result};

#[cfg(unix)]
const MAX_REQUEST_BYTES: u64 = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    pub scope: String,
    pub contained: bool,
    pub reason: Option<String>,
    pub audit_records: usize,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    command: String,
    scope: String,
}

#[cfg(unix)]
pub struct LocalStatusServer {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
}

#[cfg(unix)]
impl LocalStatusServer {
    pub fn bind(state_dir: &Path) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let directory = state_dir.join("ipc");
        std::fs::create_dir_all(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let path = directory.join("status.sock");
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket() {
                return Err(AgentError::Config(format!(
                    "refusing to replace non-socket IPC path: {}",
                    path.display()
                )));
            }
            std::fs::remove_file(&path)?;
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, path })
    }

    pub fn serve_pending(&self, status: &AgentStatus) -> Result<bool> {
        let (stream, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        // A malformed local client must not stop filesystem monitoring.
        let _ = handle_status_connection(stream, status);
        Ok(true)
    }
}

#[cfg(unix)]
fn handle_status_connection(
    mut stream: std::os::unix::net::UnixStream,
    status: &AgentStatus,
) -> Result<()> {
    use std::io::{Read, Write};

    stream.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_millis(250)))?;
    let mut request = Vec::new();
    std::io::Read::by_ref(&mut stream)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request)?;
    if request.len() as u64 > MAX_REQUEST_BYTES {
        return Err(AgentError::Serialization(
            "local IPC request exceeds 4096 bytes".to_owned(),
        ));
    }
    let request: StatusRequest = serde_json::from_slice(&request)
        .map_err(|error| AgentError::Serialization(error.to_string()))?;
    if request.command != "status" || request.scope != status.scope {
        return Err(AgentError::Config(
            "local IPC accepts status only for the watched scope".to_owned(),
        ));
    }
    serde_json::to_writer(&mut stream, status)
        .map_err(|error| AgentError::Serialization(error.to_string()))?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

#[cfg(unix)]
impl Drop for LocalStatusServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
pub fn query_local_status(state_dir: &Path, scope: &str) -> std::io::Result<AgentStatus> {
    use std::io::{Read, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(state_dir.join("ipc/status.sock"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(1)))?;
    serde_json::to_writer(
        &mut stream,
        &serde_json::json!({ "command": "status", "scope": scope }),
    )
    .map_err(std::io::Error::other)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut response)?;
    if response.len() as u64 > MAX_REQUEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local IPC response exceeds 4096 bytes",
        ));
    }
    serde_json::from_slice(&response)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn local_status_socket_is_owner_only_and_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let server = LocalStatusServer::bind(directory.path()).unwrap();
        let socket = directory.path().join("ipc/status.sock");
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let status = AgentStatus {
            scope: "scope".to_owned(),
            contained: true,
            reason: Some("change".to_owned()),
            audit_records: 7,
        };
        let state_dir = directory.path().to_path_buf();
        let client = std::thread::spawn(move || query_local_status(&state_dir, "scope").unwrap());
        for _ in 0..100 {
            if server.serve_pending(&status).unwrap() {
                assert_eq!(client.join().unwrap(), status);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("local status client was not accepted");
    }
}
