use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use vollcrypt_shield_core::{
    AuditEvent, AuditEventKind, MlDsa65PublicKey, MlDsa65SecretKey, SignedAuditRecord,
    verify_audit_chain,
};

use crate::error::{AgentError, Result};

const MAX_AUDIT_RECORD_SIZE: usize = 1_048_576;

pub struct AuditStore {
    path: PathBuf,
    records: Vec<SignedAuditRecord>,
}

impl AuditStore {
    pub fn load_or_new(path: impl Into<PathBuf>, trusted_key: &MlDsa65PublicKey) -> Result<Self> {
        let path = path.into();
        let records = if path.exists() {
            read_records(&path)?
        } else {
            Vec::new()
        };
        verify_audit_chain(&records)?;
        if let Some(first) = records.first()
            && first.public_key()?.key_id() != trusted_key.key_id()
        {
            return Err(AgentError::Config(
                "audit signer does not match configured agent key".to_owned(),
            ));
        }
        Ok(Self { path, records })
    }

    pub fn append(
        &mut self,
        timestamp_unix_ms: u64,
        scope_id: &str,
        kind: AuditEventKind,
        path: Option<String>,
        detail: impl Into<String>,
        secret: &MlDsa65SecretKey,
    ) -> Result<SignedAuditRecord> {
        let sequence = self.records.len() as u64;
        let previous_hash = self
            .records
            .last()
            .map(SignedAuditRecord::event_hash)
            .unwrap_or([0; 32]);
        let event = AuditEvent::new(
            sequence,
            timestamp_unix_ms,
            scope_id,
            kind,
            path,
            detail,
            previous_hash,
        );
        let record = SignedAuditRecord::sign(&event, secret)?;
        let encoded = record.to_cbor()?;
        if encoded.len() > MAX_AUDIT_RECORD_SIZE {
            return Err(AgentError::Serialization(
                "audit record exceeds size limit".to_owned(),
            ));
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&(encoded.len() as u32).to_be_bytes())?;
        file.write_all(&encoded)?;
        file.sync_data()?;
        self.records.push(record.clone());
        Ok(record)
    }

    pub fn verify(&self) -> Result<Vec<AuditEvent>> {
        verify_audit_chain(&self.records).map_err(Into::into)
    }
}

fn read_records(path: &Path) -> Result<Vec<SignedAuditRecord>> {
    let mut file = std::fs::File::open(path)?;
    let mut records = Vec::new();
    loop {
        let mut length = [0u8; 4];
        let first = file.read(&mut length[..1])?;
        if first == 0 {
            return Ok(records);
        }
        file.read_exact(&mut length[1..]).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                AgentError::Serialization("truncated audit record length".to_owned())
            } else {
                AgentError::Io(error)
            }
        })?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_AUDIT_RECORD_SIZE {
            return Err(AgentError::Serialization(
                "invalid audit record length".to_owned(),
            ));
        }
        let mut encoded = vec![0u8; length];
        file.read_exact(&mut encoded)?;
        records.push(SignedAuditRecord::from_cbor(&encoded)?);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::MlDsa65KeyPair;

    #[test]
    fn persisted_audit_chain_verifies() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut store = AuditStore::load_or_new(&path, &pair.public).unwrap();
        store
            .append(
                1,
                "scope",
                AuditEventKind::AgentStarted,
                None,
                "start",
                &pair.secret,
            )
            .unwrap();
        let loaded = AuditStore::load_or_new(path, &pair.public).unwrap();
        assert_eq!(loaded.verify().unwrap().len(), 1);
    }

    #[test]
    fn truncated_persisted_record_is_rejected() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut store = AuditStore::load_or_new(&path, &pair.public).unwrap();
        store
            .append(
                1,
                "scope",
                AuditEventKind::AgentStarted,
                None,
                "start",
                &pair.secret,
            )
            .unwrap();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(std::fs::metadata(&path).unwrap().len() - 1)
            .unwrap();
        assert!(AuditStore::load_or_new(path, &pair.public).is_err());
    }
}
