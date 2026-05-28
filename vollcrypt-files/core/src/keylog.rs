use crate::error::FileFormatError;
use crate::signing::{ed25519_sign, ed25519_verify};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLogEntryType {
    DeviceRegister {
        user_id: [u8; 16],
        device_id: [u8; 16],
        device_pubkey: [u8; 32],
        human_label: String, // max 256 byte UTF-8
    },
    DeviceRevoke {
        device_id: [u8; 16],
    },
}

impl KeyLogEntryType {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            KeyLogEntryType::DeviceRegister {
                user_id,
                device_id,
                device_pubkey,
                human_label,
            } => {
                let label_bytes = human_label.as_bytes();
                let mut out = Vec::with_capacity(16 + 16 + 32 + 2 + label_bytes.len());
                out.extend_from_slice(user_id);
                out.extend_from_slice(device_id);
                out.extend_from_slice(device_pubkey);
                out.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(label_bytes);
                out
            }
            KeyLogEntryType::DeviceRevoke { device_id } => device_id.to_vec(),
        }
    }

    pub fn parse(entry_type_byte: u8, data: &[u8]) -> Result<Self, FileFormatError> {
        match entry_type_byte {
            0 => {
                if data.len() < 16 + 16 + 32 + 2 {
                    return Err(FileFormatError::TruncatedChunk {
                        expected: 16 + 16 + 32 + 2,
                        got: data.len(),
                    });
                }
                let mut user_id = [0u8; 16];
                user_id.copy_from_slice(&data[0..16]);

                let mut device_id = [0u8; 16];
                device_id.copy_from_slice(&data[16..32]);

                let mut device_pubkey = [0u8; 32];
                device_pubkey.copy_from_slice(&data[32..64]);

                let mut label_len_bytes = [0u8; 2];
                label_len_bytes.copy_from_slice(&data[64..66]);
                let label_len = u16::from_be_bytes(label_len_bytes) as usize;

                if label_len > 256 {
                    return Err(FileFormatError::LabelTooLong);
                }

                if data.len() < 66 + label_len {
                    return Err(FileFormatError::TruncatedChunk {
                        expected: 66 + label_len,
                        got: data.len(),
                    });
                }

                let label_str = std::str::from_utf8(&data[66..66 + label_len])
                    .map_err(|_| FileFormatError::InvalidWrapPayload)?
                    .to_string();

                Ok(KeyLogEntryType::DeviceRegister {
                    user_id,
                    device_id,
                    device_pubkey,
                    human_label: label_str,
                })
            }
            1 => {
                if data.len() < 16 {
                    return Err(FileFormatError::TruncatedChunk {
                        expected: 16,
                        got: data.len(),
                    });
                }
                let mut device_id = [0u8; 16];
                device_id.copy_from_slice(&data[0..16]);
                Ok(KeyLogEntryType::DeviceRevoke { device_id })
            }
            other => Err(FileFormatError::UnknownOperationType(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogEntry {
    pub entry: KeyLogEntryType,
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl KeyLogEntry {
    pub fn sig_message(&self) -> Vec<u8> {
        let entry_type_byte = match &self.entry {
            KeyLogEntryType::DeviceRegister { .. } => 0u8,
            KeyLogEntryType::DeviceRevoke { .. } => 1u8,
        };
        let entry_data = self.entry.to_bytes();
        let entry_data_len = entry_data.len() as u32;

        let mut out = Vec::with_capacity(1 + 32 + 8 + 4 + entry_data.len());
        out.push(entry_type_byte);
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&entry_data_len.to_be_bytes());
        out.extend_from_slice(&entry_data);
        out
    }

    pub fn write(&self) -> Vec<u8> {
        let mut out = self.sig_message();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn parse(input: &[u8]) -> Result<(Self, usize), FileFormatError> {
        if input.len() < 1 + 32 + 8 + 4 {
            return Err(FileFormatError::TruncatedChunk {
                expected: 1 + 32 + 8 + 4,
                got: input.len(),
            });
        }
        let entry_type_byte = input[0];
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&input[1..33]);

        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&input[33..41]);
        let timestamp = u64::from_be_bytes(timestamp_bytes);

        let mut entry_data_len_bytes = [0u8; 4];
        entry_data_len_bytes.copy_from_slice(&input[41..45]);
        let entry_data_len = u32::from_be_bytes(entry_data_len_bytes) as usize;

        let expected_len = 45 + entry_data_len + 64;
        if input.len() < expected_len {
            return Err(FileFormatError::TruncatedChunk {
                expected: expected_len,
                got: input.len(),
            });
        }

        let entry_data_bytes = &input[45..45 + entry_data_len];
        let entry = KeyLogEntryType::parse(entry_type_byte, entry_data_bytes)?;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&input[45 + entry_data_len..expected_len]);

        Ok((
            KeyLogEntry {
                entry,
                prev_hash,
                timestamp,
                signature,
            },
            expected_len,
        ))
    }
}

pub fn hash_of_entry(entry: &KeyLogEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(entry.write());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLog {
    pub authority_pubkey: [u8; 32],
    pub entries: Vec<KeyLogEntry>,
}

impl KeyLog {
    pub fn new(authority_pubkey: [u8; 32]) -> Self {
        KeyLog {
            authority_pubkey,
            entries: Vec::new(),
        }
    }

    fn last_entry_hash(&self) -> [u8; 32] {
        match self.entries.last() {
            Some(entry) => hash_of_entry(entry),
            None => [0u8; 32],
        }
    }

    pub fn register_device(
        &mut self,
        user_id: [u8; 16],
        device_id: [u8; 16],
        device_pubkey: [u8; 32],
        human_label: &str,
        authority_sk: &[u8; 32],
        timestamp: u64,
    ) -> Result<[u8; 32], FileFormatError> {
        if human_label.len() > 256 {
            return Err(FileFormatError::LabelTooLong);
        }
        let entry_type = KeyLogEntryType::DeviceRegister {
            user_id,
            device_id,
            device_pubkey,
            human_label: human_label.to_string(),
        };
        let prev_hash = self.last_entry_hash();
        let mut temp_entry = KeyLogEntry {
            entry: entry_type,
            prev_hash,
            timestamp,
            signature: [0u8; 64],
        };
        let msg = temp_entry.sig_message();
        let signature = ed25519_sign(authority_sk, &msg);
        temp_entry.signature = signature;

        let entry_hash = hash_of_entry(&temp_entry);
        self.entries.push(temp_entry);
        Ok(entry_hash)
    }

    pub fn revoke_device(
        &mut self,
        device_id: [u8; 16],
        authority_sk: &[u8; 32],
        timestamp: u64,
    ) -> Result<(), FileFormatError> {
        let mut found = false;
        let mut revoked = false;

        for entry in &self.entries {
            match &entry.entry {
                KeyLogEntryType::DeviceRegister {
                    device_id: registered_id,
                    ..
                } => {
                    if *registered_id == device_id {
                        found = true;
                    }
                }
                KeyLogEntryType::DeviceRevoke {
                    device_id: revoked_id,
                    ..
                } => {
                    if *revoked_id == device_id {
                        revoked = true;
                    }
                }
            }
        }

        if !found {
            return Err(FileFormatError::DeviceNotFound);
        }
        if revoked {
            return Err(FileFormatError::DeviceAlreadyRevoked);
        }

        let entry_type = KeyLogEntryType::DeviceRevoke { device_id };
        let prev_hash = self.last_entry_hash();
        let mut temp_entry = KeyLogEntry {
            entry: entry_type,
            prev_hash,
            timestamp,
            signature: [0u8; 64],
        };
        let msg = temp_entry.sig_message();
        let signature = ed25519_sign(authority_sk, &msg);
        temp_entry.signature = signature;

        self.entries.push(temp_entry);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), FileFormatError> {
        let mut prev_hash = [0u8; 32];
        for entry in &self.entries {
            if !bool::from(entry.prev_hash.ct_eq(&prev_hash)) {
                return Err(FileFormatError::InvalidKeyLogChain);
            }

            let msg = entry.sig_message();
            ed25519_verify(&self.authority_pubkey, &msg, &entry.signature)?;

            prev_hash = hash_of_entry(entry);
        }
        Ok(())
    }

    pub fn lookup_by_entry_hash(&self, entry_hash: &[u8; 32]) -> Option<&KeyLogEntry> {
        self.entries
            .iter()
            .find(|entry| bool::from(hash_of_entry(entry).ct_eq(entry_hash)))
    }

    pub fn device_was_active_at(&self, device_id: &[u8; 16], at_timestamp: u64) -> bool {
        let mut register_timestamp = None;
        let mut revoke_timestamp = None;

        for entry in &self.entries {
            match &entry.entry {
                KeyLogEntryType::DeviceRegister {
                    device_id: registered_id,
                    ..
                } => {
                    if registered_id == device_id && entry.timestamp <= at_timestamp {
                        register_timestamp = Some(entry.timestamp);
                    }
                }
                KeyLogEntryType::DeviceRevoke {
                    device_id: revoked_id,
                    ..
                } => {
                    if revoked_id == device_id && entry.timestamp <= at_timestamp {
                        revoke_timestamp = Some(entry.timestamp);
                    }
                }
            }
        }

        match register_timestamp {
            Some(reg_ts) => match revoke_timestamp {
                Some(rev_ts) => rev_ts < reg_ts,
                None => true,
            },
            None => false,
        }
    }

    pub fn user_for_device(&self, device_id: &[u8; 16]) -> Option<[u8; 16]> {
        let mut user_id = None;
        for entry in &self.entries {
            if let KeyLogEntryType::DeviceRegister {
                device_id: registered_id,
                user_id: uid,
                ..
            } = &entry.entry
            {
                if registered_id == device_id {
                    user_id = Some(*uid);
                }
            }
        }
        user_id
    }

    pub fn write(&self) -> Vec<u8> {
        let mut entries_bytes = Vec::new();
        for entry in &self.entries {
            entries_bytes.extend_from_slice(&entry.write());
        }

        let mut out = Vec::with_capacity(8 + 1 + 3 + 32 + 4 + entries_bytes.len());
        out.extend_from_slice(b"VOLLKEYL");
        out.push(1); // Version
        out.extend_from_slice(&[0u8; 3]); // Reserved
        out.extend_from_slice(&self.authority_pubkey);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&entries_bytes);
        out
    }

    pub fn parse(input: &[u8]) -> Result<KeyLog, FileFormatError> {
        if input.len() < 8 + 1 + 3 + 32 + 4 {
            return Err(FileFormatError::TruncatedChunk {
                expected: 48,
                got: input.len(),
            });
        }

        if &input[0..8] != b"VOLLKEYL" {
            return Err(FileFormatError::InvalidKeyLogMagic);
        }

        let version = input[8];
        if version != 1 {
            return Err(FileFormatError::UnsupportedKeyLogVersion(version));
        }

        let mut authority_pubkey = [0u8; 32];
        authority_pubkey.copy_from_slice(&input[12..44]);

        let mut entry_count_bytes = [0u8; 4];
        entry_count_bytes.copy_from_slice(&input[44..48]);
        let entry_count = u32::from_be_bytes(entry_count_bytes) as usize;

        let mut entries = Vec::with_capacity(entry_count);
        let mut offset = 48;

        for _ in 0..entry_count {
            if offset >= input.len() {
                return Err(FileFormatError::TruncatedChunk {
                    expected: offset + 1,
                    got: input.len(),
                });
            }
            let (entry, read_bytes) = KeyLogEntry::parse(&input[offset..])?;
            entries.push(entry);
            offset += read_bytes;
        }

        Ok(KeyLog {
            authority_pubkey,
            entries,
        })
    }
}
