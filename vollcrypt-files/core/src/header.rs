use crate::constants::{FIXED_HEADER_LEN, MAGIC};
use crate::error::FileFormatError;
use crate::merkle::HashAlgorithm;
use crate::wrap::WrapEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Password = 0,
    Recipient = 1,
    Group = 2,
}

impl TryFrom<u8> for Mode {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Mode::Password),
            1 => Ok(Mode::Recipient),
            2 => Ok(Mode::Group),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherId {
    Aes256Gcm = 0,
}

impl TryFrom<u8> for CipherId {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CipherId::Aes256Gcm),
            other => Err(other),
        }
    }
}

use crate::hybrid_sig::{HybridPublicKey, HybridSignature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedMetadata {
    Plain {
        signer_pubkey: HybridPublicKey,
        timestamp: u64,
        key_log_id: [u8; 32],
    },
    Sealed {
        sealed_group_id: [u8; 16],
        sealed_gk_version: u32,
        iv: [u8; 12],
        sealed_payload: Vec<u8>,
        sealed_tag: [u8; 16],
        timestamp: u64,
    },
    SovereignSealed {
        signer_pubkey: HybridPublicKey,
        mode: u8,
        reason: String,
        timestamp: u64,
    },
}

impl SignedMetadata {
    pub fn parse(input: &[u8], version: u8) -> Result<Self, FileFormatError> {
        if input.len() < 9 {
            return Err(FileFormatError::TruncatedHeader {
                expected: 9,
                got: input.len(),
            });
        }
        let signer_kind = input[0];
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&input[1..9]);
        let timestamp = u64::from_be_bytes(timestamp_bytes);

        match signer_kind {
            0 => {
                if version == 3 {
                    let expected = 1 + 8 + 1984 + 32; // 2025
                    if input.len() < expected {
                        return Err(FileFormatError::TruncatedHeader {
                            expected,
                            got: input.len(),
                        });
                    }
                    let signer_pubkey = HybridPublicKey::parse(&input[9..1993])?;
                    let mut key_log_id = [0u8; 32];
                    key_log_id.copy_from_slice(&input[1993..2025]);
                    Ok(SignedMetadata::Plain {
                        signer_pubkey,
                        timestamp,
                        key_log_id,
                    })
                } else {
                    if input.len() < 73 {
                        return Err(FileFormatError::TruncatedHeader {
                            expected: 73,
                            got: input.len(),
                        });
                    }
                    let mut ed25519 = [0u8; 32];
                    ed25519.copy_from_slice(&input[9..41]);
                    let mldsa = [0u8; 1952];
                    let signer_pubkey = HybridPublicKey { ed25519, mldsa };
                    let mut key_log_id = [0u8; 32];
                    key_log_id.copy_from_slice(&input[41..73]);
                    Ok(SignedMetadata::Plain {
                        signer_pubkey,
                        timestamp,
                        key_log_id,
                    })
                }
            }
            1 => {
                if input.len() < 61 {
                    return Err(FileFormatError::TruncatedHeader {
                        expected: 61,
                        got: input.len(),
                    });
                }
                let mut sealed_group_id = [0u8; 16];
                sealed_group_id.copy_from_slice(&input[9..25]);

                let mut sealed_gk_version_bytes = [0u8; 4];
                sealed_gk_version_bytes.copy_from_slice(&input[25..29]);
                let sealed_gk_version = u32::from_be_bytes(sealed_gk_version_bytes);

                let mut iv = [0u8; 12];
                iv.copy_from_slice(&input[29..41]);

                let mut sealed_payload_len_bytes = [0u8; 4];
                sealed_payload_len_bytes.copy_from_slice(&input[41..45]);
                let sealed_payload_len = u32::from_be_bytes(sealed_payload_len_bytes) as usize;

                let expected_len = 61 + sealed_payload_len;
                if input.len() < expected_len {
                    return Err(FileFormatError::TruncatedHeader {
                        expected: expected_len,
                        got: input.len(),
                    });
                }

                let mut sealed_payload = vec![0u8; sealed_payload_len];
                sealed_payload.copy_from_slice(&input[45..45 + sealed_payload_len]);

                let mut sealed_tag = [0u8; 16];
                sealed_tag.copy_from_slice(&input[45 + sealed_payload_len..expected_len]);

                Ok(SignedMetadata::Sealed {
                    sealed_group_id,
                    sealed_gk_version,
                    iv,
                    sealed_payload,
                    sealed_tag,
                    timestamp,
                })
            }
            2 => {
                let pk_len = if version == 3 { 1984 } else { 32 };
                let min_expected = 1 + 8 + pk_len + 1 + 4;
                if input.len() < min_expected {
                    return Err(FileFormatError::TruncatedHeader {
                        expected: min_expected,
                        got: input.len(),
                    });
                }
                let signer_pubkey = if version == 3 {
                    HybridPublicKey::parse(&input[9..9 + 1984])?
                } else {
                    let mut ed25519 = [0u8; 32];
                    ed25519.copy_from_slice(&input[9..41]);
                    HybridPublicKey {
                        ed25519,
                        mldsa: [0u8; 1952],
                    }
                };
                let mode_offset = 9 + pk_len;
                let mode = input[mode_offset];
                let mut reason_len_bytes = [0u8; 4];
                reason_len_bytes.copy_from_slice(&input[mode_offset + 1..mode_offset + 5]);
                let reason_len = u32::from_be_bytes(reason_len_bytes) as usize;
                let expected_total = mode_offset + 5 + reason_len;
                if input.len() < expected_total {
                    return Err(FileFormatError::TruncatedHeader {
                        expected: expected_total,
                        got: input.len(),
                    });
                }
                let reason = String::from_utf8(input[mode_offset + 5..expected_total].to_vec())
                    .map_err(|_| FileFormatError::InvalidSealedPayload)?;

                Ok(SignedMetadata::SovereignSealed {
                    signer_pubkey,
                    mode,
                    reason,
                    timestamp,
                })
            }
            _ => Err(FileFormatError::InvalidWrapPayload),
        }
    }

    pub fn write(&self, version: u8) -> Vec<u8> {
        match self {
            SignedMetadata::Plain {
                signer_pubkey,
                timestamp,
                key_log_id,
            } => {
                if version == 3 {
                    let mut out = Vec::with_capacity(1 + 8 + 1984 + 32);
                    out.push(0); // signer_kind
                    out.extend_from_slice(&timestamp.to_be_bytes());
                    out.extend_from_slice(&signer_pubkey.write());
                    out.extend_from_slice(key_log_id);
                    out
                } else {
                    let mut out = Vec::with_capacity(73);
                    out.push(0); // signer_kind
                    out.extend_from_slice(&timestamp.to_be_bytes());
                    out.extend_from_slice(&signer_pubkey.ed25519);
                    out.extend_from_slice(key_log_id);
                    out
                }
            }
            SignedMetadata::Sealed {
                sealed_group_id,
                sealed_gk_version,
                iv,
                sealed_payload,
                sealed_tag,
                timestamp,
            } => {
                let mut out = Vec::with_capacity(61 + sealed_payload.len());
                out.push(1); // signer_kind
                out.extend_from_slice(&timestamp.to_be_bytes());
                out.extend_from_slice(sealed_group_id);
                out.extend_from_slice(&sealed_gk_version.to_be_bytes());
                out.extend_from_slice(iv);
                out.extend_from_slice(&(sealed_payload.len() as u32).to_be_bytes());
                out.extend_from_slice(sealed_payload);
                out.extend_from_slice(sealed_tag);
                out
            }
            SignedMetadata::SovereignSealed {
                signer_pubkey,
                mode,
                reason,
                timestamp,
            } => {
                let pk_bytes = if version == 3 {
                    signer_pubkey.write()
                } else {
                    signer_pubkey.ed25519.to_vec()
                };
                let reason_bytes = reason.as_bytes();
                let mut out = Vec::with_capacity(1 + 8 + pk_bytes.len() + 1 + 4 + reason_bytes.len());
                out.push(2); // signer_kind
                out.extend_from_slice(&timestamp.to_be_bytes());
                out.extend_from_slice(&pk_bytes);
                out.push(*mode);
                out.extend_from_slice(&(reason_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(reason_bytes);
                out
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub mode: Mode,
    pub cipher_id: CipherId,
    pub file_id: [u8; 16],
    pub chunk_size: u32,
    pub plaintext_size: u64,
    pub merkle_root: [u8; 32],
    pub hash_algorithm: HashAlgorithm,
    pub wraps: Vec<WrapEntry>,
    pub signed_metadata: Option<SignedMetadata>,
    pub signature: Option<HybridSignature>,
}

impl Header {
    pub fn parse(input: &[u8]) -> Result<(Self, usize), FileFormatError> {
        if input.len() < FIXED_HEADER_LEN {
            return Err(FileFormatError::TruncatedHeader {
                expected: FIXED_HEADER_LEN,
                got: input.len(),
            });
        }

        // 1. Verify Magic
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&input[0..8]);
        if magic != MAGIC {
            return Err(FileFormatError::InvalidMagic);
        }

        // 2. Verify Version
        let version = input[8];
        if version != 1 && version != 2 && version != 3 {
            return Err(FileFormatError::UnsupportedVersion(version));
        }

        // 3. Parse Mode
        let mode_u8 = input[9];
        let mode = Mode::try_from(mode_u8).map_err(|_| FileFormatError::InvalidMode(mode_u8))?;

        // 4. Parse Cipher ID
        let cipher_u8 = input[10];
        let cipher_id = CipherId::try_from(cipher_u8)
            .map_err(|_| FileFormatError::InvalidCipherId(cipher_u8))?;

        // 5. Parse File ID
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&input[11..27]);

        // 6. Parse Chunk Size
        let mut chunk_size_bytes = [0u8; 4];
        chunk_size_bytes.copy_from_slice(&input[27..31]);
        let chunk_size = u32::from_be_bytes(chunk_size_bytes);
        if chunk_size == 0 {
            return Err(FileFormatError::KdfParameterOutOfRange(
                "Chunk size cannot be zero".to_string(),
            ));
        }
        if chunk_size > 16_777_216 {
            return Err(FileFormatError::KdfParameterOutOfRange(format!(
                "Chunk size exceeds 16MB limit: {}",
                chunk_size
            )));
        }

        // 7. Parse Plaintext Size
        let mut plaintext_size_bytes = [0u8; 8];
        plaintext_size_bytes.copy_from_slice(&input[31..39]);
        let plaintext_size = u64::from_be_bytes(plaintext_size_bytes);

        // 8. Parse Merkle Root
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&input[39..71]);

        // 9. Parse Wrap Count
        let wrap_count = input[71];

        // Parse Hash Algorithm from the first reserved byte (index 72)
        let hash_algo_u8 = input[72];
        let hash_algorithm = match hash_algo_u8 {
            0 => HashAlgorithm::Sha256,
            1 => HashAlgorithm::Blake3,
            other => return Err(FileFormatError::UnsupportedHashAlgorithm(other)),
        };

        // 10. Parse Variable Length
        let mut variable_len_bytes = [0u8; 4];
        variable_len_bytes.copy_from_slice(&input[76..80]);
        let variable_len = u32::from_be_bytes(variable_len_bytes) as usize;

        let total_header_len = FIXED_HEADER_LEN + variable_len;
        if input.len() < total_header_len {
            return Err(FileFormatError::TruncatedHeader {
                expected: total_header_len,
                got: input.len(),
            });
        }

        // 11. Parse Wrap Entries
        let mut wraps = Vec::with_capacity(wrap_count as usize);
        let mut current_offset = FIXED_HEADER_LEN;
        let end_offset = FIXED_HEADER_LEN + variable_len;

        for _ in 0..wrap_count {
            if current_offset >= end_offset {
                return Err(FileFormatError::TruncatedHeader {
                    expected: end_offset,
                    got: current_offset,
                });
            }
            let (wrap, size) = WrapEntry::parse(&input[current_offset..end_offset])?;
            wraps.push(wrap);
            current_offset += size;
        }

        if current_offset != end_offset {
            return Err(FileFormatError::TruncatedHeader {
                expected: end_offset,
                got: current_offset,
            });
        }

        let mut signed_metadata = None;
        let mut signature = None;
        let mut final_header_len = total_header_len;

        if version == 2 || version == 3 {
            if input.len() < total_header_len + 4 {
                return Err(FileFormatError::TruncatedHeader {
                    expected: total_header_len + 4,
                    got: input.len(),
                });
            }
            let mut metadata_len_bytes = [0u8; 4];
            metadata_len_bytes.copy_from_slice(&input[total_header_len..total_header_len + 4]);
            let metadata_len = u32::from_be_bytes(metadata_len_bytes) as usize;

            let expected_metadata_len = total_header_len + 4 + metadata_len;
            if input.len() < expected_metadata_len {
                return Err(FileFormatError::TruncatedHeader {
                    expected: expected_metadata_len,
                    got: input.len(),
                });
            }

            let metadata_start = total_header_len + 4;
            let metadata_end = metadata_start + metadata_len;
            let parsed_metadata = SignedMetadata::parse(&input[metadata_start..metadata_end], version)?;
            signed_metadata = Some(parsed_metadata);

            let signature_start = metadata_end;
            if version == 3 {
                let sig = HybridSignature::parse(&input[signature_start..])?;
                let sig_len = sig.write().len();
                let expected_total_len = signature_start + sig_len;
                if input.len() < expected_total_len {
                    return Err(FileFormatError::TruncatedHeader {
                        expected: expected_total_len,
                        got: input.len(),
                    });
                }
                signature = Some(sig);
                final_header_len = expected_total_len;
            } else {
                let expected_total_len = signature_start + 64;
                if input.len() < expected_total_len {
                    return Err(FileFormatError::TruncatedHeader {
                        expected: expected_total_len,
                        got: input.len(),
                    });
                }
                let mut ed_sig = [0u8; 64];
                ed_sig.copy_from_slice(&input[signature_start..expected_total_len]);
                let sig = HybridSignature {
                    ed25519: ed_sig,
                    mldsa: Vec::new(),
                };
                signature = Some(sig);
                final_header_len = expected_total_len;
            }
        }

        let header = Header {
            version,
            mode,
            cipher_id,
            file_id,
            chunk_size,
            plaintext_size,
            merkle_root,
            hash_algorithm,
            wraps,
            signed_metadata,
            signature,
        };

        Ok((header, final_header_len))
    }

    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut wraps_bytes = Vec::new();
        for wrap in &self.wraps {
            wraps_bytes.extend_from_slice(&wrap.write());
        }

        let variable_len = wraps_bytes.len() as u32;
        let wrap_count = self.wraps.len() as u8;

        let version = if self.signed_metadata.is_some() { self.version } else { 1 };

        let mut out = Vec::with_capacity(FIXED_HEADER_LEN + wraps_bytes.len());
        out.extend_from_slice(&MAGIC);
        out.push(version);
        out.push(self.mode as u8);
        out.push(self.cipher_id as u8);
        out.extend_from_slice(&self.file_id);
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.plaintext_size.to_be_bytes());
        out.extend_from_slice(&self.merkle_root);
        out.push(wrap_count);
        out.push(self.hash_algorithm as u8);
        out.extend_from_slice(&[0u8; 3]); // Remaining 3 reserved bytes
        out.extend_from_slice(&variable_len.to_be_bytes());
        out.extend_from_slice(&wraps_bytes);

        if let Some(ref metadata) = self.signed_metadata {
            let metadata_bytes = metadata.write(version);
            let metadata_len = metadata_bytes.len() as u32;
            out.extend_from_slice(&metadata_len.to_be_bytes());
            out.extend_from_slice(&metadata_bytes);
        }

        out
    }

    pub fn write(&self) -> Vec<u8> {
        let mut out = self.signed_bytes();
        if self.signed_metadata.is_some() {
            match &self.signature {
                Some(sig) => {
                    if self.version == 3 {
                        out.extend_from_slice(&sig.write());
                    } else {
                        out.extend_from_slice(&sig.ed25519);
                    }
                }
                None => {
                    debug_assert!(
                        false,
                        "Signature must be present if signed_metadata is Some"
                    );
                    panic!("Signature must be present if signed_metadata is Some");
                }
            }
        } else if self.signature.is_some() {
            debug_assert!(false, "Signature must be None if signed_metadata is None");
            panic!("Signature must be None if signed_metadata is None");
        }
        out
    }

    pub fn serialized_len(&self) -> usize {
        let wraps_len: usize = self.wraps.iter().map(|w| w.wire_size()).sum();
        if let Some(ref metadata) = self.signed_metadata {
            let metadata_size = metadata.write(self.version).len();
            let sig_size = if self.version == 3 {
                self.signature.as_ref().map(|s| s.write().len()).unwrap_or(0)
            } else {
                64
            };
            FIXED_HEADER_LEN + wraps_len + 4 + metadata_size + sig_size
        } else {
            FIXED_HEADER_LEN + wraps_len
        }
    }

    pub fn canonical_header_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut header_copy = self.clone();
        header_copy.merkle_root = [0u8; 32];
        header_copy.plaintext_size = 0;
        let bytes = header_copy.signed_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}
