use crate::error::FileFormatError;
use crate::recipient::RecipientPublicKey;
use crate::wrap::WrapEntry;

/// Represents a group manifest operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Genesis {
        founder_id: [u8; 16],
        founder_signing_pk: [u8; 32],
        founder_x25519_pk: [u8; 32],
        founder_mlkem_pk: Box<[u8; 1184]>,
        founder_gk_wrap: WrapEntry,
    },
    AddMember {
        member_id: [u8; 16],
        member_signing_pk: [u8; 32],
        member_x25519_pk: [u8; 32],
        member_mlkem_pk: Box<[u8; 1184]>,
        gk_wrap: WrapEntry,
    },
    RemoveMember {
        member_id: [u8; 16],
    },
}

impl Operation {
    /// Serializes the operation payload data.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Operation::Genesis {
                founder_id,
                founder_signing_pk,
                founder_x25519_pk,
                founder_mlkem_pk,
                founder_gk_wrap,
            } => {
                let wrap_bytes = founder_gk_wrap.write();
                let mut out = Vec::with_capacity(16 + 32 + 32 + 1184 + wrap_bytes.len());
                out.extend_from_slice(founder_id);
                out.extend_from_slice(founder_signing_pk);
                out.extend_from_slice(founder_x25519_pk);
                out.extend_from_slice(founder_mlkem_pk.as_ref());
                out.extend_from_slice(&wrap_bytes);
                out
            }
            Operation::AddMember {
                member_id,
                member_signing_pk,
                member_x25519_pk,
                member_mlkem_pk,
                gk_wrap,
            } => {
                let wrap_bytes = gk_wrap.write();
                let mut out = Vec::with_capacity(16 + 32 + 32 + 1184 + wrap_bytes.len());
                out.extend_from_slice(member_id);
                out.extend_from_slice(member_signing_pk);
                out.extend_from_slice(member_x25519_pk);
                out.extend_from_slice(member_mlkem_pk.as_ref());
                out.extend_from_slice(&wrap_bytes);
                out
            }
            Operation::RemoveMember { member_id } => member_id.to_vec(),
        }
    }

    /// Parses the operation payload data.
    pub fn parse(op_type: u8, data: &[u8]) -> Result<Self, FileFormatError> {
        match op_type {
            0 => {
                let min_len = 16 + 32 + 32 + 1184;
                if data.len() < min_len {
                    return Err(FileFormatError::InvalidWrapPayload);
                }
                let mut founder_id = [0u8; 16];
                founder_id.copy_from_slice(&data[0..16]);

                let mut founder_signing_pk = [0u8; 32];
                founder_signing_pk.copy_from_slice(&data[16..48]);

                let mut founder_x25519_pk = [0u8; 32];
                founder_x25519_pk.copy_from_slice(&data[48..80]);

                let mut founder_mlkem_pk = Box::new([0u8; 1184]);
                founder_mlkem_pk.copy_from_slice(&data[80..1264]);

                let (founder_gk_wrap, _) = WrapEntry::parse(&data[1264..])?;

                Ok(Operation::Genesis {
                    founder_id,
                    founder_signing_pk,
                    founder_x25519_pk,
                    founder_mlkem_pk,
                    founder_gk_wrap,
                })
            }
            1 => {
                let min_len = 16 + 32 + 32 + 1184;
                if data.len() < min_len {
                    return Err(FileFormatError::InvalidWrapPayload);
                }
                let mut member_id = [0u8; 16];
                member_id.copy_from_slice(&data[0..16]);

                let mut member_signing_pk = [0u8; 32];
                member_signing_pk.copy_from_slice(&data[16..48]);

                let mut member_x25519_pk = [0u8; 32];
                member_x25519_pk.copy_from_slice(&data[48..80]);

                let mut member_mlkem_pk = Box::new([0u8; 1184]);
                member_mlkem_pk.copy_from_slice(&data[80..1264]);

                let (gk_wrap, _) = WrapEntry::parse(&data[1264..])?;

                Ok(Operation::AddMember {
                    member_id,
                    member_signing_pk,
                    member_x25519_pk,
                    member_mlkem_pk,
                    gk_wrap,
                })
            }
            2 => {
                if data.len() != 16 {
                    return Err(FileFormatError::InvalidWrapPayload);
                }
                let mut member_id = [0u8; 16];
                member_id.copy_from_slice(&data[0..16]);

                Ok(Operation::RemoveMember { member_id })
            }
            t => Err(FileFormatError::UnknownOperationType(t)),
        }
    }
}

/// Represents a signed operation entry in the manifest log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOperation {
    pub op_type: u8,
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
    pub signer_pubkey: [u8; 32],
    pub data_len: u32,
    pub data: Vec<u8>,
    pub signature: [u8; 64],
}

impl SignedOperation {
    /// Serializes the operation fields, excluding the signature, for signing or verification.
    pub fn sig_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 32 + 8 + 32 + 4 + self.data.len());
        msg.push(self.op_type);
        msg.extend_from_slice(&self.prev_hash);
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        msg.extend_from_slice(&self.signer_pubkey);
        msg.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        msg.extend_from_slice(&self.data);
        msg
    }

    /// Serializes the complete signed operation, including the signature.
    pub fn write(&self) -> Vec<u8> {
        let mut out = self.sig_message();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Computes the SHA-256 hash of the complete signed operation.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let bytes = self.write();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    }

    /// Parses a signed operation from a byte buffer.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), FileFormatError> {
        if input.len() < 1 + 32 + 8 + 32 + 4 {
            return Err(FileFormatError::TruncatedChunk {
                expected: 1 + 32 + 8 + 32 + 4,
                got: input.len(),
            });
        }

        let op_type = input[0];
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&input[1..33]);

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&input[33..41]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut signer_pubkey = [0u8; 32];
        signer_pubkey.copy_from_slice(&input[41..73]);

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&input[73..77]);
        let data_len = u32::from_be_bytes(len_bytes) as usize;

        let header_and_data_len = 77 + data_len;
        if input.len() < header_and_data_len + 64 {
            return Err(FileFormatError::TruncatedChunk {
                expected: header_and_data_len + 64,
                got: input.len(),
            });
        }

        let data = input[77..header_and_data_len].to_vec();

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&input[header_and_data_len..header_and_data_len + 64]);

        Ok((
            SignedOperation {
                op_type,
                prev_hash,
                timestamp,
                signer_pubkey,
                data_len: data_len as u32,
                data,
                signature,
            },
            header_and_data_len + 64,
        ))
    }
}

/// Represents the cryptographic manifest log of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupManifest {
    pub group_id: [u8; 16],
    pub operations: Vec<SignedOperation>,
}

impl GroupManifest {
    /// Generates a new GroupManifest with a Genesis block.
    pub fn genesis(
        group_id: [u8; 16],
        founder_id: [u8; 16],
        founder_signing_sk: &[u8; 32],
        founder_signing_pk: [u8; 32],
        founder_recipient_pk: RecipientPublicKey,
        founder_gk_wrap: WrapEntry,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let op = Operation::Genesis {
            founder_id,
            founder_signing_pk,
            founder_x25519_pk: founder_recipient_pk.x25519,
            founder_mlkem_pk: founder_recipient_pk.ml_kem,
            founder_gk_wrap,
        };

        let data = op.to_bytes();
        let mut signed_op = SignedOperation {
            op_type: 0,
            prev_hash: [0u8; 32],
            timestamp,
            signer_pubkey: founder_signing_pk,
            data_len: data.len() as u32,
            data,
            signature: [0u8; 64],
        };

        let msg = signed_op.sig_message();
        signed_op.signature = crate::signing::ed25519_sign(founder_signing_sk, &msg);

        GroupManifest {
            group_id,
            operations: vec![signed_op],
        }
    }

    /// Adds a new member to the group, signed by the admin.
    pub fn add_member(
        &mut self,
        admin_sk: &[u8; 32],
        member_id: [u8; 16],
        member_signing_pk: [u8; 32],
        member_recipient_pk: RecipientPublicKey,
        gk_wrap: WrapEntry,
    ) -> Result<(), FileFormatError> {
        let admin_pk = ed25519_dalek::SigningKey::from_bytes(admin_sk)
            .verifying_key()
            .to_bytes();

        let founder_pk = self.founder_signing_pk()?;
        if admin_pk != founder_pk {
            return Err(FileFormatError::NotAuthorized);
        }

        let prev_op = self
            .operations
            .last()
            .ok_or(FileFormatError::EmptyManifest)?;
        let prev_hash = prev_op.hash();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let op = Operation::AddMember {
            member_id,
            member_signing_pk,
            member_x25519_pk: member_recipient_pk.x25519,
            member_mlkem_pk: member_recipient_pk.ml_kem,
            gk_wrap,
        };

        let data = op.to_bytes();
        let mut signed_op = SignedOperation {
            op_type: 1,
            prev_hash,
            timestamp,
            signer_pubkey: admin_pk,
            data_len: data.len() as u32,
            data,
            signature: [0u8; 64],
        };

        let msg = signed_op.sig_message();
        signed_op.signature = crate::signing::ed25519_sign(admin_sk, &msg);

        self.operations.push(signed_op);
        Ok(())
    }

    /// Removes a member from the group, signed by the admin.
    pub fn remove_member(
        &mut self,
        admin_sk: &[u8; 32],
        member_id: [u8; 16],
    ) -> Result<(), FileFormatError> {
        let admin_pk = ed25519_dalek::SigningKey::from_bytes(admin_sk)
            .verifying_key()
            .to_bytes();

        let founder_pk = self.founder_signing_pk()?;
        if admin_pk != founder_pk {
            return Err(FileFormatError::NotAuthorized);
        }

        let active = self.current_members();
        if !active.contains(&member_id) {
            return Err(FileFormatError::MemberNotFound);
        }

        let prev_op = self
            .operations
            .last()
            .ok_or(FileFormatError::EmptyManifest)?;
        let prev_hash = prev_op.hash();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let op = Operation::RemoveMember { member_id };
        let data = op.to_bytes();
        let mut signed_op = SignedOperation {
            op_type: 2,
            prev_hash,
            timestamp,
            signer_pubkey: admin_pk,
            data_len: data.len() as u32,
            data,
            signature: [0u8; 64],
        };

        let msg = signed_op.sig_message();
        signed_op.signature = crate::signing::ed25519_sign(admin_sk, &msg);

        self.operations.push(signed_op);
        Ok(())
    }

    /// Helper to retrieve the founder's signing public key from the Genesis operation.
    pub fn founder_signing_pk(&self) -> Result<[u8; 32], FileFormatError> {
        let genesis_op = self
            .operations
            .first()
            .ok_or(FileFormatError::EmptyManifest)?;
        if genesis_op.op_type != 0 {
            return Err(FileFormatError::InvalidManifestChain);
        }
        let op = Operation::parse(genesis_op.op_type, &genesis_op.data)?;
        if let Operation::Genesis {
            founder_signing_pk, ..
        } = op
        {
            Ok(founder_signing_pk)
        } else {
            Err(FileFormatError::InvalidManifestChain)
        }
    }

    /// Evaluates the operation log and returns a list of current active member IDs.
    pub fn current_members(&self) -> Vec<[u8; 16]> {
        let mut members = Vec::new();
        for op_signed in &self.operations {
            if let Ok(op) = Operation::parse(op_signed.op_type, &op_signed.data) {
                match op {
                    Operation::Genesis { founder_id, .. } => {
                        if !members.contains(&founder_id) {
                            members.push(founder_id);
                        }
                    }
                    Operation::AddMember { member_id, .. } => {
                        if !members.contains(&member_id) {
                            members.push(member_id);
                        }
                    }
                    Operation::RemoveMember { member_id } => {
                        members.retain(|&m| m != member_id);
                    }
                }
            }
        }
        members
    }

    /// Scans the log in reverse to find a member's key wrap entry, returning an error if they are not active.
    pub fn find_member_wrap(&self, member_id: &[u8; 16]) -> Result<WrapEntry, FileFormatError> {
        let active = self.current_members();
        if !active.contains(member_id) {
            return Err(FileFormatError::MemberNotFound);
        }

        for op_signed in self.operations.iter().rev() {
            if let Ok(op) = Operation::parse(op_signed.op_type, &op_signed.data) {
                match op {
                    Operation::Genesis {
                        founder_id,
                        founder_gk_wrap,
                        ..
                    } => {
                        if founder_id == *member_id {
                            return Ok(founder_gk_wrap);
                        }
                    }
                    Operation::AddMember {
                        member_id: mid,
                        gk_wrap,
                        ..
                    } => {
                        if mid == *member_id {
                            return Ok(gk_wrap);
                        }
                    }
                    _ => {}
                }
            }
        }

        Err(FileFormatError::MemberNotFound)
    }

    /// Retrieves the highest GK version across all active members.
    pub fn current_gk_version(&self) -> u32 {
        let mut current_version = 0;
        for op_signed in &self.operations {
            if let Ok(op) = Operation::parse(op_signed.op_type, &op_signed.data) {
                match op {
                    Operation::Genesis {
                        founder_gk_wrap, ..
                    } => {
                        let ver = match founder_gk_wrap {
                            WrapEntry::HybridKem { gk_version, .. } => gk_version,
                            WrapEntry::GroupWrap { gk_version, .. } => gk_version,
                            _ => 0,
                        };
                        if ver > current_version {
                            current_version = ver;
                        }
                    }
                    Operation::AddMember { gk_wrap, .. } => {
                        let ver = match gk_wrap {
                            WrapEntry::HybridKem { gk_version, .. } => gk_version,
                            WrapEntry::GroupWrap { gk_version, .. } => gk_version,
                            _ => 0,
                        };
                        if ver > current_version {
                            current_version = ver;
                        }
                    }
                    _ => {}
                }
            }
        }
        current_version
    }

    /// Verifies the signature integrity and hash chain links of the manifest.
    pub fn verify(&self) -> Result<(), FileFormatError> {
        if self.operations.is_empty() {
            return Err(FileFormatError::EmptyManifest);
        }

        let founder_pk = self.founder_signing_pk()?;
        let mut expected_prev_hash = [0u8; 32];

        for op_signed in &self.operations {
            // 1. Verify hash chain link
            if op_signed.prev_hash != expected_prev_hash {
                return Err(FileFormatError::InvalidManifestChain);
            }

            // 2. Verify signer is the founder / admin
            if op_signed.signer_pubkey != founder_pk {
                return Err(FileFormatError::NotAuthorized);
            }

            // 3. Verify signature
            let msg = op_signed.sig_message();
            crate::signing::ed25519_verify(&op_signed.signer_pubkey, &msg, &op_signed.signature)?;

            // 4. Update expected_prev_hash for the next iteration
            expected_prev_hash = op_signed.hash();
        }

        Ok(())
    }

    /// Serializes the entire GroupManifest into a byte representation.
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"VOLLGMAN");
        out.push(1); // version
        out.extend_from_slice(&[0, 0, 0]); // reserved
        out.extend_from_slice(&self.group_id);
        let op_count = self.operations.len() as u32;
        out.extend_from_slice(&op_count.to_be_bytes());

        for op in &self.operations {
            out.extend_from_slice(&op.write());
        }

        out
    }

    /// Parses a GroupManifest from a byte buffer.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), FileFormatError> {
        if input.len() < 32 {
            return Err(FileFormatError::TruncatedHeader {
                expected: 32,
                got: input.len(),
            });
        }

        if &input[0..8] != b"VOLLGMAN" {
            return Err(FileFormatError::InvalidManifestMagic);
        }

        let version = input[8];
        if version != 1 {
            return Err(FileFormatError::UnsupportedManifestVersion(version));
        }

        let mut group_id = [0u8; 16];
        group_id.copy_from_slice(&input[12..28]);

        let mut op_count_bytes = [0u8; 4];
        op_count_bytes.copy_from_slice(&input[28..32]);
        let op_count = u32::from_be_bytes(op_count_bytes) as usize;

        let mut offset = 32;
        let mut operations = Vec::with_capacity(op_count);

        for _ in 0..op_count {
            let (op, read_bytes) = SignedOperation::parse(&input[offset..])?;
            operations.push(op);
            offset += read_bytes;
        }

        let manifest = GroupManifest {
            group_id,
            operations,
        };

        Ok((manifest, offset))
    }
}
