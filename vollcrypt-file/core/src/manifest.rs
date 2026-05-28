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
    RotateKey {
        new_gk_version: u32,
        wraps: Vec<([u8; 16], WrapEntry)>,
    },
    ShredGroupKey {
        shredded_gk_version: u32,
        reason: String,
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
            Operation::RotateKey {
                new_gk_version,
                wraps,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&new_gk_version.to_be_bytes());
                let num_wraps = wraps.len() as u16;
                out.extend_from_slice(&num_wraps.to_be_bytes());
                for (mid, wrap) in wraps {
                    out.extend_from_slice(mid);
                    out.extend_from_slice(&wrap.write());
                }
                out
            }
            Operation::ShredGroupKey {
                shredded_gk_version,
                reason,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&shredded_gk_version.to_be_bytes());
                let reason_bytes = reason.as_bytes();
                let reason_len = reason_bytes.len() as u16;
                out.extend_from_slice(&reason_len.to_be_bytes());
                out.extend_from_slice(reason_bytes);
                out
            }
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
            3 => {
                if data.len() < 6 {
                    return Err(FileFormatError::InvalidWrapPayload);
                }
                let mut version_bytes = [0u8; 4];
                version_bytes.copy_from_slice(&data[0..4]);
                let new_gk_version = u32::from_be_bytes(version_bytes);

                let mut num_wraps_bytes = [0u8; 2];
                num_wraps_bytes.copy_from_slice(&data[4..6]);
                let num_wraps = u16::from_be_bytes(num_wraps_bytes) as usize;

                let mut offset = 6;
                let mut wraps = Vec::with_capacity(num_wraps);
                for _ in 0..num_wraps {
                    if data.len() < offset + 16 {
                        return Err(FileFormatError::InvalidWrapPayload);
                    }
                    let mut member_id = [0u8; 16];
                    member_id.copy_from_slice(&data[offset..offset + 16]);
                    offset += 16;

                    let (wrap, read_bytes) = WrapEntry::parse(&data[offset..])?;
                    offset += read_bytes;
                    wraps.push((member_id, wrap));
                }

                Ok(Operation::RotateKey {
                    new_gk_version,
                    wraps,
                })
            }
            4 => {
                if data.len() < 6 {
                    return Err(FileFormatError::InvalidWrapPayload);
                }
                let mut version_bytes = [0u8; 4];
                version_bytes.copy_from_slice(&data[0..4]);
                let shredded_gk_version = u32::from_be_bytes(version_bytes);

                let mut reason_len_bytes = [0u8; 2];
                reason_len_bytes.copy_from_slice(&data[4..6]);
                let reason_len = u16::from_be_bytes(reason_len_bytes) as usize;

                if data.len() < 6 + reason_len {
                    return Err(FileFormatError::InvalidWrapPayload);
                }

                let reason_str = std::str::from_utf8(&data[6..6 + reason_len])
                    .map_err(|_| FileFormatError::InvalidWrapPayload)?
                    .to_string();

                Ok(Operation::ShredGroupKey {
                    shredded_gk_version,
                    reason: reason_str,
                })
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
                    _ => {}
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

    /// Retrieves the current group key version by scanning operations from end to beginning.
    pub fn current_gk_version(&self) -> u32 {
        for op_signed in self.operations.iter().rev() {
            if op_signed.op_type == 3 {
                if let Ok(Operation::RotateKey { new_gk_version, .. }) =
                    Operation::parse(op_signed.op_type, &op_signed.data)
                {
                    return new_gk_version;
                }
            } else if op_signed.op_type == 0 {
                if let Ok(Operation::Genesis {
                    founder_gk_wrap, ..
                }) = Operation::parse(op_signed.op_type, &op_signed.data)
                {
                    match founder_gk_wrap {
                        WrapEntry::HybridKem { gk_version, .. } => return gk_version,
                        WrapEntry::GroupWrap { gk_version, .. } => return gk_version,
                        _ => {}
                    }
                }
            }
        }
        1
    }

    /// Rotates the group key to a new group key, creating a RotateKey operation.
    pub fn rotate_group_key(
        &mut self,
        new_gk: &[u8; 32],
        admin_ed25519_pk: &[u8; 32],
        admin_ed25519_sk: &[u8; 32],
        timestamp: u64,
    ) -> Result<u32, FileFormatError> {
        let admin_pk_derived = ed25519_dalek::SigningKey::from_bytes(admin_ed25519_sk)
            .verifying_key()
            .to_bytes();
        if admin_pk_derived != *admin_ed25519_pk {
            return Err(FileFormatError::NotAuthorized);
        }

        let founder_pk = self.founder_signing_pk()?;
        if *admin_ed25519_pk != founder_pk {
            return Err(FileFormatError::NotAuthorized);
        }

        let new_gk_version = self.current_gk_version() + 1;
        let mut wraps = Vec::new();
        for member_id in self.current_members() {
            let member_pk = self.find_member_pk(&member_id)?;
            let wrap = crate::recipient::wrap_key_to_recipient(
                new_gk,
                member_id,
                new_gk_version,
                &member_pk,
            )?;
            wraps.push((member_id, wrap));
        }

        let op = Operation::RotateKey {
            new_gk_version,
            wraps,
        };
        let data = op.to_bytes();

        let prev_op = self
            .operations
            .last()
            .ok_or(FileFormatError::EmptyManifest)?;
        let prev_hash = prev_op.hash();

        let mut signed_op = SignedOperation {
            op_type: 3,
            prev_hash,
            timestamp,
            signer_pubkey: *admin_ed25519_pk,
            data_len: data.len() as u32,
            data,
            signature: [0u8; 64],
        };

        let msg = signed_op.sig_message();
        signed_op.signature = crate::signing::ed25519_sign(admin_ed25519_sk, &msg);

        self.operations.push(signed_op);
        Ok(new_gk_version)
    }

    /// Shreds a specific group key version, recording it in the manifest operations list.
    pub fn shred_group_key(
        &mut self,
        version_to_shred: u32,
        reason: &str,
        admin_ed25519_pk: &[u8; 32],
        admin_ed25519_sk: &[u8; 32],
        timestamp: u64,
    ) -> Result<(), FileFormatError> {
        if reason.len() > 256 {
            return Err(FileFormatError::InvalidShredReason);
        }

        let admin_pk_derived = ed25519_dalek::SigningKey::from_bytes(admin_ed25519_sk)
            .verifying_key()
            .to_bytes();
        if admin_pk_derived != *admin_ed25519_pk {
            return Err(FileFormatError::NotAuthorized);
        }

        let founder_pk = self.founder_signing_pk()?;
        if *admin_ed25519_pk != founder_pk {
            return Err(FileFormatError::NotAuthorized);
        }

        if self.is_version_shredded(version_to_shred) {
            return Err(FileFormatError::AlreadyShredded);
        }

        let op = Operation::ShredGroupKey {
            shredded_gk_version: version_to_shred,
            reason: reason.to_string(),
        };
        let data = op.to_bytes();

        let prev_op = self
            .operations
            .last()
            .ok_or(FileFormatError::EmptyManifest)?;
        let prev_hash = prev_op.hash();

        let mut signed_op = SignedOperation {
            op_type: 4,
            prev_hash,
            timestamp,
            signer_pubkey: *admin_ed25519_pk,
            data_len: data.len() as u32,
            data,
            signature: [0u8; 64],
        };

        let msg = signed_op.sig_message();
        signed_op.signature = crate::signing::ed25519_sign(admin_ed25519_sk, &msg);

        self.operations.push(signed_op);
        Ok(())
    }

    /// Finds a member's wrap for a specific version, checking RotateKey, Genesis, and AddMember.
    pub fn find_member_wrap_for_version(
        &self,
        member_id: &[u8; 16],
        gk_version: u32,
    ) -> Result<WrapEntry, FileFormatError> {
        if self.is_version_shredded(gk_version) {
            return Err(FileFormatError::GroupKeyShredded(gk_version));
        }

        // First check RotateKey operations
        for op_signed in &self.operations {
            if op_signed.op_type == 3 {
                if let Ok(Operation::RotateKey {
                    new_gk_version,
                    wraps,
                }) = Operation::parse(op_signed.op_type, &op_signed.data)
                {
                    if new_gk_version == gk_version {
                        for (mid, wrap) in wraps {
                            if mid == *member_id {
                                return Ok(wrap);
                            }
                        }
                    }
                }
            }
        }

        // Check Genesis and AddMember operations matching version
        for op_signed in &self.operations {
            if let Ok(op) = Operation::parse(op_signed.op_type, &op_signed.data) {
                match op {
                    Operation::Genesis {
                        founder_id,
                        founder_gk_wrap,
                        ..
                    } => {
                        if founder_id == *member_id {
                            let ver = match &founder_gk_wrap {
                                WrapEntry::HybridKem { gk_version: v, .. } => *v,
                                WrapEntry::GroupWrap { gk_version: v, .. } => *v,
                                _ => 0,
                            };
                            if ver == gk_version {
                                return Ok(founder_gk_wrap);
                            }
                        }
                    }
                    Operation::AddMember {
                        member_id: mid,
                        gk_wrap,
                        ..
                    } => {
                        if mid == *member_id {
                            let ver = match &gk_wrap {
                                WrapEntry::HybridKem { gk_version: v, .. } => *v,
                                WrapEntry::GroupWrap { gk_version: v, .. } => *v,
                                _ => 0,
                            };
                            if ver == gk_version {
                                return Ok(gk_wrap);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Err(FileFormatError::WrapVersionNotFound { gk_version })
    }

    /// Checks if a group key version has been shredded.
    pub fn is_version_shredded(&self, gk_version: u32) -> bool {
        for op_signed in &self.operations {
            if op_signed.op_type == 4 {
                if let Ok(Operation::ShredGroupKey {
                    shredded_gk_version,
                    ..
                }) = Operation::parse(op_signed.op_type, &op_signed.data)
                {
                    if shredded_gk_version == gk_version {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Internal helper to locate the public key of a member.
    fn find_member_pk(&self, member_id: &[u8; 16]) -> Result<RecipientPublicKey, FileFormatError> {
        let mut found_pk = None;
        for op_signed in &self.operations {
            if let Ok(op) = Operation::parse(op_signed.op_type, &op_signed.data) {
                match op {
                    Operation::Genesis {
                        founder_id,
                        founder_x25519_pk,
                        founder_mlkem_pk,
                        ..
                    } => {
                        if founder_id == *member_id {
                            found_pk = Some(RecipientPublicKey {
                                x25519: founder_x25519_pk,
                                ml_kem: founder_mlkem_pk,
                            });
                        }
                    }
                    Operation::AddMember {
                        member_id: mid,
                        member_x25519_pk,
                        member_mlkem_pk,
                        ..
                    } => {
                        if mid == *member_id {
                            found_pk = Some(RecipientPublicKey {
                                x25519: member_x25519_pk,
                                ml_kem: member_mlkem_pk,
                            });
                        }
                    }
                    Operation::RemoveMember { member_id: mid } => {
                        if mid == *member_id {
                            found_pk = None;
                        }
                    }
                    _ => {}
                }
            }
        }
        found_pk.ok_or(FileFormatError::MemberNotFound)
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
