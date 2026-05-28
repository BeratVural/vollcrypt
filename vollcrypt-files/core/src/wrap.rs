use crate::error::FileFormatError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapEntry {
    PasswordPbkdf2 {
        iterations: u32,
        salt: [u8; 16],
        wrapped_dek: [u8; 40],
    },
    PasswordArgon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        salt: [u8; 16],
        wrapped_dek: [u8; 40],
    },
    HybridKem {
        recipient_id: [u8; 16],
        gk_version: u32,
        x25519_ephemeral: [u8; 32],
        mlkem_ciphertext: Vec<u8>,
        wrapped_dek: [u8; 40],
    },
    GroupWrap {
        group_id: [u8; 16],
        gk_version: u32,
        wrapped_dek: [u8; 40],
    },
}

impl WrapEntry {
    pub fn parse(input: &[u8]) -> Result<(Self, usize), FileFormatError> {
        if input.len() < 3 {
            return Err(FileFormatError::TruncatedHeader {
                expected: 3,
                got: input.len(),
            });
        }

        let wrap_type = input[0];
        let payload_len = u16::from_be_bytes([input[1], input[2]]) as usize;

        if input.len() < 3 + payload_len {
            return Err(FileFormatError::TruncatedHeader {
                expected: 3 + payload_len,
                got: input.len(),
            });
        }

        let payload = &input[3..3 + payload_len];

        let entry = match wrap_type {
            0 => {
                if payload_len != 60 {
                    return Err(FileFormatError::WrapPayloadLengthMismatch {
                        wrap_type: 0,
                        expected: 60,
                        got: payload_len as u16,
                    });
                }
                let mut iterations_bytes = [0u8; 4];
                iterations_bytes.copy_from_slice(&payload[0..4]);
                let iterations = u32::from_be_bytes(iterations_bytes);

                let mut salt = [0u8; 16];
                salt.copy_from_slice(&payload[4..20]);

                let mut wrapped_dek = [0u8; 40];
                wrapped_dek.copy_from_slice(&payload[20..60]);

                WrapEntry::PasswordPbkdf2 {
                    iterations,
                    salt,
                    wrapped_dek,
                }
            }
            1 => {
                if payload_len != 68 {
                    return Err(FileFormatError::WrapPayloadLengthMismatch {
                        wrap_type: 1,
                        expected: 68,
                        got: payload_len as u16,
                    });
                }
                let mut m_cost_bytes = [0u8; 4];
                m_cost_bytes.copy_from_slice(&payload[0..4]);
                let m_cost = u32::from_be_bytes(m_cost_bytes);

                let mut t_cost_bytes = [0u8; 4];
                t_cost_bytes.copy_from_slice(&payload[4..8]);
                let t_cost = u32::from_be_bytes(t_cost_bytes);

                let mut p_cost_bytes = [0u8; 4];
                p_cost_bytes.copy_from_slice(&payload[8..12]);
                let p_cost = u32::from_be_bytes(p_cost_bytes);

                let mut salt = [0u8; 16];
                salt.copy_from_slice(&payload[12..28]);

                let mut wrapped_dek = [0u8; 40];
                wrapped_dek.copy_from_slice(&payload[28..68]);

                WrapEntry::PasswordArgon2id {
                    m_cost,
                    t_cost,
                    p_cost,
                    salt,
                    wrapped_dek,
                }
            }
            2 => {
                if payload_len != 1180 {
                    return Err(FileFormatError::WrapPayloadLengthMismatch {
                        wrap_type: 2,
                        expected: 1180,
                        got: payload_len as u16,
                    });
                }
                let mut recipient_id = [0u8; 16];
                recipient_id.copy_from_slice(&payload[0..16]);

                let mut gk_version_bytes = [0u8; 4];
                gk_version_bytes.copy_from_slice(&payload[16..20]);
                let gk_version = u32::from_be_bytes(gk_version_bytes);

                let mut x25519_ephemeral = [0u8; 32];
                x25519_ephemeral.copy_from_slice(&payload[20..52]);

                let mlkem_ciphertext = payload[52..1140].to_vec();

                let mut wrapped_dek = [0u8; 40];
                wrapped_dek.copy_from_slice(&payload[1140..1180]);

                WrapEntry::HybridKem {
                    recipient_id,
                    gk_version,
                    x25519_ephemeral,
                    mlkem_ciphertext,
                    wrapped_dek,
                }
            }
            3 => {
                if payload_len != 60 {
                    return Err(FileFormatError::WrapPayloadLengthMismatch {
                        wrap_type: 3,
                        expected: 60,
                        got: payload_len as u16,
                    });
                }
                let mut group_id = [0u8; 16];
                group_id.copy_from_slice(&payload[0..16]);

                let mut gk_version_bytes = [0u8; 4];
                gk_version_bytes.copy_from_slice(&payload[16..20]);
                let gk_version = u32::from_be_bytes(gk_version_bytes);

                let mut wrapped_dek = [0u8; 40];
                wrapped_dek.copy_from_slice(&payload[20..60]);

                WrapEntry::GroupWrap {
                    group_id,
                    gk_version,
                    wrapped_dek,
                }
            }
            invalid_type => return Err(FileFormatError::InvalidWrapType(invalid_type)),
        };

        Ok((entry, 3 + payload_len))
    }

    pub fn write(&self) -> Vec<u8> {
        let wrap_type = match self {
            WrapEntry::PasswordPbkdf2 { .. } => 0u8,
            WrapEntry::PasswordArgon2id { .. } => 1u8,
            WrapEntry::HybridKem { .. } => 2u8,
            WrapEntry::GroupWrap { .. } => 3u8,
        };

        let payload_len = (self.wire_size() - 3) as u16;
        let mut out = Vec::with_capacity(self.wire_size());
        out.push(wrap_type);
        out.extend_from_slice(&payload_len.to_be_bytes());

        match self {
            WrapEntry::PasswordPbkdf2 {
                iterations,
                salt,
                wrapped_dek,
            } => {
                out.extend_from_slice(&iterations.to_be_bytes());
                out.extend_from_slice(salt);
                out.extend_from_slice(wrapped_dek);
            }
            WrapEntry::PasswordArgon2id {
                m_cost,
                t_cost,
                p_cost,
                salt,
                wrapped_dek,
            } => {
                out.extend_from_slice(&m_cost.to_be_bytes());
                out.extend_from_slice(&t_cost.to_be_bytes());
                out.extend_from_slice(&p_cost.to_be_bytes());
                out.extend_from_slice(salt);
                out.extend_from_slice(wrapped_dek);
            }
            WrapEntry::HybridKem {
                recipient_id,
                gk_version,
                x25519_ephemeral,
                mlkem_ciphertext,
                wrapped_dek,
            } => {
                out.extend_from_slice(recipient_id);
                out.extend_from_slice(&gk_version.to_be_bytes());
                out.extend_from_slice(x25519_ephemeral);
                out.extend_from_slice(mlkem_ciphertext);
                out.extend_from_slice(wrapped_dek);
            }
            WrapEntry::GroupWrap {
                group_id,
                gk_version,
                wrapped_dek,
            } => {
                out.extend_from_slice(group_id);
                out.extend_from_slice(&gk_version.to_be_bytes());
                out.extend_from_slice(wrapped_dek);
            }
        }

        out
    }

    pub fn wire_size(&self) -> usize {
        match self {
            WrapEntry::PasswordPbkdf2 { .. } => 3 + 60,
            WrapEntry::PasswordArgon2id { .. } => 3 + 68,
            WrapEntry::HybridKem { .. } => 3 + 1180,
            WrapEntry::GroupWrap { .. } => 3 + 60,
        }
    }
}
