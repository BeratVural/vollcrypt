use crate::constants::{FIXED_HEADER_LEN, MAGIC};
use crate::error::FileFormatError;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub mode: Mode,
    pub cipher_id: CipherId,
    pub file_id: [u8; 16],
    pub chunk_size: u32,
    pub plaintext_size: u64,
    pub merkle_root: [u8; 32],
    pub wraps: Vec<WrapEntry>,
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
        if version != crate::constants::VERSION {
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

        // 7. Parse Plaintext Size
        let mut plaintext_size_bytes = [0u8; 8];
        plaintext_size_bytes.copy_from_slice(&input[31..39]);
        let plaintext_size = u64::from_be_bytes(plaintext_size_bytes);

        // 8. Parse Merkle Root
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&input[39..71]);

        // 9. Parse Wrap Count
        let wrap_count = input[71];

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

        let header = Header {
            version,
            mode,
            cipher_id,
            file_id,
            chunk_size,
            plaintext_size,
            merkle_root,
            wraps,
        };

        Ok((header, total_header_len))
    }

    pub fn write(&self) -> Vec<u8> {
        let mut wraps_bytes = Vec::new();
        for wrap in &self.wraps {
            wraps_bytes.extend_from_slice(&wrap.write());
        }

        let variable_len = wraps_bytes.len() as u32;
        let wrap_count = self.wraps.len() as u8;

        let mut out = Vec::with_capacity(FIXED_HEADER_LEN + wraps_bytes.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.push(self.mode as u8);
        out.push(self.cipher_id as u8);
        out.extend_from_slice(&self.file_id);
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.plaintext_size.to_be_bytes());
        out.extend_from_slice(&self.merkle_root);
        out.push(wrap_count);
        out.extend_from_slice(&[0u8; 4]); // Reserved
        out.extend_from_slice(&variable_len.to_be_bytes());
        out.extend_from_slice(&wraps_bytes);

        out
    }

    pub fn serialized_len(&self) -> usize {
        FIXED_HEADER_LEN + self.wraps.iter().map(|w| w.wire_size()).sum::<usize>()
    }
}
