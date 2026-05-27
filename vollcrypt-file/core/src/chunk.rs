use crate::error::FileFormatError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEnvelope {
    pub chunk_index: u32,
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

impl ChunkEnvelope {
    pub fn parse(input: &[u8], ciphertext_len: usize) -> Result<Self, FileFormatError> {
        let expected_len = 32 + ciphertext_len;
        if input.len() < expected_len {
            return Err(FileFormatError::TruncatedChunk {
                expected: expected_len,
                got: input.len(),
            });
        }

        let mut chunk_index_bytes = [0u8; 4];
        chunk_index_bytes.copy_from_slice(&input[0..4]);
        let chunk_index = u32::from_be_bytes(chunk_index_bytes);

        let mut iv = [0u8; 12];
        iv.copy_from_slice(&input[4..16]);

        let ciphertext = input[16..16 + ciphertext_len].to_vec();

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&input[16 + ciphertext_len..16 + ciphertext_len + 16]);

        Ok(ChunkEnvelope {
            chunk_index,
            iv,
            ciphertext,
            tag,
        })
    }

    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ciphertext.len());
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    pub fn wire_size(ciphertext_len: usize) -> usize {
        32 + ciphertext_len
    }
}
