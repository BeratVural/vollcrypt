use std::collections::BTreeMap;
use std::io::Write;
use crate::chunk::ChunkEnvelope;
use crate::error::FileFormatError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoWriteMode {
    Sequential,
    DirectOffset,
    Batched { batch_size: usize },
}

pub trait ChunkWriter {
    fn write_chunk(&mut self, index: u32, envelope: &ChunkEnvelope) -> Result<(), FileFormatError>;
    fn finalize(&mut self) -> Result<(), FileFormatError>;
}

pub struct SequentialChunkWriter<W: Write> {
    writer: W,
    pending: BTreeMap<u32, ChunkEnvelope>,
    next_expected: u32,
}

impl<W: Write> SequentialChunkWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            pending: BTreeMap::new(),
            next_expected: 0,
        }
    }
}

impl<W: Write> ChunkWriter for SequentialChunkWriter<W> {
    fn write_chunk(&mut self, index: u32, envelope: &ChunkEnvelope) -> Result<(), FileFormatError> {
        self.pending.insert(index, envelope.clone());
        while let Some(env) = self.pending.remove(&self.next_expected) {
            let bytes = env.write();
            self.writer.write_all(&bytes).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            self.next_expected += 1;
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), FileFormatError> {
        self.writer.flush().map_err(|e| FileFormatError::IoError(e.to_string()))?;
        if !self.pending.is_empty() {
            return Err(FileFormatError::IoError("Pending chunks remain in SequentialChunkWriter".to_string()));
        }
        Ok(())
    }
}

pub struct BatchedChunkWriter<W: Write> {
    writer: W,
    pending: BTreeMap<u32, ChunkEnvelope>,
    next_expected: u32,
    batch_size: usize,
}

impl<W: Write> BatchedChunkWriter<W> {
    pub fn new(writer: W, batch_size: usize) -> Self {
        Self {
            writer,
            pending: BTreeMap::new(),
            next_expected: 0,
            batch_size,
        }
    }
}

impl<W: Write> ChunkWriter for BatchedChunkWriter<W> {
    fn write_chunk(&mut self, index: u32, envelope: &ChunkEnvelope) -> Result<(), FileFormatError> {
        self.pending.insert(index, envelope.clone());
        
        let mut sequential_count = 0;
        let mut check_idx = self.next_expected;
        while self.pending.contains_key(&check_idx) {
            sequential_count += 1;
            check_idx += 1;
        }
        
        if sequential_count >= self.batch_size {
            for _ in 0..self.batch_size {
                if let Some(env) = self.pending.remove(&self.next_expected) {
                    let bytes = env.write();
                    self.writer.write_all(&bytes).map_err(|e| FileFormatError::IoError(e.to_string()))?;
                    self.next_expected += 1;
                }
            }
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), FileFormatError> {
        while let Some(env) = self.pending.remove(&self.next_expected) {
            let bytes = env.write();
            self.writer.write_all(&bytes).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            self.next_expected += 1;
        }
        self.writer.flush().map_err(|e| FileFormatError::IoError(e.to_string()))?;
        if !self.pending.is_empty() {
            return Err(FileFormatError::IoError("Pending chunks remain in BatchedChunkWriter".to_string()));
        }
        Ok(())
    }
}

pub struct DirectOffsetChunkWriter {
    file: std::fs::File,
    header_len: u64,
    chunk_size: usize,
}

impl DirectOffsetChunkWriter {
    pub fn new(file: std::fs::File, header_len: u64, chunk_size: usize) -> Self {
        Self {
            file,
            header_len,
            chunk_size,
        }
    }
}

impl ChunkWriter for DirectOffsetChunkWriter {
    fn write_chunk(&mut self, index: u32, envelope: &ChunkEnvelope) -> Result<(), FileFormatError> {
        let bytes = envelope.write();
        let offset = self.header_len + (index as u64) * (32 + self.chunk_size as u64);
        write_raw_at(&self.file, &bytes, offset)?;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), FileFormatError> {
        self.file.sync_all().map_err(|e| FileFormatError::IoError(e.to_string()))?;
        Ok(())
    }
}

pub fn write_raw_at(file: &std::fs::File, buf: &[u8], offset: u64) -> Result<(), FileFormatError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let mut buf = buf;
        let mut offset = offset;
        while !buf.is_empty() {
            let n = file.write_at(buf, offset).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            if n == 0 {
                return Err(FileFormatError::IoError("Write returned 0".to_string()));
            }
            buf = &buf[n..];
            offset += n as u64;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut buf = buf;
        let mut offset = offset;
        while !buf.is_empty() {
            let n = file.seek_write(buf, offset).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            if n == 0 {
                return Err(FileFormatError::IoError("Write returned 0".to_string()));
            }
            buf = &buf[n..];
            offset += n as u64;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        let _ = buf;
        let _ = offset;
        Err(FileFormatError::IoError("Direct offset writing is not supported on this platform".to_string()))
    }
}
