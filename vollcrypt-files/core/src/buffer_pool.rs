use crate::constants::CHUNK_ENVELOPE_OVERHEAD;
use zeroize::Zeroize;

pub struct PooledBuffer {
    data: Vec<u8>,
    chunk_size: usize,
}

impl PooledBuffer {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            data: vec![0u8; CHUNK_ENVELOPE_OVERHEAD + chunk_size],
            chunk_size,
        }
    }

    pub fn set_index(&mut self, index: u32) {
        self.data[0..4].copy_from_slice(&index.to_be_bytes());
    }

    pub fn get_index(&self) -> u32 {
        u32::from_be_bytes(self.data[0..4].try_into().unwrap())
    }

    pub fn set_iv(&mut self, iv: &[u8; 12]) {
        self.data[4..16].copy_from_slice(iv);
    }

    pub fn get_iv(&self) -> &[u8; 12] {
        self.data[4..16].try_into().unwrap()
    }

    pub fn as_plaintext_mut(&mut self, len: usize) -> &mut [u8] {
        assert!(len <= self.chunk_size);
        &mut self.data[16..16 + len]
    }

    pub fn as_ciphertext_mut(&mut self, len: usize) -> &mut [u8] {
        assert!(len <= self.chunk_size);
        &mut self.data[16..16 + len]
    }

    pub fn as_plaintext(&self, len: usize) -> &[u8] {
        assert!(len <= self.chunk_size);
        &self.data[16..16 + len]
    }

    pub fn as_ciphertext(&self, len: usize) -> &[u8] {
        assert!(len <= self.chunk_size);
        &self.data[16..16 + len]
    }

    pub fn as_tag_slice(&self, len: usize) -> &[u8; 16] {
        (&self.data[16 + len..CHUNK_ENVELOPE_OVERHEAD + len])
            .try_into()
            .unwrap()
    }

    pub fn as_tag_mut(&mut self, len: usize) -> &mut [u8; 16] {
        (&mut self.data[16 + len..CHUNK_ENVELOPE_OVERHEAD + len])
            .try_into()
            .unwrap()
    }

    pub fn as_envelope_slice(&self, len: usize) -> &[u8] {
        &self.data[0..CHUNK_ENVELOPE_OVERHEAD + len]
    }

    pub fn as_envelope_mut(&mut self, len: usize) -> &mut [u8] {
        &mut self.data[0..CHUNK_ENVELOPE_OVERHEAD + len]
    }

    // Pointer accessors for zero-copy WASM bridge
    pub fn data_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn plaintext_ptr(&self) -> *const u8 {
        &self.data[16] as *const u8
    }

    pub fn ciphertext_ptr(&self) -> *const u8 {
        &self.data[16] as *const u8
    }

    pub fn tag_ptr(&self, len: usize) -> *const u8 {
        &self.data[16 + len] as *const u8
    }
}

impl Zeroize for PooledBuffer {
    fn zeroize(&mut self) {
        self.data.as_mut_slice().zeroize();
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct BufferPool {
    free_tx: crossbeam_channel::Sender<PooledBuffer>,
    free_rx: crossbeam_channel::Receiver<PooledBuffer>,
}

impl BufferPool {
    pub fn new(chunk_size: usize, pool_size: usize) -> Self {
        let (free_tx, free_rx) = crossbeam_channel::bounded::<PooledBuffer>(pool_size);
        for _ in 0..pool_size {
            free_tx.send(PooledBuffer::new(chunk_size)).unwrap();
        }
        Self { free_tx, free_rx }
    }

    pub fn rent(&self) -> PooledBuffer {
        self.free_rx.recv().unwrap()
    }

    pub fn return_buffer(&self, mut buffer: PooledBuffer) {
        buffer.zeroize();
        self.free_tx
            .send(buffer)
            .expect("buffer pool retains its receiver for its entire lifetime");
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_buffers_are_zeroized_before_reuse() {
        let pool = BufferPool::new(8, 1);
        let mut buffer = pool.rent();
        buffer.as_plaintext_mut(8).fill(0xA5);
        pool.return_buffer(buffer);

        let reused = pool.rent();
        assert!(reused.as_envelope_slice(8).iter().all(|byte| *byte == 0));
    }
}
