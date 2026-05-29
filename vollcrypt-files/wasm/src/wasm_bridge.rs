use vollcrypt_files_core::buffer_pool::{BufferPool, PooledBuffer};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmPooledBuffer {
    pub(crate) inner: PooledBuffer,
}

#[wasm_bindgen]
impl WasmPooledBuffer {
    #[wasm_bindgen(constructor)]
    pub fn new(chunk_size: usize) -> Self {
        Self {
            inner: PooledBuffer::new(chunk_size),
        }
    }

    #[wasm_bindgen(js_name = setIndex)]
    pub fn set_index(&mut self, index: u32) {
        self.inner.set_index(index);
    }

    #[wasm_bindgen(js_name = getIndex)]
    pub fn get_index(&self) -> u32 {
        self.inner.get_index()
    }

    #[wasm_bindgen(js_name = setIv)]
    pub fn set_iv(&mut self, iv: &[u8]) {
        if let Ok(iv_arr) = iv.try_into() {
            self.inner.set_iv(iv_arr);
        }
    }

    #[wasm_bindgen(js_name = getIv)]
    pub fn get_iv(&self) -> Vec<u8> {
        self.inner.get_iv().to_vec()
    }

    #[wasm_bindgen(js_name = dataPtr)]
    pub fn data_ptr(&self) -> *const u8 {
        self.inner.data_ptr()
    }

    #[wasm_bindgen(js_name = plaintextPtr)]
    pub fn plaintext_ptr(&self) -> *const u8 {
        self.inner.plaintext_ptr()
    }

    #[wasm_bindgen(js_name = ciphertextPtr)]
    pub fn ciphertext_ptr(&self) -> *const u8 {
        self.inner.ciphertext_ptr()
    }

    #[wasm_bindgen(js_name = tagPtr)]
    pub fn tag_ptr(&self, len: usize) -> *const u8 {
        self.inner.tag_ptr(len)
    }

    #[wasm_bindgen(js_name = getPlaintext)]
    pub fn get_plaintext(&self, len: usize) -> Vec<u8> {
        self.inner.as_plaintext(len).to_vec()
    }

    #[wasm_bindgen(js_name = getCiphertext)]
    pub fn get_ciphertext(&self, len: usize) -> Vec<u8> {
        self.inner.as_ciphertext(len).to_vec()
    }

    #[wasm_bindgen(js_name = getEnvelope)]
    pub fn get_envelope(&self, len: usize) -> Vec<u8> {
        self.inner.as_envelope_slice(len).to_vec()
    }
}

#[wasm_bindgen]
pub struct WasmBufferPool {
    inner: BufferPool,
}

#[wasm_bindgen]
impl WasmBufferPool {
    #[wasm_bindgen(constructor)]
    pub fn new(chunk_size: usize, pool_size: usize) -> Self {
        Self {
            inner: BufferPool::new(chunk_size, pool_size),
        }
    }

    pub fn rent(&self) -> WasmPooledBuffer {
        WasmPooledBuffer {
            inner: self.inner.rent(),
        }
    }

    #[wasm_bindgen(js_name = returnBuffer)]
    pub fn return_buffer(&self, buffer: WasmPooledBuffer) {
        self.inner.return_buffer(buffer.inner);
    }
}

#[wasm_bindgen(js_name = getWasmMemoryView)]
pub fn get_wasm_memory_view(ptr: *const u8, len: usize) -> js_sys::Uint8Array {
    let memory = wasm_bindgen::memory();
    let memory: js_sys::WebAssembly::Memory = wasm_bindgen::JsCast::dyn_into(memory).unwrap();
    js_sys::Uint8Array::new_with_byte_offset_and_length(&memory.buffer(), ptr as u32, len as u32)
}
