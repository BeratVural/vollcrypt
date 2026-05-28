use std::collections::BTreeMap;
use std::io::{Read, Write, Seek, SeekFrom};
use std::sync::mpsc::sync_channel;
use std::thread;
use std::sync::Arc;

use crate::chunk::ChunkEnvelope;
use crate::crypt::{encrypt_chunk, decrypt_chunk};
use crate::error::FileFormatError;
use crate::header::{Header, Mode, CipherId, SignedMetadata};
use crate::merkle::{MerkleTree, chunk_leaf_hash};
use crate::wrap::WrapEntry;
use crate::signature::{sign_header_plain, sign_header_sealed};
use crate::constants::FIXED_HEADER_LEN;

/// Signature/signing details to apply to the header after encryption is complete.
#[derive(Clone)]
pub enum PipelinedSignInfo {
    Plain {
        signer_ed25519_pk: [u8; 32],
        signer_ed25519_sk: [u8; 32],
        key_log_id: [u8; 32],
        timestamp: u64,
    },
    Sealed {
        signer_ed25519_pk: [u8; 32],
        signer_ed25519_sk: [u8; 32],
        key_log_id: [u8; 32],
        timestamp: u64,
        sealed_group_id: [u8; 16],
        sealed_gk_version: u32,
        sealed_gk: [u8; 32],
    },
}

/// Encrypts data from a reader and writes the formatted file to a seekable writer using pipelined thread workers.
///
/// * `source`: Reader containing plaintext data.
/// * `dest`: Seekable writer where the encrypted file (header + chunk envelopes) is written.
/// * `dek`: Data Encryption Key (32 bytes).
/// * `file_id`: Unique file identifier (16 bytes).
/// * `chunk_size`: Size of each chunk in bytes.
/// * `wraps`: Wrap entries protecting the DEK.
/// * `mode`: Header encryption mode.
/// * `num_workers`: Number of parallel worker threads for encryption.
/// * `sign_info`: Optional signing metadata and keys.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_file_pipelined<R: Read + Send + 'static, W: Write + Seek>(
    mut source: R,
    mut dest: W,
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: usize,
    wraps: Vec<WrapEntry>,
    mode: Mode,
    num_workers: usize,
    sign_info: Option<PipelinedSignInfo>,
) -> Result<Header, FileFormatError> {
    if num_workers == 0 {
        return Err(FileFormatError::IoError("num_workers must be greater than 0".to_string()));
    }

    // 1. Build a placeholder header to determine the final serialized length.
    let mut header = Header {
        version: if sign_info.is_some() { 2 } else { 1 },
        mode,
        cipher_id: CipherId::Aes256Gcm,
        file_id: *file_id,
        chunk_size: chunk_size as u32,
        plaintext_size: 0,
        merkle_root: [0u8; 32],
        wraps,
        signed_metadata: None,
        signature: None,
    };

    if let Some(ref info) = sign_info {
        match info {
            PipelinedSignInfo::Plain { signer_ed25519_pk, key_log_id, timestamp, .. } => {
                header.signed_metadata = Some(SignedMetadata::Plain {
                    signer_pubkey: *signer_ed25519_pk,
                    timestamp: *timestamp,
                    key_log_id: *key_log_id,
                });
                header.signature = Some([0u8; 64]);
            }
            PipelinedSignInfo::Sealed { sealed_group_id, sealed_gk_version, timestamp, .. } => {
                header.signed_metadata = Some(SignedMetadata::Sealed {
                    sealed_group_id: *sealed_group_id,
                    sealed_gk_version: *sealed_gk_version,
                    iv: [0u8; 12],
                    sealed_payload: vec![0u8; 64],
                    sealed_tag: [0u8; 16],
                    timestamp: *timestamp,
                });
                header.signature = Some([0u8; 64]);
            }
        }
    }

    let header_len = header.serialized_len();
    
    // Write placeholder space
    let dummy_header = vec![0u8; header_len];
    dest.write_all(&dummy_header).map_err(|e| FileFormatError::IoError(e.to_string()))?;

    // 2. Setup channels
    let queue_bound = num_workers * 2;
    let (read_tx, read_rx) = sync_channel::<(u32, Vec<u8>)>(queue_bound);
    let (write_tx, write_rx) = sync_channel::<(u32, Result<ChunkEnvelope, FileFormatError>)>(queue_bound);

    let read_rx = Arc::new(std::sync::Mutex::new(read_rx));
    let dek = *dek;
    let file_id = *file_id;

    // 3. Spawn workers
    let mut workers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let read_rx_c = Arc::clone(&read_rx);
        let write_tx_c = write_tx.clone();
        
        let t = thread::spawn(move || {
            loop {
                let task = {
                    let rx = read_rx_c.lock().unwrap();
                    rx.recv().ok()
                };
                if let Some((idx, data)) = task {
                    let res = encrypt_chunk(&dek, &file_id, idx, &data);
                    if write_tx_c.send((idx, res)).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
        });
        workers.push(t);
    }
    drop(write_tx);

    // 4. Read source in a separate thread
    let read_tx_c = read_tx;
    let read_thread = thread::spawn(move || -> std::io::Result<u64> {
        let mut idx = 0;
        let mut total_bytes = 0u64;
        loop {
            let mut buf = vec![0u8; chunk_size];
            let mut read_bytes = 0;
            while read_bytes < chunk_size {
                let n = source.read(&mut buf[read_bytes..])?;
                if n == 0 {
                    break;
                }
                read_bytes += n;
            }
            if read_bytes == 0 {
                break;
            }
            buf.truncate(read_bytes);
            total_bytes += read_bytes as u64;
            if read_tx_c.send((idx, buf)).is_err() {
                break;
            }
            idx += 1;
        }
        Ok(total_bytes)
    });

    // 5. Gather and write sequentially to dest
    let mut pending = BTreeMap::new();
    let mut next_expected = 0u32;
    let mut leaves = Vec::new();
    let mut encrypt_err = None;

    while let Ok((idx, res)) = write_rx.recv() {
        if encrypt_err.is_none() {
            match res {
                Ok(env) => {
                    pending.insert(idx, env);
                }
                Err(e) => {
                    encrypt_err = Some(e);
                }
            }
        }
        while let Some(env) = pending.remove(&next_expected) {
            let leaf = chunk_leaf_hash(&env);
            leaves.push(leaf);
            let env_bytes = env.write();
            dest.write_all(&env_bytes).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            next_expected += 1;
        }
    }

    if let Some(e) = encrypt_err {
        return Err(e);
    }

    // Wait for read thread
    let plaintext_size = read_thread.join().unwrap().map_err(|e| FileFormatError::IoError(e.to_string()))?;

    // Wait for workers
    for w in workers {
        let _ = w.join();
    }

    // 6. Compute final Merkle root
    let merkle_root = MerkleTree::from_leaves(leaves).root();

    // 7. Update header details
    header.plaintext_size = plaintext_size;
    header.merkle_root = merkle_root;
    header.signed_metadata = None;
    header.signature = None;

    if let Some(info) = sign_info {
        match info {
            PipelinedSignInfo::Plain { signer_ed25519_pk, signer_ed25519_sk, key_log_id, timestamp } => {
                sign_header_plain(
                    &mut header,
                    &signer_ed25519_pk,
                    &signer_ed25519_sk,
                    key_log_id,
                    timestamp,
                )?;
            }
            PipelinedSignInfo::Sealed {
                signer_ed25519_pk,
                signer_ed25519_sk,
                key_log_id,
                timestamp,
                sealed_group_id,
                sealed_gk_version,
                sealed_gk,
            } => {
                sign_header_sealed(
                    &mut header,
                    &signer_ed25519_pk,
                    &signer_ed25519_sk,
                    key_log_id,
                    timestamp,
                    sealed_group_id,
                    sealed_gk_version,
                    &sealed_gk,
                )?;
            }
        }
    }

    let serialized_header = header.write();
    assert_eq!(serialized_header.len(), header_len, "Serialized header size changed!");

    dest.seek(SeekFrom::Start(0)).map_err(|e| FileFormatError::IoError(e.to_string()))?;
    dest.write_all(&serialized_header).map_err(|e| FileFormatError::IoError(e.to_string()))?;
    dest.seek(SeekFrom::End(0)).map_err(|e| FileFormatError::IoError(e.to_string()))?;

    Ok(header)
}

/// Decrypts data from a reader and writes the decrypted stream to a writer using pipelined threads.
///
/// * `source`: Reader containing the encrypted file data.
/// * `dest`: Writer where the decrypted plaintext is written.
/// * `dek`: Data Encryption Key (32 bytes).
/// * `num_workers`: Number of parallel worker threads for decryption.
pub fn decrypt_file_pipelined<R: Read + Send + 'static, W: Write>(
    mut source: R,
    mut dest: W,
    dek: &[u8; 32],
    num_workers: usize,
) -> Result<Header, FileFormatError> {
    if num_workers == 0 {
        return Err(FileFormatError::IoError("num_workers must be greater than 0".to_string()));
    }

    // 1. Read the fixed portion of the header first (80 bytes)
    let mut fixed_buf = [0u8; FIXED_HEADER_LEN];
    source.read_exact(&mut fixed_buf).map_err(|e| FileFormatError::IoError(e.to_string()))?;
    
    if fixed_buf[0..8] != crate::constants::MAGIC {
        return Err(FileFormatError::InvalidMagic);
    }

    let mut var_len_bytes = [0u8; 4];
    var_len_bytes.copy_from_slice(&fixed_buf[76..80]);
    let variable_len = u32::from_be_bytes(var_len_bytes) as usize;

    let version = fixed_buf[8];
    let mut total_header_len = FIXED_HEADER_LEN + variable_len;
    
    let mut header_buf = vec![0u8; total_header_len];
    header_buf[0..FIXED_HEADER_LEN].copy_from_slice(&fixed_buf);
    source.read_exact(&mut header_buf[FIXED_HEADER_LEN..]).map_err(|e| FileFormatError::IoError(e.to_string()))?;

    if version == 2 {
        let mut meta_len_bytes = [0u8; 4];
        source.read_exact(&mut meta_len_bytes).map_err(|e| FileFormatError::IoError(e.to_string()))?;
        let metadata_len = u32::from_be_bytes(meta_len_bytes) as usize;
        
        let extra_bytes_len = metadata_len + 64;
        let mut extra_bytes = vec![0u8; extra_bytes_len];
        source.read_exact(&mut extra_bytes).map_err(|e| FileFormatError::IoError(e.to_string()))?;
        
        header_buf.extend_from_slice(&meta_len_bytes);
        header_buf.extend_from_slice(&extra_bytes);
        total_header_len += 4 + extra_bytes_len;
    }

    let (header, header_parsed_len) = Header::parse(&header_buf)?;
    assert_eq!(header_parsed_len, total_header_len);

    let chunk_size = header.chunk_size as usize;
    let plaintext_size = header.plaintext_size;
    let file_id = header.file_id;

    // 2. Setup channels
    let queue_bound = num_workers * 2;
    let (read_tx, read_rx) = sync_channel::<(u32, ChunkEnvelope)>(queue_bound);
    let (write_tx, write_rx) = sync_channel::<(u32, Result<Vec<u8>, FileFormatError>)>(queue_bound);

    let read_rx = Arc::new(std::sync::Mutex::new(read_rx));
    let dek = *dek;

    // 3. Spawn workers
    let mut workers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let read_rx_c = Arc::clone(&read_rx);
        let write_tx_c = write_tx.clone();
        
        let t = thread::spawn(move || {
            loop {
                let task = {
                    let rx = read_rx_c.lock().unwrap();
                    rx.recv().ok()
                };
                if let Some((idx, env)) = task {
                    let decrypted = decrypt_chunk(&dek, &file_id, idx, &env);
                    if write_tx_c.send((idx, decrypted)).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
        });
        workers.push(t);
    }
    drop(write_tx);

    // 4. Read envelopes in a separate thread
    let total_chunks = if plaintext_size == 0 {
        0
    } else {
        plaintext_size.div_ceil(chunk_size as u64) as u32
    };

    let read_tx_c = read_tx;
    let read_thread = thread::spawn(move || -> Result<(), FileFormatError> {
        for idx in 0..total_chunks {
            let is_last = idx == total_chunks - 1;
            let chunk_plaintext_len = if is_last {
                let rem = plaintext_size % chunk_size as u64;
                if rem == 0 { chunk_size } else { rem as usize }
            } else {
                chunk_size
            };
            let envelope_size = 32 + chunk_plaintext_len;
            let mut env_buf = vec![0u8; envelope_size];
            source.read_exact(&mut env_buf).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            
            let env = ChunkEnvelope::parse(&env_buf, chunk_plaintext_len)?;
            if read_tx_c.send((idx, env)).is_err() {
                break;
            }
        }
        Ok(())
    });

    // 5. Gather and write plaintexts sequentially
    let mut pending = BTreeMap::new();
    let mut next_expected = 0u32;
    let mut decrypt_err = None;

    while let Ok((idx, res)) = write_rx.recv() {
        if decrypt_err.is_none() {
            match res {
                Ok(pt) => {
                    pending.insert(idx, pt);
                }
                Err(e) => {
                    decrypt_err = Some(e);
                }
            }
        }
        while let Some(pt) = pending.remove(&next_expected) {
            dest.write_all(&pt).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            next_expected += 1;
        }
    }

    if let Some(e) = decrypt_err {
        return Err(e);
    }

    // Wait for read thread
    read_thread.join().unwrap()?;

    // Wait for workers
    for w in workers {
        let _ = w.join();
    }

    Ok(header)
}
