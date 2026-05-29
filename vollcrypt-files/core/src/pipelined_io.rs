use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread;

use crate::chunk::ChunkEnvelope;
use crate::constants::FIXED_HEADER_LEN;
use crate::crypt::{
    decrypt_chunk_async, decrypt_chunk_in_place, encrypt_chunk_async, encrypt_chunk_in_place,
};
use crate::error::FileFormatError;
use crate::header::{CipherId, Header, Mode, SignedMetadata};
use crate::hybrid_sig::{HybridPublicKey, HybridSecretKey, HybridSignature};
use crate::merkle::{chunk_leaf_hash_raw_with_algo, chunk_leaf_hash_with_algo, StreamingMerkle};
use crate::signature::{sign_header_plain, sign_header_sealed};
use crate::wrap::WrapEntry;
use crate::writer::IoWriteMode;

/// Signature/signing details to apply to the header after encryption is complete.
#[derive(Clone)]
pub enum PipelinedSignInfo {
    Plain {
        signer_pk: HybridPublicKey,
        signer_sk: HybridSecretKey,
        key_log_id: [u8; 32],
        timestamp: u64,
    },
    Sealed {
        signer_pk: HybridPublicKey,
        signer_sk: HybridSecretKey,
        key_log_id: [u8; 32],
        timestamp: u64,
        sealed_group_id: [u8; 16],
        sealed_gk_version: u32,
        sealed_gk: [u8; 32],
    },
}

struct EncryptTask {
    index: u32,
    buffer: crate::buffer_pool::PooledBuffer,
    plaintext_len: usize,
}

enum EncryptResultInPlace {
    Envelope(crate::buffer_pool::PooledBuffer),
    Leaf([u8; 32]),
}

struct EncryptResultTask {
    index: u32,
    plaintext_len: usize,
    result: Result<EncryptResultInPlace, FileFormatError>,
}

struct DecryptTask {
    index: u32,
    buffer: crate::buffer_pool::PooledBuffer,
    plaintext_len: usize,
}

struct DecryptResultTask {
    index: u32,
    plaintext_len: usize,
    result: Result<crate::buffer_pool::PooledBuffer, FileFormatError>,
}

fn try_downcast_file(any: &mut dyn std::any::Any) -> Option<&mut std::fs::File> {
    if any.is::<std::fs::File>() {
        any.downcast_mut::<std::fs::File>()
    } else if any.is::<&mut std::fs::File>() {
        any.downcast_mut::<&mut std::fs::File>().map(|f| &mut **f)
    } else {
        None
    }
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
/// * `write_mode`: Configures sequential, batched, or direct offset I/O writes.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_file_pipelined<R: Read + Send + 'static, W: Write + Seek + Send + 'static>(
    source: R,
    dest: W,
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: usize,
    wraps: Vec<WrapEntry>,
    mode: Mode,
    num_workers: usize,
    sign_info: Option<PipelinedSignInfo>,
    write_mode: Option<IoWriteMode>,
) -> Result<Header, FileFormatError> {
    let mut dest_opt = Some(dest);
    let mut is_direct = false;
    let res = encrypt_file_pipelined_inner(
        source,
        &mut dest_opt,
        dek,
        file_id,
        chunk_size,
        wraps,
        mode,
        num_workers,
        sign_info,
        write_mode,
        &mut is_direct,
    );

    if res.is_err() && is_direct {
        if let Some(ref mut dest) = dest_opt {
            let dest_any: &mut dyn std::any::Any = dest;
            if let Some(file) = try_downcast_file(dest_any) {
                let _ = file.set_len(0);
            }
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn encrypt_file_pipelined_inner<R: Read + Send + 'static, W: Write + Seek + Send + 'static>(
    mut source: R,
    dest_opt: &mut Option<W>,
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: usize,
    wraps: Vec<WrapEntry>,
    mode: Mode,
    num_workers: usize,
    sign_info: Option<PipelinedSignInfo>,
    write_mode: Option<IoWriteMode>,
    is_direct: &mut bool,
) -> Result<Header, FileFormatError> {
    if num_workers == 0 {
        return Err(FileFormatError::IoError(
            "num_workers must be greater than 0".to_string(),
        ));
    }

    let hash_algo = crate::merkle::default_hash_algorithm();

    // 1. Build a placeholder header to determine the final serialized length.
    let mut header = Header {
        version: if sign_info.is_some() { 3 } else { 1 },
        mode,
        cipher_id: CipherId::Aes256Gcm,
        file_id: *file_id,
        chunk_size: chunk_size as u32,
        plaintext_size: 0,
        merkle_root: [0u8; 32],
        hash_algorithm: hash_algo,
        wraps,
        signed_metadata: None,
        signature: None,
    };

    if let Some(ref info) = sign_info {
        match info {
            PipelinedSignInfo::Plain {
                signer_pk,
                key_log_id,
                timestamp,
                ..
            } => {
                header.signed_metadata = Some(SignedMetadata::Plain {
                    signer_pubkey: signer_pk.clone(),
                    timestamp: *timestamp,
                    key_log_id: *key_log_id,
                });
                header.signature = Some(HybridSignature {
                    ed25519: [0u8; 64],
                    mldsa: vec![0u8; 3309],
                });
            }
            PipelinedSignInfo::Sealed {
                sealed_group_id,
                sealed_gk_version,
                timestamp,
                ..
            } => {
                header.signed_metadata = Some(SignedMetadata::Sealed {
                    sealed_group_id: *sealed_group_id,
                    sealed_gk_version: *sealed_gk_version,
                    iv: [0u8; 12],
                    sealed_payload: vec![0u8; 32],
                    sealed_tag: [0u8; 16],
                    timestamp: *timestamp,
                });
                header.signature = Some(HybridSignature {
                    ed25519: [0u8; 64],
                    mldsa: vec![0u8; 3309],
                });
            }
        }
    }

    let header_hash = header.canonical_header_hash();
    let header_len = header.serialized_len();

    // Write placeholder space (only for non-DirectOffset, for DirectOffset we pre-allocate the whole file first)
    let selected_mode = write_mode.unwrap_or(IoWriteMode::Sequential);
    if selected_mode != IoWriteMode::DirectOffset {
        let dest = dest_opt.as_mut().expect("dest must be present");
        let dummy_header = vec![0u8; header_len];
        dest.write_all(&dummy_header)
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
    }

    // Setup direct offset if requested
    let mut direct_write_files = Vec::with_capacity(num_workers);

    if let IoWriteMode::DirectOffset = selected_mode {
        *is_direct = true;

        // Find source length
        let source_any: &mut dyn std::any::Any = &mut source;
        let source_len = if let Some(file) = try_downcast_file(source_any) {
            file.metadata().ok().map(|m| m.len())
        } else {
            None
        }
        .ok_or_else(|| {
            FileFormatError::IoError(
                "DirectOffset mode requires a source of known size (e.g. std::fs::File)"
                    .to_string(),
            )
        })?;

        let total_chunks = if source_len == 0 {
            0
        } else {
            source_len.div_ceil(chunk_size as u64)
        };
        let mut total_size = header_len as u64;
        if total_chunks > 0 {
            let last_chunk_plaintext_len = (source_len % chunk_size as u64) as usize;
            let last_chunk_len = if last_chunk_plaintext_len == 0 {
                chunk_size
            } else {
                last_chunk_plaintext_len
            };
            total_size += (total_chunks - 1) * (32 + chunk_size as u64);
            total_size += 32 + last_chunk_len as u64;
        }

        let dest = dest_opt.as_mut().expect("dest must be present");
        let dest_any: &mut dyn std::any::Any = dest;
        let dest_file = try_downcast_file(dest_any).ok_or_else(|| {
            FileFormatError::IoError(
                "DirectOffset mode requires a destination std::fs::File".to_string(),
            )
        })?;

        // Preallocate
        dest_file
            .set_len(total_size)
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;

        // Spawn writers
        for _ in 0..num_workers {
            let cloned_file = dest_file
                .try_clone()
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            direct_write_files.push(Some(cloned_file));
        }
    } else {
        for _ in 0..num_workers {
            direct_write_files.push(None);
        }
    }

    // Allocate BufferPool
    let batch_size = 16;
    let pool_size = (num_workers * 2 + 2) * batch_size;
    let pool = Arc::new(crate::buffer_pool::BufferPool::new(chunk_size, pool_size));

    // 2. Setup channels
    let queue_bound = num_workers * 2;
    let (read_tx, read_rx) = sync_channel::<Vec<EncryptTask>>(queue_bound);
    let (write_tx, write_rx) = sync_channel::<Vec<EncryptResultTask>>(queue_bound);

    let read_rx = Arc::new(std::sync::Mutex::new(read_rx));
    let dek = *dek;
    let file_id = *file_id;

    // 3. Spawn workers
    let mut workers = Vec::with_capacity(num_workers);
    for worker_id in 0..num_workers {
        let read_rx_c = Arc::clone(&read_rx);
        let write_tx_c = write_tx.clone();
        let local_file = direct_write_files[worker_id].take();
        let pool_c = Arc::clone(&pool);

        let t = thread::spawn(move || loop {
            let task = {
                let rx = read_rx_c.lock().unwrap();
                rx.recv().ok()
            };
            if let Some(batch) = task {
                let mut results = Vec::with_capacity(batch.len());
                for mut t in batch {
                    let idx = t.index;
                    let res = encrypt_chunk_in_place(
                        &dek,
                        &file_id,
                        idx,
                        &mut t.buffer,
                        t.plaintext_len,
                        Some(&header_hash),
                    );
                    match res {
                        Ok(()) => {
                            if let Some(ref file) = local_file {
                                let offset =
                                    header_len as u64 + (idx as u64) * (32 + chunk_size as u64);
                                if let Err(e) = crate::writer::write_raw_at(
                                    file,
                                    t.buffer.as_envelope_slice(t.plaintext_len),
                                    offset,
                                ) {
                                    pool_c.return_buffer(t.buffer);
                                    results.push(EncryptResultTask {
                                        index: idx,
                                        plaintext_len: t.plaintext_len,
                                        result: Err(e),
                                    });
                                    continue;
                                }
                                let leaf = chunk_leaf_hash_raw_with_algo(
                                    idx,
                                    t.buffer.get_iv(),
                                    t.buffer.as_tag_slice(t.plaintext_len),
                                    hash_algo,
                                );
                                pool_c.return_buffer(t.buffer);
                                results.push(EncryptResultTask {
                                    index: idx,
                                    plaintext_len: t.plaintext_len,
                                    result: Ok(EncryptResultInPlace::Leaf(leaf)),
                                });
                            } else {
                                results.push(EncryptResultTask {
                                    index: idx,
                                    plaintext_len: t.plaintext_len,
                                    result: Ok(EncryptResultInPlace::Envelope(t.buffer)),
                                });
                            }
                        }
                        Err(e) => {
                            pool_c.return_buffer(t.buffer);
                            results.push(EncryptResultTask {
                                index: idx,
                                plaintext_len: t.plaintext_len,
                                result: Err(e),
                            });
                        }
                    }
                }
                if write_tx_c.send(results).is_err() {
                    break;
                }
            } else {
                break;
            }
        });
        workers.push(t);
    }
    drop(write_tx);

    // 4. Read source in a separate thread
    let read_tx_c = read_tx;
    let pool_c = Arc::clone(&pool);
    let read_thread = thread::spawn(move || -> std::io::Result<u64> {
        let mut total_bytes = 0u64;
        let mut current_batch = Vec::with_capacity(batch_size);
        let mut idx = 0;
        loop {
            let mut buffer = pool_c.rent();
            let mut read_bytes = 0;
            let target_slice = buffer.as_plaintext_mut(chunk_size);
            while read_bytes < chunk_size {
                let n = source.read(&mut target_slice[read_bytes..])?;
                if n == 0 {
                    break;
                }
                read_bytes += n;
            }
            if read_bytes == 0 {
                pool_c.return_buffer(buffer);
                break;
            }

            total_bytes += read_bytes as u64;
            current_batch.push(EncryptTask {
                index: idx,
                buffer,
                plaintext_len: read_bytes,
            });
            idx += 1;

            if current_batch.len() == batch_size {
                let batch_to_send =
                    std::mem::replace(&mut current_batch, Vec::with_capacity(batch_size));
                if read_tx_c.send(batch_to_send).is_err() {
                    return Ok(total_bytes);
                }
            }
        }
        if !current_batch.is_empty() {
            let _ = read_tx_c.send(current_batch);
        }
        Ok(total_bytes)
    });

    let mut merkle_reducer = StreamingMerkle::new_with_algo(hash_algo);
    let plaintext_size;

    {
        // 5. Gather and write sequentially to dest
        let mut pending = BTreeMap::new();
        let mut pending_leaves = BTreeMap::new();
        let mut next_expected = 0u32;
        let mut encrypt_err = None;

        while let Ok(batch_results) = write_rx.recv() {
            if encrypt_err.is_none() {
                for task in batch_results {
                    let idx = task.index;
                    match task.result {
                        Ok(EncryptResultInPlace::Envelope(buf)) => {
                            pending.insert(idx, (buf, task.plaintext_len));
                        }
                        Ok(EncryptResultInPlace::Leaf(leaf)) => {
                            pending_leaves.insert(idx, leaf);
                        }
                        Err(e) => {
                            encrypt_err = Some(e);
                        }
                    }
                }
            }

            if !*is_direct {
                match selected_mode {
                    IoWriteMode::Sequential => {
                        while let Some((buf, len)) = pending.remove(&next_expected) {
                            let iv = *buf.get_iv();
                            let tag = *buf.as_tag_slice(len);
                            let leaf =
                                chunk_leaf_hash_raw_with_algo(next_expected, &iv, &tag, hash_algo);
                            merkle_reducer.push_leaf(leaf);
                            let dest = dest_opt.as_mut().expect("dest must be present");
                            if let Err(e) = dest.write_all(buf.as_envelope_slice(len)) {
                                encrypt_err = Some(FileFormatError::IoError(e.to_string()));
                            }
                            pool.return_buffer(buf);
                            next_expected += 1;
                        }
                    }
                    IoWriteMode::Batched { batch_size } => {
                        let mut sequential_count = 0;
                        let mut check_idx = next_expected;
                        while pending.contains_key(&check_idx) {
                            sequential_count += 1;
                            check_idx += 1;
                        }
                        if sequential_count >= batch_size {
                            for _ in 0..batch_size {
                                if let Some((buf, len)) = pending.remove(&next_expected) {
                                    let iv = *buf.get_iv();
                                    let tag = *buf.as_tag_slice(len);
                                    let leaf = chunk_leaf_hash_raw_with_algo(
                                        next_expected,
                                        &iv,
                                        &tag,
                                        hash_algo,
                                    );
                                    merkle_reducer.push_leaf(leaf);
                                    let dest = dest_opt.as_mut().expect("dest must be present");
                                    if let Err(e) = dest.write_all(buf.as_envelope_slice(len)) {
                                        encrypt_err = Some(FileFormatError::IoError(e.to_string()));
                                    }
                                    pool.return_buffer(buf);
                                    next_expected += 1;
                                }
                            }
                        }
                    }
                    IoWriteMode::DirectOffset => unreachable!(),
                }
            } else {
                while let Some(leaf) = pending_leaves.remove(&next_expected) {
                    merkle_reducer.push_leaf(leaf);
                    next_expected += 1;
                }
            }
        }

        if encrypt_err.is_none() && !*is_direct {
            if let IoWriteMode::Batched { .. } = selected_mode {
                while let Some((buf, len)) = pending.remove(&next_expected) {
                    let iv = *buf.get_iv();
                    let tag = *buf.as_tag_slice(len);
                    let leaf = chunk_leaf_hash_raw_with_algo(next_expected, &iv, &tag, hash_algo);
                    merkle_reducer.push_leaf(leaf);
                    let dest = dest_opt.as_mut().expect("dest must be present");
                    if let Err(e) = dest.write_all(buf.as_envelope_slice(len)) {
                        encrypt_err = Some(FileFormatError::IoError(e.to_string()));
                    }
                    pool.return_buffer(buf);
                    next_expected += 1;
                }
            }
        }

        // Cleanup remaining buffers in case of errors
        for (_, (buf, _)) in pending {
            pool.return_buffer(buf);
        }

        if let Some(e) = encrypt_err {
            return Err(e);
        }

        // Wait for read thread
        plaintext_size = read_thread
            .join()
            .unwrap()
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;

        // Wait for workers
        for w in workers {
            let _ = w.join();
        }
    }

    if *is_direct {
        // DirectOffset: sync file
        let dest = dest_opt.as_mut().expect("dest must be present");
        let dest_any: &mut dyn std::any::Any = dest;
        if let Some(file) = try_downcast_file(dest_any) {
            file.sync_all()
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        }
    }

    // 6. Compute final Merkle root
    let merkle_root = merkle_reducer.finalize();

    // 7. Update header details
    header.plaintext_size = plaintext_size;
    header.merkle_root = merkle_root;
    header.signed_metadata = None;
    header.signature = None;

    if let Some(info) = sign_info {
        match info {
            PipelinedSignInfo::Plain {
                signer_pk,
                signer_sk,
                key_log_id,
                timestamp,
            } => {
                sign_header_plain(
                    &mut header,
                    &signer_pk,
                    &signer_sk,
                    key_log_id,
                    timestamp,
                )?;
            }
            PipelinedSignInfo::Sealed {
                signer_pk,
                signer_sk,
                key_log_id,
                timestamp,
                sealed_group_id,
                sealed_gk_version,
                sealed_gk,
            } => {
                sign_header_sealed(
                    &mut header,
                    &signer_pk,
                    &signer_sk,
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
    assert_eq!(
        serialized_header.len(),
        header_len,
        "Serialized header size changed!"
    );

    if *is_direct {
        let dest = dest_opt.as_mut().expect("dest must be present");
        let dest_any: &mut dyn std::any::Any = dest;
        if let Some(file) = try_downcast_file(dest_any) {
            crate::writer::write_raw_at(file, &serialized_header, 0)?;
        }
    } else {
        let dest = dest_opt.as_mut().expect("dest must be present");
        dest.seek(SeekFrom::Start(0))
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        dest.write_all(&serialized_header)
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        dest.seek(SeekFrom::End(0))
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
    }

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
        return Err(FileFormatError::IoError(
            "num_workers must be greater than 0".to_string(),
        ));
    }

    // 1. Read the fixed portion of the header first (80 bytes)
    let mut fixed_buf = [0u8; FIXED_HEADER_LEN];
    source
        .read_exact(&mut fixed_buf)
        .map_err(|e| FileFormatError::IoError(e.to_string()))?;

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
    source
        .read_exact(&mut header_buf[FIXED_HEADER_LEN..])
        .map_err(|e| FileFormatError::IoError(e.to_string()))?;

    if version == 2 || version == 3 {
        let mut meta_len_bytes = [0u8; 4];
        source
            .read_exact(&mut meta_len_bytes)
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        let metadata_len = u32::from_be_bytes(meta_len_bytes) as usize;

        let extra_bytes = if version == 3 {
            let mut meta_bytes = vec![0u8; metadata_len];
            source
                .read_exact(&mut meta_bytes)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;

            let mut sig_header = [0u8; 66];
            source
                .read_exact(&mut sig_header)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;

            let mldsa_len = u16::from_be_bytes([sig_header[64], sig_header[65]]) as usize;
            let mut mldsa_bytes = vec![0u8; mldsa_len];
            source
                .read_exact(&mut mldsa_bytes)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;

            let mut extra = Vec::with_capacity(metadata_len + 66 + mldsa_len);
            extra.extend_from_slice(&meta_bytes);
            extra.extend_from_slice(&sig_header);
            extra.extend_from_slice(&mldsa_bytes);
            extra
        } else {
            let mut extra_bytes = vec![0u8; metadata_len + 64];
            source
                .read_exact(&mut extra_bytes)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            extra_bytes
        };

        let extra_len = extra_bytes.len();
        header_buf.extend_from_slice(&meta_len_bytes);
        header_buf.extend_from_slice(&extra_bytes);
        total_header_len += 4 + extra_len;
    }

    let (header, header_parsed_len) = Header::parse(&header_buf)?;
    assert_eq!(header_parsed_len, total_header_len);

    let header_hash = header.canonical_header_hash();
    let chunk_size = header.chunk_size as usize;
    let plaintext_size = header.plaintext_size;
    let file_id = header.file_id;

    // Allocate BufferPool
    let batch_size = 16;
    let pool_size = (num_workers * 2 + 2) * batch_size;
    let pool = Arc::new(crate::buffer_pool::BufferPool::new(chunk_size, pool_size));

    // 2. Setup channels
    let queue_bound = num_workers * 2;
    let (read_tx, read_rx) = sync_channel::<Vec<DecryptTask>>(queue_bound);
    let (write_tx, write_rx) = sync_channel::<Vec<DecryptResultTask>>(queue_bound);

    let read_rx = Arc::new(std::sync::Mutex::new(read_rx));
    let dek = *dek;

    // 3. Spawn workers
    let mut workers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let read_rx_c = Arc::clone(&read_rx);
        let write_tx_c = write_tx.clone();
        let pool_c = Arc::clone(&pool);

        let t = thread::spawn(move || loop {
            let task = {
                let rx = read_rx_c.lock().unwrap();
                rx.recv().ok()
            };
            if let Some(batch) = task {
                let mut results = Vec::with_capacity(batch.len());
                for mut t in batch {
                    let idx = t.index;
                    let res = decrypt_chunk_in_place(
                        &dek,
                        &file_id,
                        idx,
                        &mut t.buffer,
                        t.plaintext_len,
                        Some(&header_hash),
                    );
                    match res {
                        Ok(()) => {
                            results.push(DecryptResultTask {
                                index: idx,
                                plaintext_len: t.plaintext_len,
                                result: Ok(t.buffer),
                            });
                        }
                        Err(e) => {
                            pool_c.return_buffer(t.buffer);
                            results.push(DecryptResultTask {
                                index: idx,
                                plaintext_len: t.plaintext_len,
                                result: Err(e),
                            });
                        }
                    }
                }
                if write_tx_c.send(results).is_err() {
                    break;
                }
            } else {
                break;
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

    let hash_algo = header.hash_algorithm;
    let read_tx_c = read_tx;
    let pool_c = Arc::clone(&pool);
    let read_thread = thread::spawn(move || -> Result<Vec<[u8; 32]>, FileFormatError> {
        let mut leaf_hashes = Vec::with_capacity(total_chunks as usize);
        let mut current_batch = Vec::with_capacity(batch_size);
        for idx in 0..total_chunks {
            let is_last = idx == total_chunks - 1;
            let chunk_plaintext_len = if is_last {
                let rem = plaintext_size % chunk_size as u64;
                if rem == 0 {
                    chunk_size
                } else {
                    rem as usize
                }
            } else {
                chunk_size
            };

            let mut buffer = pool_c.rent();
            source
                .read_exact(buffer.as_envelope_mut(chunk_plaintext_len))
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;

            use crate::merkle::chunk_leaf_hash_raw_with_algo;
            let leaf = chunk_leaf_hash_raw_with_algo(
                idx,
                buffer.get_iv(),
                buffer.as_tag_slice(chunk_plaintext_len),
                hash_algo,
            );
            leaf_hashes.push(leaf);

            current_batch.push(DecryptTask {
                index: idx,
                buffer,
                plaintext_len: chunk_plaintext_len,
            });

            if current_batch.len() == batch_size {
                let batch_to_send =
                    std::mem::replace(&mut current_batch, Vec::with_capacity(batch_size));
                if read_tx_c.send(batch_to_send).is_err() {
                    return Ok(leaf_hashes);
                }
            }
        }
        if !current_batch.is_empty() {
            let _ = read_tx_c.send(current_batch);
        }
        Ok(leaf_hashes)
    });

    // 5. Gather and write plaintexts sequentially
    let mut pending = BTreeMap::new();
    let mut next_expected = 0u32;
    let mut decrypt_err = None;

    let mut total_decrypted_bytes = 0u64;
    while let Ok(batch_results) = write_rx.recv() {
        if decrypt_err.is_none() {
            for task in batch_results {
                let idx = task.index;
                match task.result {
                    Ok(buf) => {
                        pending.insert(idx, (buf, task.plaintext_len));
                    }
                    Err(e) => {
                        decrypt_err = Some(e);
                    }
                }
            }
        }
        while let Some((buf, len)) = pending.remove(&next_expected) {
            dest.write_all(buf.as_plaintext(len))
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            total_decrypted_bytes += len as u64;
            pool.return_buffer(buf);
            next_expected += 1;
        }
    }

    // Cleanup remaining buffers in case of errors
    for (_, (buf, _)) in pending {
        pool.return_buffer(buf);
    }

    if let Some(e) = decrypt_err {
        return Err(e);
    }

    // Wait for read thread
    let leaf_hashes = read_thread.join().unwrap()?;

    // Wait for workers
    for w in workers {
        let _ = w.join();
    }

    // Verify integrity checks:
    // 1. Recompute Merkle root and compare with constant-time equality
    let recomputed_root = if leaf_hashes.is_empty() {
        [0u8; 32]
    } else {
        let mut tree = crate::merkle::MerkleTree::from_leaves_with_algo(leaf_hashes, hash_algo);
        tree.root()
    };

    use subtle::ConstantTimeEq;
    if recomputed_root.ct_eq(&header.merkle_root).unwrap_u8() != 1 {
        return Err(FileFormatError::AesGcmDecryptFailed);
    }

    // 2. Cross-check plaintext size and chunk counts
    if next_expected != total_chunks {
        return Err(FileFormatError::TruncatedChunk {
            expected: total_chunks as usize,
            got: next_expected as usize,
        });
    }

    if total_decrypted_bytes != plaintext_size {
        return Err(FileFormatError::TruncatedHeader {
            expected: plaintext_size as usize,
            got: total_decrypted_bytes as usize,
        });
    }

    Ok(header)
}

/// Encrypts in-memory plaintext asynchronously with WebCrypto/concurrent provider capability.
pub async fn encrypt_file_pipelined_async(
    plaintext: &[u8],
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: usize,
    wraps: Vec<WrapEntry>,
    mode: Mode,
    sign_info: Option<PipelinedSignInfo>,
) -> Result<(Header, Vec<u8>), FileFormatError> {
    let hash_algo = crate::merkle::default_hash_algorithm();
    let mut header = Header {
        version: if sign_info.is_some() { 3 } else { 1 },
        mode,
        cipher_id: CipherId::Aes256Gcm,
        file_id: *file_id,
        chunk_size: chunk_size as u32,
        plaintext_size: plaintext.len() as u64,
        merkle_root: [0u8; 32],
        hash_algorithm: hash_algo,
        wraps,
        signed_metadata: None,
        signature: None,
    };

    if let Some(ref info) = sign_info {
        match info {
            PipelinedSignInfo::Plain {
                signer_pk,
                key_log_id,
                timestamp,
                ..
            } => {
                header.signed_metadata = Some(SignedMetadata::Plain {
                    signer_pubkey: signer_pk.clone(),
                    timestamp: *timestamp,
                    key_log_id: *key_log_id,
                });
                header.signature = Some(HybridSignature {
                    ed25519: [0u8; 64],
                    mldsa: vec![0u8; 3309],
                });
            }
            PipelinedSignInfo::Sealed {
                sealed_group_id,
                sealed_gk_version,
                timestamp,
                ..
            } => {
                header.signed_metadata = Some(SignedMetadata::Sealed {
                    sealed_group_id: *sealed_group_id,
                    sealed_gk_version: *sealed_gk_version,
                    iv: [0u8; 12],
                    sealed_payload: vec![0u8; 32],
                    sealed_tag: [0u8; 16],
                    timestamp: *timestamp,
                });
                header.signature = Some(HybridSignature {
                    ed25519: [0u8; 64],
                    mldsa: vec![0u8; 3309],
                });
            }
        }
    }

    let header_hash = header.canonical_header_hash();
    let chunk_count = if plaintext.is_empty() {
        0
    } else {
        plaintext.chunks(chunk_size).count()
    };
    let mut merkle_reducer = StreamingMerkle::new_with_algo(hash_algo);
    let mut encrypted_chunks = vec![Vec::new(); chunk_count];

    // Process batches of 16 chunks concurrently
    for batch_idx in 0..chunk_count.div_ceil(16) {
        let start_chunk = batch_idx * 16;
        let end_chunk = std::cmp::min(start_chunk + 16, chunk_count);
        let mut futures = Vec::new();

        for idx in start_chunk..end_chunk {
            let offset_start = idx * chunk_size;
            let offset_end = std::cmp::min((idx + 1) * chunk_size, plaintext.len());
            let chunk_data = plaintext[offset_start..offset_end].to_vec();
            let dek = *dek;
            let file_id = *file_id;
            let header_hash = header_hash;

            futures.push(async move {
                let res =
                    encrypt_chunk_async(&dek, &file_id, idx as u32, chunk_data, Some(&header_hash))
                        .await;
                (idx, res)
            });
        }

        let results = futures_util::future::join_all(futures).await;
        for (idx, res) in results {
            let env = res?;
            merkle_reducer.push_leaf(chunk_leaf_hash_with_algo(&env, hash_algo));
            encrypted_chunks[idx] = env.write();
        }
    }

    let merkle_root = merkle_reducer.finalize();
    header.merkle_root = merkle_root;

    if let Some(info) = sign_info {
        match info {
            PipelinedSignInfo::Plain {
                signer_pk,
                signer_sk,
                key_log_id,
                timestamp,
            } => {
                sign_header_plain(
                    &mut header,
                    &signer_pk,
                    &signer_sk,
                    key_log_id,
                    timestamp,
                )?;
            }
            PipelinedSignInfo::Sealed {
                signer_pk,
                signer_sk,
                key_log_id,
                timestamp,
                sealed_group_id,
                sealed_gk_version,
                sealed_gk,
            } => {
                sign_header_sealed(
                    &mut header,
                    &signer_pk,
                    &signer_sk,
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
    let total_capacity =
        serialized_header.len() + encrypted_chunks.iter().map(|c| c.len()).sum::<usize>();
    let mut final_output = Vec::with_capacity(total_capacity);
    final_output.extend_from_slice(&serialized_header);
    for chunk in encrypted_chunks {
        final_output.extend_from_slice(&chunk);
    }

    Ok((header, final_output))
}

/// Decrypts in-memory ciphertext asynchronously with WebCrypto/concurrent provider capability.
pub async fn decrypt_file_pipelined_async(
    ciphertext_bytes: &[u8],
    dek: &[u8; 32],
) -> Result<(Header, Vec<u8>), FileFormatError> {
    let (header, header_len) = Header::parse(ciphertext_bytes)?;
    let header_hash = header.canonical_header_hash();

    let chunk_size = header.chunk_size as usize;
    let plaintext_size = header.plaintext_size;
    let file_id = header.file_id;

    let total_chunks = if plaintext_size == 0 {
        0
    } else {
        plaintext_size.div_ceil(chunk_size as u64) as u32
    };

    let mut decrypted_chunks = vec![Vec::new(); total_chunks as usize];
    let mut leaf_hashes = Vec::with_capacity(total_chunks as usize);
    let mut offset = header_len;

    // Process batches of 16 chunks concurrently
    for batch_idx in 0..(total_chunks as usize).div_ceil(16) {
        let start_chunk = batch_idx * 16;
        let end_chunk = std::cmp::min(start_chunk + 16, total_chunks as usize);
        let mut futures = Vec::new();

        for idx in start_chunk..end_chunk {
            let is_last = idx == (total_chunks as usize) - 1;
            let chunk_plaintext_len = if is_last {
                let rem = plaintext_size % chunk_size as u64;
                if rem == 0 {
                    chunk_size
                } else {
                    rem as usize
                }
            } else {
                chunk_size
            };
            let envelope_size = 32 + chunk_plaintext_len;
            if offset + envelope_size > ciphertext_bytes.len() {
                return Err(FileFormatError::TruncatedChunk {
                    expected: envelope_size,
                    got: ciphertext_bytes.len() - offset,
                });
            }
            let env_bytes = &ciphertext_bytes[offset..offset + envelope_size];
            offset += envelope_size;

            let env = ChunkEnvelope::parse(env_bytes, chunk_plaintext_len)?;

            use crate::merkle::chunk_leaf_hash_with_algo;
            let leaf = chunk_leaf_hash_with_algo(&env, header.hash_algorithm);
            leaf_hashes.push(leaf);

            let dek = *dek;
            let file_id = file_id;
            let header_hash = header_hash;
            futures.push(async move {
                let res =
                    decrypt_chunk_async(&dek, &file_id, idx as u32, env, Some(&header_hash)).await;
                (idx, res)
            });
        }

        let results = futures_util::future::join_all(futures).await;
        for (idx, res) in results {
            decrypted_chunks[idx] = res?;
        }
    }

    // Verify integrity checks:
    // 1. Recompute Merkle root and compare with constant-time equality
    let recomputed_root = if leaf_hashes.is_empty() {
        [0u8; 32]
    } else {
        let mut tree =
            crate::merkle::MerkleTree::from_leaves_with_algo(leaf_hashes, header.hash_algorithm);
        tree.root()
    };

    use subtle::ConstantTimeEq;
    if recomputed_root.ct_eq(&header.merkle_root).unwrap_u8() != 1 {
        return Err(FileFormatError::AesGcmDecryptFailed);
    }

    let mut plaintext = Vec::with_capacity(plaintext_size as usize);
    for chunk in decrypted_chunks {
        plaintext.extend_from_slice(&chunk);
    }

    if plaintext.len() as u64 != plaintext_size {
        return Err(FileFormatError::TruncatedHeader {
            expected: plaintext_size as usize,
            got: plaintext.len(),
        });
    }

    Ok((header, plaintext))
}
