#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};
    use std::thread;
    use std::time::{Duration, Instant};
    use sysinfo::System;
    use vollcrypt_files_core::*;

    fn get_rss_mb() -> f64 {
        let mut sys = System::new();
        let pid = sysinfo::get_current_pid().ok();
        if let Some(pid) = pid {
            sys.refresh_process(pid);
            if let Some(process) = sys.process(pid) {
                return process.memory() as f64 / 1_048_576.0;
            }
        }
        0.0
    }

    #[test]
    fn test_concurrent_file_encryption() {
        let logical_cpus = num_cpus::get();
        let thread_configs = [logical_cpus, logical_cpus * 2, logical_cpus * 4];

        for &num_threads in &thread_configs {
            let mut handles = Vec::with_capacity(num_threads);
            let start = Instant::now();

            for i in 0..num_threads {
                handles.push(thread::spawn(move || {
                    let dek = [i as u8; 32];
                    let file_id = [i as u8; 16];
                    let plaintext = vec![i as u8; 64 * 1024]; // 64 KB
                    
                    // Encrypt
                    let env = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
                    // Decrypt
                    let decrypted = decrypt_chunk(&dek, &file_id, 0, &env).unwrap();
                    
                    assert_eq!(plaintext, decrypted);
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let elapsed = start.elapsed();
            let total_data_mb = (num_threads * 64 * 1024) as f64 / 1_048_576.0;
            println!(
                "CONCURRENT ENCRYPT: Threads={}, Total Encrypted={:.3} MB, Time={:?}, Throughput={:.2} MB/s",
                num_threads,
                total_data_mb,
                elapsed,
                total_data_mb / elapsed.as_secs_f64()
            );
        }
    }

    #[test]
    fn test_concurrent_manifest_reads() {
        let group_id = [0u8; 16];
        let founder_id = [1u8; 16];
        let (admin_pk, admin_sk) = ed25519_keypair_generate();
        let (rec_pk, _) = generate_recipient_keypair();
        let gk_wrap = wrap_key_to_recipient(&[0u8; 32], founder_id, 1, &rec_pk).unwrap();

        let manifest = GroupManifest::genesis(
            group_id,
            founder_id,
            &admin_sk,
            admin_pk,
            rec_pk.clone(),
            gk_wrap.clone(),
        );

        let manifest_arc = Arc::new(RwLock::new(manifest));
        let num_readers = 100;
        let mut handles = Vec::with_capacity(num_readers + 1);

        // 1 Writer Thread
        let writer_manifest = Arc::clone(&manifest_arc);
        let writer_admin_sk = admin_sk;
        let writer_admin_pk = admin_pk;
        let writer_rec_pk = rec_pk;
        let writer_gk_wrap = gk_wrap;
        handles.push(thread::spawn(move || {
            for i in 0..10 {
                let mut mid = [0u8; 16];
                mid[0..4].copy_from_slice(&(i as u32 + 2).to_be_bytes());
                {
                    let mut lock = writer_manifest.write().unwrap();
                    let _ = lock.add_member(
                        &writer_admin_sk,
                        mid,
                        writer_admin_pk,
                        writer_rec_pk.clone(),
                        writer_gk_wrap.clone(),
                    );
                }
                thread::sleep(Duration::from_millis(5));
            }
        }));

        // 100 Reader Threads
        for _ in 0..num_readers {
            let reader_manifest = Arc::clone(&manifest_arc);
            handles.push(thread::spawn(move || {
                for _ in 0..20 {
                    let members = {
                        let lock = reader_manifest.read().unwrap();
                        lock.current_members()
                    };
                    assert!(!members.is_empty());
                    thread::sleep(Duration::from_millis(2));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
        println!("CONCURRENT MANIFEST: 1 writer and 100 readers completed successfully without race conditions.");
    }

    #[test]
    fn test_concurrent_kdf() {
        let num_threads = 8;
        let mut handles = Vec::with_capacity(num_threads);

        let start_rss = get_rss_mb();
        let start = Instant::now();

        for i in 0..num_threads {
            handles.push(thread::spawn(move || {
                let password = format!("SecurePasswordStr{}", i);
                let salt = [i as u8; 16];
                // Argon2id preset: m=16384 (16 MB), t=2, p=2
                let res = derive_kek_argon2id(password.as_bytes(), &salt, 16384, 2, 2).unwrap();
                assert_ne!(res, [0u8; 32]);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let elapsed = start.elapsed();
        let end_rss = get_rss_mb();
        println!(
            "CONCURRENT KDF: Threads={}, Time={:?}, RSS delta={:.2} MB (Start: {:.2} MB, End: {:.2} MB)",
            num_threads,
            elapsed,
            end_rss - start_rss,
            start_rss,
            end_rss
        );
    }

    #[test]
    fn test_stability_loop() {
        let duration = if std::env::var("VOLLCRYPT_LONG_STABILITY").is_ok() {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(2)
        };

        let dek = [0u8; 32];
        let file_id = [0u8; 16];
        let plaintext = vec![0u8; 1024 * 1024]; // 1 MB chunk

        let start = Instant::now();
        let mut iterations = 0;
        let start_rss = get_rss_mb();

        while start.elapsed() < duration {
            let env = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
            let decrypted = decrypt_chunk(&dek, &file_id, 0, &env).unwrap();
            assert_eq!(plaintext, decrypted);
            iterations += 1;
        }

        let end_rss = get_rss_mb();
        println!(
            "STABILITY LOOP: Ran {} encrypt/decrypt roundtrips in {:?}. RSS: {:.2} MB -> {:.2} MB (diff: {:.2} MB)",
            iterations,
            start.elapsed(),
            start_rss,
            end_rss,
            end_rss - start_rss
        );
        assert!(end_rss - start_rss < 20.0, "Potential memory leak detected!");
    }
}
