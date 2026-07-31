use crate::envelope::{pack_envelope, unpack_envelope};
use crate::kdf::{MIN_PBKDF2_ITERATIONS, derive_hkdf, derive_pbkdf2, derive_srk};
use crate::pqc::ml_kem_decapsulate;
use crate::symmetric::decrypt_aes256gcm;
use std::panic;

// ── Fuzzing / Iteration ───────────────────────────────────────────────────

#[test]
fn panic_safety_aes256gcm() {
    // We expect errs rather than panics.
    let result = panic::catch_unwind(|| {
        let key = [0u8; 32];
        let mut ct = vec![0x42; 100];
        let _ = decrypt_aes256gcm(&key, &ct, None);

        ct.truncate(10);
        let _ = decrypt_aes256gcm(&key, &ct, None);

        let _ = decrypt_aes256gcm(&key, &[], None);
    });
    assert!(
        result.is_ok(),
        "AES-256-GCM malformed ciphertext handling must not panic"
    );
}

#[test]
fn panic_safety_hkdf() {
    let result = panic::catch_unwind(|| {
        let _ = derive_hkdf(b"", None, None, 32);
        let _ = derive_hkdf(b"a", Some(b"salt"), Some(b"info"), 1000000); // Exceeds max length, should return Err, not panic
    });
    assert!(result.is_ok(), "HKDF invalid input handling must not panic");
}

#[test]
fn panic_safety_pbkdf2() {
    let result = panic::catch_unwind(|| {
        let _ = derive_pbkdf2(b"", b"", MIN_PBKDF2_ITERATIONS, 32).unwrap();
        assert!(derive_pbkdf2(b"pass", b"salt", 0, 32).is_err());
        let _ = derive_pbkdf2(b"pass", b"salt", MIN_PBKDF2_ITERATIONS, 32).unwrap();
    });
    assert!(
        result.is_ok(),
        "PBKDF2 supported input handling must not panic"
    );
}

#[test]
fn panic_safety_srk() {
    let result = panic::catch_unwind(|| {
        let _ = derive_srk(b"", b"");
        let _ = derive_srk(b"alice", vec![0u8; 100_000].as_slice());
    });
    assert!(
        result.is_ok(),
        "SRK derivation edge input handling must not panic"
    );
}

#[test]
fn panic_safety_envelope() {
    let result = panic::catch_unwind(|| {
        let _ = pack_envelope(1, &[0; 32], b"abc");
        let _ = unpack_envelope(b"short");
        let _ = unpack_envelope(b"");
    });
    assert!(
        result.is_ok(),
        "Envelope malformed input handling must not panic"
    );
}

#[test]
fn panic_safety_pqc_decap() {
    // Invalid ciphertexts passed to pqc decapsulate should not panic
    let result = panic::catch_unwind(|| {
        let bad_sk = [0u8; 2400]; // ML-KEM-768 SK len
        let bad_ct = [0u8; 1088]; // ML-KEM-768 CT len

        // ML-KEM implicit rejection may return a pseudorandom shared secret for
        // malformed ciphertext. A structured error or a 32-byte secret is safe.
        if let Ok(shared_secret) = ml_kem_decapsulate(&bad_sk, &bad_ct) {
            assert_eq!(shared_secret.len(), 32);
        }
    });
    assert!(
        result.is_ok(),
        "PQC decapsulation invalid input handling must not panic"
    );
}
