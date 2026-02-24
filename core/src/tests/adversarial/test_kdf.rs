use std::collections::HashSet;
use std::time::Instant;

use crate::kdf::{derive_hkdf, derive_pbkdf2, derive_window_key};

// ── HKDF Attacks ──────────────────────────────────────────────────────────

#[test]
fn hkdf_empty_ikm() {
    // HKDF spec allows empty IKM, it just depends on the salt/info for uniqueness,
    // though it provides no entropy.
    let result = derive_hkdf(&[], Some(b"salt"), Some(b"info"), 32);
    assert!(result.is_ok(), "Empty IKM is valid in HKDF");
    let okm = result.unwrap();
    assert_eq!(okm.len(), 32);
}

#[test]
fn hkdf_empty_output() {
    let ikm = [0x42u8; 32];
    let result = derive_hkdf(&ikm, None, None, 0);
    // Usually HKDF okm of length 0 is a valid empty array
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn hkdf_very_large_output() {
    let ikm = [0x42u8; 32];
    // max size for HKDF-SHA256 is 255 * 32 = 8160 bytes
    let result = derive_hkdf(&ikm, None, None, 8160);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 8160);
}

#[test]
fn hkdf_output_exceeds_maximum() {
    let ikm = [0x42u8; 32];
    // max size + 1
    let result = derive_hkdf(&ikm, None, None, 8161);
    assert!(result.is_err(), "Must fail when output length exceeds HKDF limit");
}

#[test]
fn hkdf_same_ikm_different_info_different_output() {
    let ikm = [0x42u8; 32];
    let okm1 = derive_hkdf(&ikm, None, Some(b"info1"), 32).unwrap();
    let okm2 = derive_hkdf(&ikm, None, Some(b"info2"), 32).unwrap();
    assert_ne!(okm1, okm2, "Different info must yield different OKM");
}

#[test]
fn hkdf_same_ikm_same_info_same_output() {
    let ikm = [0x42u8; 32];
    let okm1 = derive_hkdf(&ikm, None, Some(b"info"), 32).unwrap();
    let okm2 = derive_hkdf(&ikm, None, Some(b"info"), 32).unwrap();
    assert_eq!(okm1, okm2, "HKDF must be deterministic");
}

#[test]
fn hkdf_context_collision_attempt() {
    let ikm = [0x42u8; 32];
    // Usually, info strings should be delimited. 
    // This is to verify behavior when collision domains might overlap.
    let okm1 = derive_hkdf(&ikm, None, Some(b"vollchat-srk-v1vollchat-window-key-v1"), 32).unwrap();
    let okm2 = derive_hkdf(&ikm, None, Some(b"vollchat-srk-v1"), 32).unwrap();
    assert_ne!(okm1, okm2, "Different total info strings prevent collision");
}

// ── PBKDF2 Attacks ────────────────────────────────────────────────────────

#[test]
fn pbkdf2_empty_password() {
    let pw = b"";
    let salt = b"salt";
    let key = derive_pbkdf2(pw, salt, 1000, 32);
    // It's weak, but valid algorithmically
    assert_eq!(key.len(), 32);
}

#[test]
fn pbkdf2_empty_salt() {
    let pw = b"password";
    let salt = b"";
    let key = derive_pbkdf2(pw, salt, 1000, 32);
    // Valid algorithmically, though insecure
    assert_eq!(key.len(), 32);
}

#[test]
fn pbkdf2_zero_iterations() {
    // The underlying pbkdf2 library might not panic on 0 iterations but clamps it.
    let pw = b"password";
    let salt = b"salt";
    let key = derive_pbkdf2(pw, salt, 0, 32);
    // As long as it doesn't crash, we consider it safe (though insecure to use 0)
    assert_eq!(key.len(), 32);
}

#[test]
fn pbkdf2_one_iteration() {
    let pw = b"password";
    let salt = b"salt";
    let key = derive_pbkdf2(pw, salt, 1, 32);
    assert_eq!(key.len(), 32);
}

#[test]
fn pbkdf2_same_password_different_salt_different_output() {
    let pw = b"password";
    let key1 = derive_pbkdf2(pw, b"salt1", 1000, 32);
    let key2 = derive_pbkdf2(pw, b"salt2", 1000, 32);
    assert_ne!(key1, key2);
}

#[test]
#[ignore = "Timing tests take longer and are non-deterministic on shared CI runners"]
fn pbkdf2_timing_consistency() {
    let mut timings = Vec::new();
    let salt = b"static_salt";
    
    for i in 0..10 {
        let pw = format!("password{}", i);
        let start = Instant::now();
        let _ = derive_pbkdf2(pw.as_bytes(), salt, 100_000, 32);
        timings.push(start.elapsed().as_micros() as f64);
    }
    
    let mean = timings.iter().sum::<f64>() / timings.len() as f64;
    let variance = timings.iter().map(|&t| (t - mean).powi(2)).sum::<f64>() / timings.len() as f64;
    let std_dev = variance.sqrt();
    
    // Std dev < 10%
    assert!(std_dev < mean * 0.1, "Timing deviance too high, possible timing attack surface");
}

// ── WindowKey Attacks ─────────────────────────────────────────────────────

#[test]
fn window_key_index_zero() {
    let srk = [0x42u8; 32];
    let key = derive_window_key(&srk, 0).expect("Window Key 0 failed");
    assert_eq!(key.len(), 32);
}

#[test]
fn window_key_max_u64_index() {
    let srk = [0x42u8; 32];
    let key = derive_window_key(&srk, u64::MAX).expect("Window Key MAX failed");
    assert_eq!(key.len(), 32);
}

#[test]
fn window_key_sequential_uniqueness() {
    let srk = [0x42u8; 32];
    let mut keys = HashSet::new();

    for i in 0..1000 {
        let key = derive_window_key(&srk, i).unwrap();
        assert!(keys.insert(key), "Generated duplicate WindowKey");
    }

    assert_eq!(keys.len(), 1000);
}
