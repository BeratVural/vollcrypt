use crate::keys::generate_ed25519_keypair;
use crate::verification::{
    EMOJI_PALETTE, generate_verification_code, verify_codes_match, verify_fingerprints_match,
};

// ── Symmetry and Determinism ──────────────────────────────────────────────

#[test]
fn verification_symmetry_100_random_pairs() {
    let conv = b"test_conv_sym";
    for _ in 0..100 {
        let (_, pk_a) = generate_ed25519_keypair();
        let (_, pk_b) = generate_ed25519_keypair();

        let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
        let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

        let code_ab = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);
        let code_ba = generate_verification_code(&pk_arr_b, &pk_arr_a, conv);

        assert_eq!(
            code_ab.fingerprint, code_ba.fingerprint,
            "Verification codes must be symmetric"
        );
    }
}

#[test]
fn verification_deterministic_1000_calls() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();
    let conv = b"test_conv_det";

    let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

    let expected = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);

    for _ in 0..1000 {
        let code = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);
        assert_eq!(
            code.fingerprint, expected.fingerprint,
            "Verification codes must be fully deterministic"
        );
    }
}

#[test]
fn verification_empty_conversation_id() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();
    let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

    let code = generate_verification_code(&pk_arr_a, &pk_arr_b, b"");
    assert_eq!(code.numeric.digits.len(), 60);
}

#[test]
fn verification_very_long_conversation_id() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();
    let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

    let conv = vec![b'x'; 65536];
    let code = generate_verification_code(&pk_arr_a, &pk_arr_b, &conv);
    assert_eq!(code.numeric.digits.len(), 60);
}

// ── MITM Detection Power ──────────────────────────────────────────────────

#[test]
fn verification_single_bit_flip_in_key_changes_code() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();

    let mut pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();
    let conv = b"conv";

    let code_base = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);

    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;

        pk_arr_a[byte_idx] ^= 1 << bit_idx;

        let code_mod = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);
        assert!(
            !verify_codes_match(&code_base, &code_mod),
            "A single bit flip must produce a completely different verification code"
        );

        // revert
        pk_arr_a[byte_idx] ^= 1 << bit_idx;
    }
}

#[test]
fn verification_hamming_distance_of_codes() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();

    let mut pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();
    let conv = b"conv";

    let code1 = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);

    pk_arr_a[0] ^= 0x01; // flip 1 bit
    let code2 = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);

    // Convert numeric to characters and measure difference
    let c1_chars: Vec<char> = code1.numeric.digits.chars().collect();
    let c2_chars: Vec<char> = code2.numeric.digits.chars().collect();

    let mut diff_count = 0;
    for i in 0..c1_chars.len() {
        if c1_chars[i] != c2_chars[i] {
            diff_count += 1;
        }
    }

    // Avalanche effect due to SHA-256 usually leads to ~50% different bits,
    // which in base 10 means roughly 90% different digits.
    assert!(
        diff_count >= 5,
        "Hamming distance must reflect strong avalanche effect (found diff: {})",
        diff_count
    );
}

// ── Format Validation ─────────────────────────────────────────────────────

#[test]
fn verification_numeric_format_all_decimal() {
    let conv = b"conv";
    for _ in 0..1000 {
        let (_, pk_a) = generate_ed25519_keypair();
        let (_, pk_b) = generate_ed25519_keypair();
        let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
        let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

        let code = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);
        assert!(code.numeric.digits.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(code.numeric.digits.len(), 60);
    }
}

#[test]
fn verification_emoji_all_in_palette() {
    let conv = b"conv";
    for _ in 0..1000 {
        let (_, pk_a) = generate_ed25519_keypair();
        let (_, pk_b) = generate_ed25519_keypair();
        let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
        let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

        let code = generate_verification_code(&pk_arr_a, &pk_arr_b, conv);

        for emoji in &code.emoji.emojis {
            assert!(
                EMOJI_PALETTE.contains(emoji),
                "Generated emoji must be within the predefined palette"
            );
        }
    }
}

#[test]
fn verification_numeric_groups_count_and_length() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();
    let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

    let code = generate_verification_code(&pk_arr_a, &pk_arr_b, b"conv");

    assert_eq!(
        code.numeric.groups.len(),
        12,
        "Must have exactly 12 numeric groups"
    );
    for g in &code.numeric.groups {
        assert_eq!(g.len(), 5, "Each numeric group must be exactly 5 digits");
    }
}

#[test]
fn verification_emoji_groups_count() {
    let (_, pk_a) = generate_ed25519_keypair();
    let (_, pk_b) = generate_ed25519_keypair();
    let pk_arr_a: [u8; 32] = pk_a.try_into().unwrap();
    let pk_arr_b: [u8; 32] = pk_b.try_into().unwrap();

    let code = generate_verification_code(&pk_arr_a, &pk_arr_b, b"conv");

    assert_eq!(
        code.emoji.groups.len(),
        4,
        "Must have exactly 4 emoji groups"
    );
    assert_eq!(
        code.emoji.emojis.len(),
        20,
        "Must have exactly 20 emojis total"
    );
}

// ── Timing ────────────────────────────────────────────────────────────────

#[test]
fn verification_fingerprint_rejects_every_mismatch_position() {
    let expected = [0xA5u8; 32];
    assert!(verify_fingerprints_match(&expected, &expected));

    for index in 0..expected.len() {
        let mut different = expected;
        different[index] ^= 1;
        assert!(
            !verify_fingerprints_match(&expected, &different),
            "Mismatch at byte {index} was accepted"
        );
    }
}
