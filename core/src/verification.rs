use sha2::{Sha256, Digest};
use serde::Serialize;

/// Numeric representation of the verification code.
/// 60 digits, in 12 groups (5 digits each), separated by spaces.
/// Example: "25437 81920 34521 09876 54321 12345 67890 24680 13579 86420 11223 34455"
#[derive(Debug, Clone, Serialize)]
pub struct NumericVerificationCode {
    /// Raw 60 digits (no spaces)
    pub digits: String,
    /// Grouped representation (for display)
    pub formatted: String,
    /// 12 groups of 5 digits
    pub groups: Vec<String>,
}

/// Emoji representation of the verification code.
/// 20 emojis, in 4 groups (5 emojis each), separated by spaces.
/// Example: "🔥💧🌊⚡🎯 🦋🌸🍀🌙☀️ 🎵🎸🎹🎺🎻 🦁🐯🐻🦊🐺"
#[derive(Debug, Clone, Serialize)]
pub struct EmojiVerificationCode {
    /// Raw 20 emojis (no spaces)
    pub emojis: Vec<&'static str>,
    /// Grouped representation (for display)
    pub formatted: String,
    /// 4 groups of 5 emojis
    pub groups: Vec<String>,
}

/// Verification code in both formats.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationCode {
    pub numeric: NumericVerificationCode,
    pub emoji:   EmojiVerificationCode,
    /// Raw 32-byte fingerprint (for high-level use)
    pub fingerprint: [u8; 32],
}

/// 64-element emoji palette. Index = 6-bit value (0-63).
/// Selection criteria:
///   - Platform independent appearance (Apple, Google, Windows)
///   - Easily distinguishable from each other
///   - Culturally neutral
pub const EMOJI_PALETTE: [&str; 64] = [
    "🔥", "💧", "🌊", "⚡", "🎯", "🦋", "🌸", "🍀",
    "🌙", "☀️", "🎵", "🎸", "🎹", "🎺", "🎻", "🦁",
    "🐯", "🐻", "🦊", "🐺", "🌵", "🍄", "🌴", "🌺",
    "🍁", "❄️", "🌈", "🔮", "💎", "🗝️", "⚓", "🧭",
    "🏔️", "🌋", "🏝️", "🌌", "🎃", "🎄", "🎋", "🎍",
    "🎐", "🎑", "🎀", "🎁", "🎈", "🎉", "🎊", "🎠",
    "🚀", "🛸", "⛵", "🚂", "🏆", "🥇", "🎲", "�",
    "🧩", "🎭", "🎨", "🖼️", "📿", "🧿", "🪬", "🔑",
];

/// Generates a verification code from two users' public keys.
///
/// The function is symmetric and deterministic:
/// generate(alice_pk, bob_pk, conv_id) == generate(bob_pk, alice_pk, conv_id)
/// This ensures that both parties produce the same code regardless of who calculates it.
///
/// # Arguments
/// * `key_a`            — First user's Ed25519 public key (32 bytes)
/// * `key_b`            — Second user's Ed25519 public key (32 bytes)
/// * `conversation_id`  — Conversation identifier (context, replay protection)
///
/// # Symmetry Guarantee
/// key_a and key_b are unordered: before SHA-256 calculation,
/// the two keys are sorted lexicographically.
/// Thus, Alice and Bob will derive the same fingerprint.
pub fn generate_verification_code(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    conversation_id: &[u8],
) -> VerificationCode {
    let fingerprint = compute_fingerprint(key_a, key_b, conversation_id);
    let numeric = fingerprint_to_numeric(&fingerprint);
    let emoji = fingerprint_to_emoji(&fingerprint);

    VerificationCode {
        numeric,
        emoji,
        fingerprint,
    }
}

/// Generates only the raw fingerprint (32 bytes).
/// Used inside generate_verification_code().
/// Also exposed for high-level usage.
///
/// fingerprint = SHA-256(
///   "vollchat-key-verification-v1" ||
///   min(key_a, key_b) ||   ← lexicographically smaller first
///   max(key_a, key_b) ||
///   conversation_id
/// )
pub fn compute_fingerprint(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    conversation_id: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vollchat-key-verification-v1");

    // Lexicographical sort (for symmetry)
    if key_a < key_b {
        hasher.update(key_a);
        hasher.update(key_b);
    } else {
        hasher.update(key_b);
        hasher.update(key_a);
    }

    hasher.update(conversation_id);
    hasher.finalize().into()
}

/// Generates a numeric verification code from the fingerprint.
///
/// Algorithm:
/// 1. fingerprint (32 bytes = 256 bits)
/// 2. Map every 5 bits → 0-99999 range (256 bits / ~4.4 bits/digit ≈ 60 digits)
///    Simpler way: every byte pair (2 bytes = 16 bits) → 5 digits (00000-65535, mod 100000)
///    16 bytes → 8 groups × 5 digits = 40 digits... 
///    32 bytes → every 2 bytes = 1 group: 16 groups × 4 digits (0000-9999) = 64 digits → take 60
///
///    Exact algorithm:
///    - fingerprint[0..30] → 15 chunks of 2 bytes
///    - Each chunk: u16::from_be_bytes % 100000 → 5 digits (zero-padded)
///    - Total: 15 × 5 = 75 digits → take first 60
///    - groups: split 60 digits into 12 groups (5 digits each)
pub fn fingerprint_to_numeric(fingerprint: &[u8; 32]) -> NumericVerificationCode {
    let mut digits = String::with_capacity(75);
    
    // Create 15 chunks of 2 bytes using 30 bytes
    for i in 0..15 {
        let chunk_bytes = [fingerprint[2*i], fingerprint[2*i+1]];
        let chunk_val = u16::from_be_bytes(chunk_bytes);
        // Reduce to 0-99999 range
        let val = (chunk_val as u32) % 100000;
        // 5 digits, zero-padded
        digits.push_str(&format!("{:05}", val));
    }

    // Take the first 60 digits
    let digits = digits[..60].to_string();
    
    // Group (12 groups, 5 digits each)
    let mut groups = Vec::new();
    for i in 0..12 {
        groups.push(digits[i*5..(i+1)*5].to_string());
    }

    let formatted = groups.join(" ");

    NumericVerificationCode {
        digits,
        formatted,
        groups,
    }
}

/// Generates an emoji verification code from the fingerprint.
///
/// Algorithm:
/// 1. fingerprint (32 bytes = 256 bits)
/// 2. Every 6 bits → EMOJI_PALETTE[index] (0-63)
///    256 bits / 6 bits = 42 emojis (42 × 6 = 252 bits, 4 bits discarded)
///    Take first 20 emojis
/// 3. groups: split 20 emojis into 4 groups (5 emojis each)
pub fn fingerprint_to_emoji(fingerprint: &[u8; 32]) -> EmojiVerificationCode {
    let mut emojis = Vec::new();
    
    // Process as bit stream
    // Total 256 bits. One emoji for every 6 bits.
    // 20 emojis * 6 bits = 120 bits. (First 15 bytes are sufficient)
    
    // Simple bit reading logic:
    // 32 bytes = 256 bits
    // Bit range for i-th emoji: [i*6 .. i*6+6]
    
    for i in 0..20 {
        let bit_offset = i * 6;
        let byte_index = bit_offset / 8;
        let bit_index = bit_offset % 8; // start bit within byte (MSB=0)
        
        // We might need to read at least 2 bytes (if straddling boundary)
        // fingerprint[byte_index] and fingerprint[byte_index+1]
        
        let b0 = fingerprint[byte_index];
        let b1 = if byte_index + 1 < 32 { fingerprint[byte_index + 1] } else { 0 };
        
        // 16-bit window: [b0][b1]
        let word = ((b0 as u16) << 8) | (b1 as u16);
        
        // Extract relevant 6 bits.
        // Shift amount = 16 - 6 - bit_index = 10 - bit_index
        let shift = 10 - bit_index;
        let index = (word >> shift) & 0x3F; // 6-bit mask (63)
        
        emojis.push(EMOJI_PALETTE[index as usize]);
    }

    // Group (4 groups, 5 emojis each)
    let mut groups = Vec::new();
    for chunk in emojis.chunks(5) {
        groups.push(chunk.join("")); // Emojis are adjacent, groups separated by space
    }

    let formatted = groups.join(" ");

    EmojiVerificationCode {
        emojis,
        formatted,
        groups,
    }
}

/// Timing-safe comparison to check if two verification codes match.
/// Compares via fingerprint — format (numeric/emoji) does not matter.
pub fn verify_codes_match(a: &VerificationCode, b: &VerificationCode) -> bool {
    use subtle::ConstantTimeEq;
    a.fingerprint.ct_eq(&b.fingerprint).into()
}

/// Only fingerprint comparison (for raw byte array).
pub fn verify_fingerprints_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ed25519_keypair;
    use std::convert::TryInto;

    fn get_keypair() -> ([u8; 32], [u8; 32]) {
        let (sk, pk) = generate_ed25519_keypair();
        let sk_arr: [u8; 32] = sk.try_into().expect("Secret key must be 32 bytes");
        let pk_arr: [u8; 32] = pk.try_into().expect("Public key must be 32 bytes");
        (sk_arr, pk_arr)
    }

    #[test]
    fn test_symmetric_property() {
        // generate(alice, bob) == generate(bob, alice)
        // Same code regardless of which party calculates it
        let alice = get_keypair();
        let bob   = get_keypair();
        let conv  = b"conv-001";

        let code_ab = generate_verification_code(&alice.1, &bob.1, conv);
        let code_ba = generate_verification_code(&bob.1, &alice.1, conv);

        assert_eq!(code_ab.fingerprint, code_ba.fingerprint,
            "Alice->Bob and Bob->Alice must produce the same code");
        assert_eq!(code_ab.numeric.digits, code_ba.numeric.digits);
        assert_eq!(code_ab.emoji.formatted, code_ba.emoji.formatted);
    }

    #[test]
    fn test_different_keys_different_codes() {
        let alice   = get_keypair();
        let bob     = get_keypair();
        let mallory = get_keypair();
        let conv = b"conv-001";

        let code_real  = generate_verification_code(&alice.1, &bob.1, conv);
        let code_mitm  = generate_verification_code(&alice.1, &mallory.1, conv);

        assert_ne!(code_real.fingerprint, code_mitm.fingerprint,
            "Different keys (MITM) must produce different codes");
    }

    #[test]
    fn test_deterministic() {
        // Same inputs must always produce the same code
        let alice = get_keypair();
        let bob   = get_keypair();
        let conv  = b"conv-001";

        let code1 = generate_verification_code(&alice.1, &bob.1, conv);
        let code2 = generate_verification_code(&alice.1, &bob.1, conv);

        assert_eq!(code1.fingerprint, code2.fingerprint);
        assert_eq!(code1.numeric.formatted, code2.numeric.formatted);
    }

    #[test]
    fn test_different_conversation_different_codes() {
        // Same key pair, different conversation -> different code
        // (Code from one conversation cannot be ported to another)
        let alice = get_keypair();
        let bob   = get_keypair();

        let code_c1 = generate_verification_code(&alice.1, &bob.1, b"conv-001");
        let code_c2 = generate_verification_code(&alice.1, &bob.1, b"conv-002");

        assert_ne!(code_c1.fingerprint, code_c2.fingerprint,
            "Different conversation ID must produce different codes");
    }

    #[test]
    fn test_numeric_code_format() {
        let alice = get_keypair();
        let bob   = get_keypair();
        let code  = generate_verification_code(&alice.1, &bob.1, b"conv");

        // 60 digits (no spaces)
        assert_eq!(code.numeric.digits.len(), 60,
            "Numeric code must contain 60 digits");

        // All characters are digits
        assert!(code.numeric.digits.chars().all(|c| c.is_ascii_digit()),
            "All characters must be digits");

        // 12 groups * 5 digits
        assert_eq!(code.numeric.groups.len(), 12);
        for group in &code.numeric.groups {
            assert_eq!(group.len(), 5, "Each group must be 5 digits");
        }
    }

    #[test]
    fn test_emoji_code_format() {
        let alice = get_keypair();
        let bob   = get_keypair();
        let code  = generate_verification_code(&alice.1, &bob.1, b"conv");

        // 20 emojis
        assert_eq!(code.emoji.emojis.len(), 20,
            "Emoji code must contain 20 emojis");

        // 4 groups * 5 emojis
        assert_eq!(code.emoji.groups.len(), 4);
        
        // Check total length via emojis vector
        assert_eq!(code.emoji.emojis.len(), 20);
    }

    #[test]
    fn test_verify_codes_match_positive() {
        let alice = get_keypair();
        let bob   = get_keypair();
        let conv  = b"conv-001";

        let code_alice = generate_verification_code(&alice.1, &bob.1, conv);
        let code_bob   = generate_verification_code(&bob.1, &alice.1, conv);

        assert!(verify_codes_match(&code_alice, &code_bob),
            "Codes must match for the same key pair");
    }

    #[test]
    fn test_verify_codes_match_negative() {
        let alice   = get_keypair();
        let bob     = get_keypair();
        let mallory = get_keypair();

        let code_real = generate_verification_code(&alice.1, &bob.1, b"conv");
        let code_fake = generate_verification_code(&alice.1, &mallory.1, b"conv");

        assert!(!verify_codes_match(&code_real, &code_fake),
            "Different key pairs must not match");
    }

    #[test]
    fn test_emoji_palette_no_duplicates() {
        // Dictionary must not contain duplicates
        let mut seen = std::collections::HashSet::new();
        for emoji in EMOJI_PALETTE.iter() {
            assert!(seen.insert(*emoji),
                "Duplicate found in emoji dictionary: {}", emoji);
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn test_same_key_pair_different_length_conversation_ids() {
        // Different length conversation_ids must work consistently
        let alice = get_keypair();
        let bob   = get_keypair();

        let code_short = generate_verification_code(&alice.1, &bob.1, b"a");
        let code_long  = generate_verification_code(&alice.1, &bob.1, b"a-very-long-conversation-id-string");

        // Both are valid (no panic, correct format)
        assert_eq!(code_short.numeric.digits.len(), 60);
        assert_eq!(code_long.numeric.digits.len(), 60);
        // And produce different codes
        assert_ne!(code_short.fingerprint, code_long.fingerprint);
    }
}
