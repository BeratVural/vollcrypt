use bip39::{Language, Mnemonic};
use rand::{RngCore, thread_rng};

/// Generates a new random BIP39 mnemonic (24 words by default).
pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 32]; // 32 bytes = 256 bits = 24 words
    thread_rng().fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .expect("Entropy is exactly 32 bytes");
    mnemonic.to_string()
}

/// Converts a BIP39 mnemonic phrase to a 64-byte seed.
/// Returns an error if the phrase is invalid.
pub fn mnemonic_to_seed(phrase: &str, password: Option<&str>) -> Result<Vec<u8>, &'static str> {
    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, phrase) {
        Ok(m) => m,
        Err(_) => return Err("Invalid mnemonic phrase"),
    };

    // Generate the seed
    let seed = mnemonic.to_seed(password.unwrap_or(""));

    // Copy the bytes into a Vec so we can safely zeroize the original seed if necessary
    // Mnemonic/Seed from the `bip39` crate usually handle their own memory, but we can be explicit.
    Ok(seed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_restore() {
        let phrase = generate_mnemonic();
        assert_eq!(phrase.split_whitespace().count(), 24);

        let seed = mnemonic_to_seed(&phrase, None).unwrap();
        assert_eq!(seed.len(), 64);
    }
}
