use bip39::{Language, Mnemonic};
use rand::{RngCore, rngs::OsRng};

/// Generates a new random BIP39 mnemonic (24 words by default).
pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 32]; // 32 bytes = 256 bits = 24 words
    OsRng.fill_bytes(&mut entropy);

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

    #[test]
    fn test_official_vector_with_passphrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, Some("TREZOR")).unwrap();
        assert_eq!(
            seed.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            concat!(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553",
                "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
        );
    }

    #[test]
    fn test_invalid_checksum_is_rejected() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(mnemonic_to_seed(phrase, None).is_err());
    }
}
