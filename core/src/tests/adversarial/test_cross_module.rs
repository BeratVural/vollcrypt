use crate::kdf::derive_window_key;
use crate::symmetric::{encrypt_aes256gcm, decrypt_aes256gcm};

#[test]
fn cross_use_srk_as_window_key() {
    let srk = [0x55u8; 32];
    let window_index = 1;
    let window_key = derive_window_key(&srk, window_index).unwrap();
    
    // SRK and Window Key should be distinct
    assert_ne!(&srk[..], window_key.as_slice(), "SRK and derived window key must not be exactly the same");
    
    let plaintext = b"secret message";
    let encrypted_with_window = encrypt_aes256gcm(&window_key, plaintext, None).unwrap();
    
    // Try decrypting with SRK instead of window key
    let decrypt_attempt = decrypt_aes256gcm(&srk, &encrypted_with_window, None);
    assert!(decrypt_attempt.is_err(), "Must fail to decrypt if the raw SRK is mistakenly used instead of the derived Window Key");
}
