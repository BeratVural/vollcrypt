use crate::wrap::{unwrap_key, wrap_key};

#[test]
fn aes_kw_empty_key_to_wrap() {
    let kek = [0u8; 32];
    let result = wrap_key(&kek, &[]);
    assert!(result.is_err(), "Empty key to wrap must fail");
}

#[test]
fn aes_kw_wrong_wrapping_key_length() {
    let kek = [0u8; 16]; // 16 bytes instead of 32
    let item = [0x42u8; 32];
    let result = wrap_key(&kek, &item);
    assert!(result.is_err(), "KEK < 32 bytes must fail");
}

#[test]
fn aes_kw_wrong_unwrapping_key() {
    let kek1 = [0x11u8; 32];
    let kek2 = [0x22u8; 32];
    let item = [0x42u8; 32];
    
    let wrapped = wrap_key(&kek1, &item).unwrap();
    let result = unwrap_key(&kek2, &wrapped);
    
    assert!(result.is_err(), "Unwrapping with wrong KEK must fail");
}

#[test]
fn aes_kw_corrupted_wrapped_key_1_bit() {
    let kek = [0x11u8; 32];
    let item = [0x42u8; 32];
    
    let mut wrapped = wrap_key(&kek, &item).unwrap();
    wrapped[5] ^= 0x01;
    
    let result = unwrap_key(&kek, &wrapped);
    assert!(result.is_err(), "Tampered wrapped key must fail authentication");
}

#[test]
fn aes_kw_truncated_wrapped_key() {
    let kek = [0x11u8; 32];
    let item = [0x42u8; 32];
    
    let mut wrapped = wrap_key(&kek, &item).unwrap();
    for _ in 0..8 {
        wrapped.pop(); // Remove the last 8 byte block
    }
    
    let result = unwrap_key(&kek, &wrapped);
    assert!(result.is_err(), "Truncated wrapped key must fail");
}

#[test]
fn aes_kw_non_multiple_of_8_bytes() {
    let kek = [0x11u8; 32];
    let item = [0x42u8; 33]; // Not a multiple of 8
    
    let result = wrap_key(&kek, &item);
    assert!(result.is_err(), "Must reject input length that is not a multiple of 8 bytes for AES-KW");
}
