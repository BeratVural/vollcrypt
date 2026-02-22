use aes_kw::KekAes256;

/// Wraps a cryptographic key (e.g., DEK, SRK) using AES-256-KW.
/// The Key Encrypting Key (KEK) must be 32 bytes.
/// The `key_to_wrap` must be at least 16 bytes and a multiple of 8 bytes.
pub fn wrap_key(kek: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>, &'static str> {
    if kek.len() != 32 {
        return Err("KEK must be exactly 32 bytes");
    }
    if key_to_wrap.len() < 16 || key_to_wrap.len() % 8 != 0 {
        return Err("Key to wrap must be at least 16 bytes and a multiple of 8 bytes in length");
    }

    let mut kek_arr = [0u8; 32];
    kek_arr.copy_from_slice(kek);
    let kek_obj = KekAes256::from(kek_arr);

    kek_obj.wrap_vec(key_to_wrap).map_err(|_| "Failed to wrap key")
}

/// Unwraps a wrapped cryptographic key using AES-256-KW.
/// The Key Encrypting Key (KEK) must be 32 bytes.
pub fn unwrap_key(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if kek.len() != 32 {
        return Err("KEK must be exactly 32 bytes");
    }
    if wrapped_key.len() < 24 || wrapped_key.len() % 8 != 0 {
        return Err("Wrapped key must be at least 24 bytes and a multiple of 8 bytes in length");
    }

    let mut kek_arr = [0u8; 32];
    kek_arr.copy_from_slice(kek);
    let kek_obj = KekAes256::from(kek_arr);

    kek_obj.unwrap_vec(wrapped_key).map_err(|_| "Failed to unwrap key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap() {
        let kek = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let key_item = b"some_sensitive_key_material_32_b"; // 32 bytes
        
        let wrapped = wrap_key(kek, key_item).unwrap();
        assert_eq!(wrapped.len(), key_item.len() + 8); // AES-KW adds 8 bytes overhead

        let unwrapped = unwrap_key(kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key_item);
    }
}
