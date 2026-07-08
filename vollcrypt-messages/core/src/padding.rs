use rand::{RngCore, rngs::OsRng};

/// Calculates deterministic padding for a given content length.
/// Target sizes are predefined buckets: 64, 128, 256, 512, 1024, 2048.
/// If content exceeds 2048, it rounds up to the next multiple of 1024.
/// Returns the random padding bytes to append.
pub fn calculate_padding(content_len: usize) -> Vec<u8> {
    let sizes = [64, 128, 256, 512, 1024, 2048];
    let min_padding = 2;

    let target = sizes
        .iter()
        .find(|&&s| s >= content_len + min_padding)
        .copied()
        .unwrap_or_else(|| {
            // If larger than all predefined sizes, round to next multiple of 1024
            let remainder = (content_len + min_padding) % 1024;
            if remainder == 0 {
                content_len + min_padding
            } else {
                content_len + min_padding + (1024 - remainder)
            }
        });

    let padding_len = target - content_len;
    let mut padding = vec![0u8; padding_len];
    OsRng.fill_bytes(&mut padding);
    padding
}

/// Helper function to randomly pad a message slice and return the padded vector.
pub fn pad_message(content: &[u8]) -> Vec<u8> {
    let padding_bytes = calculate_padding(content.len());
    let mut padded_content = Vec::with_capacity(content.len() + padding_bytes.len());
    padded_content.extend_from_slice(content);
    padded_content.extend_from_slice(&padding_bytes);
    padded_content
}

pub fn pad_message_with_len(content: &[u8]) -> Result<Vec<u8>, &'static str> {
    const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024; // 64 MB maximum
    if content.len() > MAX_PAYLOAD_SIZE {
        return Err("Message exceeds maximum allowed payload size");
    }
    let len_bytes = (content.len() as u32).to_be_bytes();
    let base_len = 4 + content.len();
    let padding_bytes = calculate_padding(base_len);
    let capacity = base_len
        .checked_add(padding_bytes.len())
        .ok_or("Padding calculations caused overflow")?;
    let mut padded = Vec::with_capacity(capacity);
    padded.extend_from_slice(&len_bytes);
    padded.extend_from_slice(content);
    padded.extend_from_slice(&padding_bytes);
    Ok(padded)
}

pub fn unpad_message_with_len(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if padded.len() < 4 {
        return Err("Padded message too short");
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > padded.len() - 4 {
        return Err("Invalid padded message length");
    }
    Ok(padded[4..4 + len].to_vec())
}

/// Checks if a length matches a valid padded block size.
pub fn is_valid_padded_len(len: usize) -> bool {
    let sizes = [64, 128, 256, 512, 1024, 2048];
    if len <= 2048 {
        sizes.contains(&len)
    } else {
        len % 1024 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_padding() {
        assert_eq!(calculate_padding(10).len(), 54); // 64 - 10
        assert_eq!(calculate_padding(63).len(), 65); // 128 - 63 (because 63 + 2 > 64)
        assert_eq!(calculate_padding(2000).len(), 48); // 2048 - 2000
        assert_eq!(calculate_padding(2050).len(), 1022); // Target: 3072, Padding: 1022
    }

    #[test]
    fn test_pad_unpad_with_len_roundtrip() {
        let msg = b"hello padding";
        let padded = pad_message_with_len(msg).unwrap();
        let unpadded = unpad_message_with_len(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn test_unpad_with_len_invalid() {
        assert!(unpad_message_with_len(b"").is_err());
        assert!(unpad_message_with_len(&[0, 0, 0, 5, 1, 2]).is_err());
    }
}
