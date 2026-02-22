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
}
