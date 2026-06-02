use vollcrypt_files_core::{
    decode_share, encode_share, generate_dek, generate_file_id, unwrap_dek_with_threshold,
    wrap_dek_with_threshold, FileFormatError, Share,
};
use zeroize::Zeroize;

#[test]
fn test_threshold_correctness_and_subsets() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let t = 3;
    let n = 5;
    let cipher_suite_id = 0;

    let (wrap, shares) =
        wrap_dek_with_threshold(&dek, &file_id, t, n, cipher_suite_id).unwrap();

    // Verify we got the correct number of shares
    assert_eq!(shares.len(), n as usize);

    // Let's test every subset of size t (3) out of n (5)
    // Combinations of size 3 from {0, 1, 2, 3, 4}
    let subsets = vec![
        vec![0, 1, 2],
        vec![0, 1, 3],
        vec![0, 1, 4],
        vec![0, 2, 3],
        vec![0, 2, 4],
        vec![0, 3, 4],
        vec![1, 2, 3],
        vec![1, 2, 4],
        vec![1, 3, 4],
        vec![2, 3, 4],
    ];

    for subset in subsets {
        let test_shares: Vec<Share> = subset.iter().map(|&idx| shares[idx].clone()).collect();
        let unwrapped =
            unwrap_dek_with_threshold(&wrap, &file_id, &test_shares, cipher_suite_id).unwrap();
        assert_eq!(dek, unwrapped);
    }

    // Try with all 5 shares (more than t)
    let unwrapped_all =
        unwrap_dek_with_threshold(&wrap, &file_id, &shares, cipher_suite_id).unwrap();
    assert_eq!(dek, unwrapped_all);
}

#[test]
fn test_threshold_security_limits() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let t = 3;
    let n = 5;
    let cipher_suite_id = 0;

    let (wrap, shares) =
        wrap_dek_with_threshold(&dek, &file_id, t, n, cipher_suite_id).unwrap();

    // Verify that any subset of size t-1 (2) fails to unwrap
    let subsets_insufficient = vec![
        vec![0, 1],
        vec![0, 2],
        vec![1, 2],
        vec![2, 3],
        vec![3, 4],
    ];

    for subset in subsets_insufficient {
        let test_shares: Vec<Share> = subset.iter().map(|&idx| shares[idx].clone()).collect();
        let res = unwrap_dek_with_threshold(&wrap, &file_id, &test_shares, cipher_suite_id);
        assert!(res.is_err());
    }

    // Test with a single share
    let res_single = unwrap_dek_with_threshold(&wrap, &file_id, &[shares[0].clone()], cipher_suite_id);
    assert!(res_single.is_err());

    // Test with empty shares
    let res_empty = unwrap_dek_with_threshold(&wrap, &file_id, &[], cipher_suite_id);
    assert!(res_empty.is_err());
}

#[test]
fn test_share_encoding_decoding_roundtrip() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let t = 2;
    let n = 3;

    let (_, shares) = wrap_dek_with_threshold(&dek, &file_id, t, n, 0).unwrap();

    for share in &shares {
        let encoded = encode_share(share);
        assert!(encoded.starts_with("vcs_"));

        let decoded = decode_share(&encoded).unwrap();
        assert_eq!(share.share_set_id, decoded.share_set_id);
        assert_eq!(share.t, decoded.t);
        assert_eq!(share.n, decoded.n);
        assert_eq!(share.x, decoded.x);
        assert_eq!(share.y, decoded.y);
    }
}

#[test]
fn test_share_tampering() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let t = 2;
    let n = 3;

    let (wrap, shares) = wrap_dek_with_threshold(&dek, &file_id, t, n, 0).unwrap();

    // Case 1: Corrupted share string (typo/bit flip in base64url string)
    let share_str = encode_share(&shares[0]);
    let mut chars: Vec<char> = share_str.chars().collect();
    // Swap a character to simulate corruption (checksum fails)
    let last_idx = chars.len() - 1;
    let original_char = chars[last_idx];
    chars[last_idx] = if original_char == 'A' { 'B' } else { 'A' };
    let corrupted_str: String = chars.into_iter().collect();

    let decode_res = decode_share(&corrupted_str);
    assert!(matches!(decode_res, Err(FileFormatError::InvalidShare)));

    // Case 2: Modified coordinate byte in decoded Share (fails unwrap/integrity check)
    let mut tampered_share = shares[0].clone();
    tampered_share.y[0] ^= 1; // Flip a bit in the share y-value
    let test_shares = vec![tampered_share, shares[1].clone()];

    let unwrap_res = unwrap_dek_with_threshold(&wrap, &file_id, &test_shares, 0);
    assert!(unwrap_res.is_err());
}

#[test]
fn test_mismatched_share_sets() {
    let dek = generate_dek();
    let file_id = generate_file_id();

    // Generate two independent sets
    let (wrap1, shares1) = wrap_dek_with_threshold(&dek, &file_id, 2, 3, 0).unwrap();
    let (_, shares2) = wrap_dek_with_threshold(&dek, &file_id, 2, 3, 0).unwrap();

    // Mix share from set 2 into set 1
    let mixed_shares = vec![shares1[0].clone(), shares2[1].clone()];
    let res = unwrap_dek_with_threshold(&wrap1, &file_id, &mixed_shares, 0);
    // Since share_set_id mismatch, reconstruct_tms rejects immediately
    assert!(matches!(res, Err(FileFormatError::InvalidShare)));
}

#[test]
fn test_duplicate_shares() {
    let dek = generate_dek();
    let file_id = generate_file_id();

    let (wrap, shares) = wrap_dek_with_threshold(&dek, &file_id, 2, 3, 0).unwrap();

    // Use duplicate share (same x coordinate)
    let dup_shares = vec![shares[0].clone(), shares[0].clone()];
    let res = unwrap_dek_with_threshold(&wrap, &file_id, &dup_shares, 0);
    // Reconstructor rejects duplicate coordinates
    assert!(matches!(res, Err(FileFormatError::InvalidShare)));
}

#[test]
fn test_parameter_bounds() {
    let dek = generate_dek();
    let file_id = generate_file_id();

    // t = 0 invalid
    let res_t0 = wrap_dek_with_threshold(&dek, &file_id, 0, 3, 0);
    assert!(matches!(res_t0, Err(FileFormatError::KdfParameterOutOfRange(_))));

    // t > n invalid
    let res_t_gt_n = wrap_dek_with_threshold(&dek, &file_id, 4, 3, 0);
    assert!(matches!(res_t_gt_n, Err(FileFormatError::KdfParameterOutOfRange(_))));

    // t = 1 is allowed
    let res_t1 = wrap_dek_with_threshold(&dek, &file_id, 1, 3, 0);
    assert!(res_t1.is_ok());
    let (wrap, shares) = res_t1.unwrap();
    let unwrapped = unwrap_dek_with_threshold(&wrap, &file_id, &[shares[0].clone()], 0).unwrap();
    assert_eq!(dek, unwrapped);
}

#[test]
fn test_share_zeroization() {
    let mut share = Share {
        share_set_id: [1u8; 16],
        t: 2,
        n: 3,
        x: 1,
        y: [0xff; 32],
    };

    share.zeroize();
    assert_eq!(share.y, [0u8; 32]);
}
