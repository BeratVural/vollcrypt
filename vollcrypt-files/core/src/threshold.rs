use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::FileFormatError;
use crate::keywrap::{aes256_kw_unwrap, aes256_kw_wrap};
use crate::wrap::WrapEntry;

/// A threshold secret share.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    #[zeroize(skip)]
    pub share_set_id: [u8; 16],
    #[zeroize(skip)]
    pub t: u8,
    #[zeroize(skip)]
    pub n: u8,
    #[zeroize(skip)]
    pub x: u8,
    pub y: [u8; 32],
}

/// Constant-time multiplication in GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        let mask = (b & 1).wrapping_neg();
        res ^= a & mask;
        let carry = (a >> 7).wrapping_neg();
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    res
}

/// Constant-time multiplicative inversion in GF(2^8) using Fermat's Little Theorem (b^254).
/// Returns 0 for 0, which is standard.
#[inline]
fn gf256_inv(b: u8) -> u8 {
    let p2 = gf256_mul(b, b);
    let p4 = gf256_mul(p2, p2);
    let p8 = gf256_mul(p4, p4);
    let p16 = gf256_mul(p8, p8);
    let p32 = gf256_mul(p16, p16);
    let p64 = gf256_mul(p32, p32);
    let p128 = gf256_mul(p64, p64);

    let mut res = p2;
    res = gf256_mul(res, p4);
    res = gf256_mul(res, p8);
    res = gf256_mul(res, p16);
    res = gf256_mul(res, p32);
    res = gf256_mul(res, p64);
    res = gf256_mul(res, p128);
    res
}

/// Splits a 32-byte Threshold Master Secret (TMS) into `n` shares with threshold `t`.
pub fn split_tms(
    tms: &[u8; 32],
    t: u8,
    n: u8,
) -> Result<([u8; 16], Vec<Share>), FileFormatError> {
    if t == 0 || n == 0 || t > n {
        return Err(FileFormatError::KdfParameterOutOfRange(
            "Invalid threshold parameters: t, n must be 1..=255 and t <= n".to_string(),
        ));
    }

    let mut share_set_id = [0u8; 16];
    OsRng.fill_bytes(&mut share_set_id);

    let mut shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        shares.push(Share {
            share_set_id,
            t,
            n,
            x,
            y: [0u8; 32],
        });
    }

    for k in 0..32 {
        let mut coeff = vec![0u8; t as usize];
        coeff[0] = tms[k];
        if t > 1 {
            OsRng.fill_bytes(&mut coeff[1..]);
        }

        for i in 0..(n as usize) {
            let x = (i + 1) as u8;
            let mut y_val = 0;
            for j in (0..t as usize).rev() {
                y_val = gf256_mul(y_val, x);
                y_val ^= coeff[j];
            }
            shares[i].y[k] = y_val;
        }

        coeff.zeroize();
    }

    Ok((share_set_id, shares))
}

/// Reconstructs the 32-byte TMS from a slice of shares using Lagrange interpolation at x=0.
pub fn reconstruct_tms(shares: &[Share]) -> Result<[u8; 32], FileFormatError> {
    if shares.is_empty() {
        return Err(FileFormatError::InvalidShare);
    }

    let t = shares[0].t;
    let n = shares[0].n;
    let share_set_id = shares[0].share_set_id;

    if shares.len() < t as usize {
        return Err(FileFormatError::InvalidShare);
    }

    let mut x_coords = Vec::with_capacity(shares.len());
    for share in shares {
        if share.share_set_id != share_set_id || share.t != t || share.n != n {
            return Err(FileFormatError::InvalidShare);
        }
        if share.x == 0 {
            return Err(FileFormatError::InvalidShare);
        }
        if x_coords.contains(&share.x) {
            return Err(FileFormatError::InvalidShare);
        }
        x_coords.push(share.x);
    }

    let mut tms = [0u8; 32];
    for k in 0..32 {
        let mut secret_byte = 0u8;
        for i in 0..shares.len() {
            let mut num = 1;
            let mut den = 1;
            for j in 0..shares.len() {
                if j == i {
                    continue;
                }
                num = gf256_mul(num, shares[j].x);
                den = gf256_mul(den, shares[j].x ^ shares[i].x);
            }
            if den == 0 {
                return Err(FileFormatError::InvalidShare);
            }
            let li = gf256_mul(num, gf256_inv(den));
            secret_byte ^= gf256_mul(shares[i].y[k], li);
        }
        tms[k] = secret_byte;
    }

    Ok(tms)
}

const BASE64URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
    let mut buffer = 0u32;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((buffer >> bits) & 0x3f) as usize;
            result.push(BASE64URL_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (6 - bits)) & 0x3f) as usize;
        result.push(BASE64URL_ALPHABET[idx] as char);
    }
    result
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, FileFormatError> {
    let mut result = Vec::with_capacity((s.len() * 3) / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in s.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => return Err(FileFormatError::InvalidShare),
        };
        buffer = ((buffer << 6) | val) & 0xffffff;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(result)
}

/// Encodes a share into a portable string format prefixed with `vcs_`.
pub fn encode_share(share: &Share) -> String {
    let mut payload = [0u8; 59];
    payload[0..4].copy_from_slice(b"VCS\x01");
    payload[4..20].copy_from_slice(&share.share_set_id);
    payload[20] = share.t;
    payload[21] = share.n;
    payload[22] = share.x;
    payload[23..55].copy_from_slice(&share.y);

    let mut hasher = Sha256::new();
    hasher.update(&payload[0..55]);
    let hash = hasher.finalize();
    payload[55..59].copy_from_slice(&hash[0..4]);

    let encoded = format!("vcs_{}", base64url_encode(&payload));
    payload.zeroize();
    encoded
}

/// Decodes a share from a portable string format.
pub fn decode_share(s: &str) -> Result<Share, FileFormatError> {
    if !s.starts_with("vcs_") {
        return Err(FileFormatError::InvalidShare);
    }
    let b64_part = &s[4..];
    let mut payload = base64url_decode(b64_part)?;
    if payload.len() != 59 {
        payload.zeroize();
        return Err(FileFormatError::InvalidShare);
    }

    if &payload[0..4] != b"VCS\x01" {
        payload.zeroize();
        return Err(FileFormatError::InvalidShare);
    }

    let mut hasher = Sha256::new();
    hasher.update(&payload[0..55]);
    let hash = hasher.finalize();
    if payload[55..59] != hash[0..4] {
        payload.zeroize();
        return Err(FileFormatError::InvalidShare);
    }

    let mut share_set_id = [0u8; 16];
    share_set_id.copy_from_slice(&payload[4..20]);

    let t = payload[20];
    let n = payload[21];
    let x = payload[22];

    if t == 0 || n == 0 || t > n || x == 0 || x > n {
        payload.zeroize();
        return Err(FileFormatError::InvalidShare);
    }

    let mut y = [0u8; 32];
    y.copy_from_slice(&payload[23..55]);

    payload.zeroize();

    Ok(Share {
        share_set_id,
        t,
        n,
        x,
        y,
    })
}

/// Derives a Key Encrypting Key (KEK) using HKDF-SHA256.
pub fn derive_threshold_kek(
    tms: &[u8; 32],
    file_id: &[u8; 16],
    share_set_id: &[u8; 16],
    t: u8,
    n: u8,
    cipher_suite_id: u8,
) -> Result<[u8; 32], FileFormatError> {
    let mut info = [0u8; 50];
    info[0..31].copy_from_slice(b"vollcrypt-file-threshold-kek-v1");
    info[31..47].copy_from_slice(share_set_id);
    info[47] = t;
    info[48] = n;
    info[49] = cipher_suite_id;

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(file_id), tms);
    let mut kek = [0u8; 32];
    hk.expand(&info, &mut kek).map_err(|_| {
        FileFormatError::IntegrityError("HKDF expansion failed for threshold KEK".to_string())
    })?;

    Ok(kek)
}

/// Generates a random TMS, splits it into shares, and wraps the DEK under KEK.
pub fn wrap_dek_with_threshold(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    t: u8,
    n: u8,
    cipher_suite_id: u8,
) -> Result<(WrapEntry, Vec<Share>), FileFormatError> {
    let mut tms = [0u8; 32];
    OsRng.fill_bytes(&mut tms);

    let (share_set_id, shares) = split_tms(&tms, t, n)?;

    let mut kek = derive_threshold_kek(&tms, file_id, &share_set_id, t, n, cipher_suite_id)?;
    let wrapped_dek = aes256_kw_wrap(&kek, dek);

    tms.zeroize();
    kek.zeroize();

    let entry = WrapEntry::Threshold {
        t,
        n,
        share_set_id,
        wrapped_dek,
    };

    Ok((entry, shares))
}

/// Unwraps the DEK using the threshold entry, file_id, and shares.
pub fn unwrap_dek_with_threshold(
    entry: &WrapEntry,
    file_id: &[u8; 16],
    shares: &[Share],
    cipher_suite_id: u8,
) -> Result<[u8; 32], FileFormatError> {
    match entry {
        WrapEntry::Threshold {
            t,
            n,
            share_set_id,
            wrapped_dek,
        } => {
            let mut tms = reconstruct_tms(shares)?;
            let mut kek = derive_threshold_kek(&tms, file_id, share_set_id, *t, *n, cipher_suite_id)?;

            let dek_res = aes256_kw_unwrap(&kek, wrapped_dek);

            tms.zeroize();
            kek.zeroize();

            dek_res
        }
        _ => Err(FileFormatError::WrongWrapType),
    }
}
