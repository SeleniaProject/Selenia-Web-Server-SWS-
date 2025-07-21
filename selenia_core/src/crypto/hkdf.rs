//! HKDF-SHA256 (RFC 5869) extract / expand.
//! Uses builtin HMAC-SHA256 implementation.

use super::hmac::hmac_sha256;

pub struct HkdfSha256 {
    prk: [u8;32],
}

/// Shortcut helper matching TLS 1.3 semantics: returns PRK array.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8;32] {
    hmac_sha256(if salt.is_empty(){&[0u8;32]}else{salt}, ikm)
}

/// HKDF-Expand-Label used in TLS 1.3.
/// label = "tls13 " || label
pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    assert_eq!(secret.len(), 32, "HKDF secret must be 32 bytes");
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&secret[..32]);

    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    HkdfSha256 { prk }.expand(&info, out_len)
}

impl HkdfSha256 {
    /// HKDF-Extract(salt, ikm)
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let prk = hmac_sha256(if salt.is_empty(){&[0u8;32]}else{salt}, ikm);
        HkdfSha256{prk}
    }

    /// HKDF-Expand(prk, info, length)
    pub fn expand(&self, info: &[u8], out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len);
        let n = (out_len+31)/32; // number of hash blocks
        let mut prev: Vec<u8> = Vec::new();
        for i in 1..=n {
            let mut data = Vec::with_capacity(prev.len()+info.len()+1);
            data.extend_from_slice(&prev);
            data.extend_from_slice(info);
            data.push(i as u8);
            prev = hmac_sha256(&self.prk, &data).to_vec();
            out.extend_from_slice(&prev);
        }
        out.truncate(out_len);
        out
    }
} 