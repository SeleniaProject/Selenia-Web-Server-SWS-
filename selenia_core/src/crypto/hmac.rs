//! Minimal HMAC-SHA256 (RFC 2104) implementation.

use super::sha256::sha256_digest;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];

    if key.len() > BLOCK {
        let digest = sha256_digest(key);
        for i in 0..BLOCK { ipad[i] ^= digest[i]; opad[i] ^= digest[i]; }
    } else {
        for (i,&b) in key.iter().enumerate() { ipad[i] ^= b; opad[i] ^= b; }
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256_digest(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256_digest(&outer)
} 