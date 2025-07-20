//! AES-128-GCM implementation (RFC 5116) with software GHASH and AES-NI-assisted cipher.
//! Supports 96-bit nonce (recommended) and 128-bit tag size.

use super::aes::aes128_encrypt_block;

#[inline]
fn inc32(counter: &mut [u8; 16]) {
    let mut n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    n = n.wrapping_add(1);
    let be = n.to_be_bytes();
    counter[12..].copy_from_slice(&be);
}

#[inline]
fn to_u128_be(bytes: &[u8; 16]) -> u128 { u128::from_be_bytes(*bytes) }
#[inline]
fn from_u128_be(x: u128) -> [u8; 16] { x.to_be_bytes() }

/// GF(2^128) multiplication as defined by GHASH (little-endian polynomial basis).
fn gf_mul(mut x: u128, mut y: u128) -> u128 {
    let mut z = 0u128;
    for _ in 0..128 {
        if (y & 1) != 0 { z ^= x; }
        let carry = x & 1;
        x >>= 1;
        if carry != 0 { x ^= 0xe1 << 120; }
        y >>= 1;
    }
    z
}

fn ghash(h: u128, data: &[u8]) -> u128 {
    let mut y = 0u128;
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        y ^= to_u128_be(&block);
        y = gf_mul(y, h);
    }
    y
}

/// Encrypt `plaintext` (in place) producing authentication tag.
pub fn seal(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> [u8; 16] {
    // 1. Generate hash subkey H = AES_K(0^128)
    let mut zero_block = [0u8; 16];
    aes128_encrypt_block(key, &mut zero_block);
    let h = to_u128_be(&zero_block);

    // 2. Compute J0 = IV || 0x00000001
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 1;

    // 3. Encrypt plaintext (CTR mode starting with counter=1)
    let mut ctr_block = counter;
    inc32(&mut ctr_block); // counter = 1
    for chunk in plaintext.chunks_mut(16) {
        let mut keystream = ctr_block;
        aes128_encrypt_block(key, &mut keystream);
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) { *b ^= k; }
        inc32(&mut ctr_block);
    }

    // 4. Build GHASH input: AAD || pad || CIPHERTEXT || pad || lenAAD(64) || lenC(64)
    let aad_len_bits = (aad.len() as u64) * 8;
    let txt_len_bits = (plaintext.len() as u64) * 8;
    let mut gbuf = Vec::with_capacity(aad.len() + plaintext.len() + 32);
    gbuf.extend_from_slice(aad);
    while gbuf.len() % 16 != 0 { gbuf.push(0); }
    gbuf.extend_from_slice(plaintext);
    while gbuf.len() % 16 != 0 { gbuf.push(0); }
    gbuf.extend_from_slice(&aad_len_bits.to_be_bytes());
    gbuf.extend_from_slice(&txt_len_bits.to_be_bytes());
    let s = ghash(h, &gbuf);

    // 5. Tag = AES_K(J0) XOR S
    let mut j0_enc = counter;
    aes128_encrypt_block(key, &mut j0_enc);
    let tag = to_u128_be(&j0_enc) ^ s;
    from_u128_be(tag)
}

/// Decrypt in place, verifying tag. Returns `true` if authentication succeeds.
pub fn open(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], ciphertext: &mut Vec<u8>, tag: &[u8; 16]) -> bool {
    // H
    let mut zero_block = [0u8; 16];
    aes128_encrypt_block(key, &mut zero_block);
    let h = to_u128_be(&zero_block);

    // J0
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 1;

    // GHASH over AAD || CIPHERTEXT
    let aad_len_bits = (aad.len() as u64) * 8;
    let txt_len_bits = (ciphertext.len() as u64) * 8;
    let mut gbuf = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    gbuf.extend_from_slice(aad);
    while gbuf.len() % 16 != 0 { gbuf.push(0); }
    gbuf.extend_from_slice(ciphertext);
    while gbuf.len() % 16 != 0 { gbuf.push(0); }
    gbuf.extend_from_slice(&aad_len_bits.to_be_bytes());
    gbuf.extend_from_slice(&txt_len_bits.to_be_bytes());
    let s = ghash(h, &gbuf);

    let mut j0_enc = counter;
    aes128_encrypt_block(key, &mut j0_enc);
    let expected_tag = to_u128_be(&j0_enc) ^ s;
    if expected_tag != to_u128_be(tag) { return false; }

    // Authentication passed – decrypt CTR mode
    let mut ctr_block = counter;
    inc32(&mut ctr_block);
    for chunk in ciphertext.chunks_mut(16) {
        let mut keystream = ctr_block;
        aes128_encrypt_block(key, &mut keystream);
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) { *b ^= k; }
        inc32(&mut ctr_block);
    }
    true
} 