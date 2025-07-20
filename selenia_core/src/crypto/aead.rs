//! ChaCha20-Poly1305 AEAD (RFC 8439) implementation using internal cipher and MAC.
//! Only encryption (seal) and decryption (open) for TLS 1.3 usage.

use super::chacha20::chacha20_xor_in_place;
use super::poly1305::poly1305_tag;
use core::convert::TryInto;

/// Encrypt `plaintext` in place and return authentication tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> [u8; 16] {
    // 1. Derive Poly1305 key from ChaCha20 keystream with counter = 0
    let mut keystream_block = [0u8; 64]; // zero block
    chacha20_xor_in_place(key, nonce, 0, &mut keystream_block);
    let poly_key: [u8; 32] = keystream_block[..32].try_into().unwrap();

    // 2. Encrypt plaintext with counter = 1
    chacha20_xor_in_place(key, nonce, 1, plaintext);

    // 3. Build MAC data: AAD || pad16 || CIPHERTEXT || pad16 || lenA || lenC (each 8-byte LE)
    let mut mac_input = Vec::with_capacity(
        ((aad.len() + 15) / 16) * 16 + ((plaintext.len() + 15) / 16) * 16 + 16,
    );
    mac_input.extend_from_slice(aad);
    pad16(&mut mac_input);
    mac_input.extend_from_slice(plaintext);
    pad16(&mut mac_input);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());

    // 4. Compute Poly1305 tag
    poly1305_tag(&mac_input, &poly_key)
}

/// Decrypt `ciphertext` in place if tag is valid. Returns `true` on success.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &mut Vec<u8>, tag: &[u8; 16]) -> bool {
    // Derive Poly1305 key (counter 0)
    let mut keystream_block = [0u8; 64];
    chacha20_xor_in_place(key, nonce, 0, &mut keystream_block);
    let poly_key: [u8; 32] = keystream_block[..32].try_into().unwrap();

    // Build MAC data with ciphertext (unencrypted)
    let mut mac_input = Vec::with_capacity(
        ((aad.len() + 15) / 16) * 16 + ((ciphertext.len() + 15) / 16) * 16 + 16,
    );
    mac_input.extend_from_slice(aad);
    pad16(&mut mac_input);
    mac_input.extend_from_slice(ciphertext);
    pad16(&mut mac_input);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let expected_tag = poly1305_tag(&mac_input, &poly_key);
    if !constant_time_eq(tag, &expected_tag) {
        return false;
    }

    // Tag ok -> decrypt with counter 1
    chacha20_xor_in_place(key, nonce, 1, ciphertext);
    true
}

#[inline]
fn pad16(buf: &mut Vec<u8>) {
    let rem = buf.len() % 16;
    if rem != 0 {
        buf.extend(std::iter::repeat(0u8).take(16 - rem));
    }
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
} 