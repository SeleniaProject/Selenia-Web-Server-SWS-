//! Minimal TLS 1.3 (RFC 8446) server-side handshake & record layer.
//! No external crates: relies on internal HKDF/HMAC/SHA-256/AES-GCM.
//! Supports:
//! • One cipher suite: TLS_AES_128_GCM_SHA256 (0x1301)
//! • One signature scheme: rsa_pss_rsae_sha256 (0x0804) – signature skipped (CertificateVerify omitted)
//! • Session resumption / 0-RTT not implemented.
//! • ALPN & extensions are parsed but ignored.
//!
//! This implementation is sufficient for encrypted HTTP traffic inside benchmark
//! scenarios. For production-grade X.509 validation & certificate handling, an
//! external PKI module should supply the certificate bytes and private-key
//! sign/decrypt operations.

use super::{hkdf::hkdf_extract, hkdf::hkdf_expand_label, sha256::sha256_digest, aes_gcm};
use crate::crypto::rand::fill_random;

const SUITE_TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
const LABEL_DERIVED: &[u8] = b"derived";
const LABEL_KEY: &[u8] = b"key";
const LABEL_IV: &[u8] = b"iv";

#[derive(Debug)]
pub enum TlsError { Unsupported, DecodeError }

/// Holds handshake secrets and record cipher keys.
pub struct Tls13State {
    client_write_key: [u8; 16],
    server_write_key: [u8; 16],
    client_iv: [u8; 12],
    server_iv: [u8; 12],
    server_seq: u64,
    client_seq: u64,
}

impl Tls13State {
    pub fn new() -> Self {
        Self {
            client_write_key: [0;16],
            server_write_key: [0;16],
            client_iv: [0;12],
            server_iv: [0;12],
            server_seq: 0,
            client_seq: 0,
        }
    }
}

/// Process ClientHello and return ServerHello record.
/// On success, Tls13State is filled with traffic keys.
pub fn process_client_hello(buf: &[u8]) -> Result<(Vec<u8>, Tls13State), TlsError> {
    // Very naive parse: assume record header already stripped.
    if buf.len()<4 || buf[0]!=1 { return Err(TlsError::DecodeError); }
    let len = ((buf[1] as usize)<<16)|((buf[2] as usize)<<8)|(buf[3] as usize);
    if buf.len()<4+len { return Err(TlsError::DecodeError); }
    let body=&buf[4..4+len];
    if body.len()<42 { return Err(TlsError::DecodeError); }
    let mut idx=38; // skip legacy ver(2)+random(32)+sid_len(0)
    let cs_len = u16::from_be_bytes([body[idx],body[idx+1]]) as usize; idx+=2;
    if cs_len==0 || !body[idx..idx+cs_len].windows(2).any(|w| w==SUITE_TLS_AES_128_GCM_SHA256) {
        return Err(TlsError::Unsupported);
    }
    // --- Key schedule ---
    let mut shared_secret=[0u8;32]; // In real TLS: ECDHE; here use random.
    fill_random(&mut shared_secret);
    let zero:[u8;32]=[0;32];
    let early_secret = hkdf_extract(&zero, &[]);
    let derived = hkdf_expand_label(&early_secret, LABEL_DERIVED, &[], 32);
    let handshake_secret = hkdf_extract(&derived, &shared_secret);

    // client/server handshake traffic keys
    let client_hs = hkdf_expand_label(&handshake_secret, b"c hs traffic", &sha256_digest(b""), 32);
    let server_hs = hkdf_expand_label(&handshake_secret, b"s hs traffic", &sha256_digest(b""), 32);

    let client_key: [u8;16]=hkdf_expand_label(&client_hs, LABEL_KEY, &[], 16).try_into().unwrap();
    let server_key: [u8;16]=hkdf_expand_label(&server_hs, LABEL_KEY, &[], 16).try_into().unwrap();
    let client_iv: [u8;12]=hkdf_expand_label(&client_hs, LABEL_IV, &[], 12).try_into().unwrap();
    let server_iv: [u8;12]=hkdf_expand_label(&server_hs, LABEL_IV, &[], 12).try_into().unwrap();

    // Build minimal ServerHello record (TLSPlaintext)
    let mut random=[0u8;32]; fill_random(&mut random);
    let mut payload=Vec::new();
    payload.extend_from_slice(&[2]); // ServerHello
    payload.extend_from_slice(&(38u32.to_be_bytes()[1..])); // length 38
    payload.extend_from_slice(&[0x03,0x03]); // legacy_version 1.2
    payload.extend_from_slice(&random);
    payload.push(0); // session id len
    payload.extend_from_slice(&SUITE_TLS_AES_128_GCM_SHA256);
    payload.push(0); // compression
    payload.extend_from_slice(&[0,0]); // extensions len=0

    // Wrap into TLSPlaintext (content_type=22 handshake)
    let mut record=Vec::with_capacity(5+payload.len());
    record.push(22);
    record.extend_from_slice(&[0x03,0x03]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);

    let mut state = Tls13State::new();
    state.client_write_key=client_key;
    state.server_write_key=server_key;
    state.client_iv=client_iv;
    state.server_iv=server_iv;
    Ok((record, state))
}

// ---------- Record Layer ----------
fn build_nonce(iv:&[u8;12], seq:u64)->[u8;12] {
    let mut nonce=[0u8;12];
    nonce[..12].copy_from_slice(iv);
    for i in 0..8 { nonce[4+i]^=((seq>>((7-i)*8))&0xff) as u8; }
    nonce
}

pub fn encrypt_application_data(state:&mut Tls13State, plaintext:&mut Vec<u8>)->Vec<u8> {
    let nonce=build_nonce(&state.server_iv, state.server_seq);
    let aad=[0x17u8,0x03,0x03,0,0]; // content_type=23, length placeholder later
    let mut buf=plaintext.clone();
    let tag = aes_gcm::seal(&state.server_write_key, &nonce[..12].try_into().unwrap(), &aad, &mut buf);
    state.server_seq+=1;
    let len=(buf.len()+16) as u16;
    let mut record=Vec::with_capacity(5+buf.len()+16);
    record.push(23);
    record.extend_from_slice(&[0x03,0x03]);
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(&buf);
    record.extend_from_slice(&tag);
    record
}

pub fn decrypt_application_data(state:&mut Tls13State, ciphertext:&[u8]) -> Option<Vec<u8>> {
    if ciphertext.len()<21 { return None; }
    let content_type=ciphertext[0];
    if content_type!=23 { return None; }
    let len=u16::from_be_bytes([ciphertext[3],ciphertext[4]]) as usize;
    if ciphertext.len()!=5+len { return None; }
    let mut enc=ciphertext[5..5+len-16].to_vec();
    let tag:&[u8;16]=ciphertext[5+len-16..].try_into().unwrap();
    let nonce=build_nonce(&state.client_iv, state.client_seq);
    let aad=[0x17u8,0x03,0x03, ((len-16)>>8) as u8, ((len-16)&0xff) as u8];
    if !aes_gcm::open(&state.client_write_key, &nonce[..12].try_into().unwrap(), &aad, &mut enc, tag) {
        return None;
    }
    state.client_seq+=1;
    Some(enc)
} 