//! 純 Rust TLS 1.3 ハンドシェイクスケルトン
//! RFC 8446 のメッセージ構造体を最小実装する。

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

#[derive(Debug)]
pub struct HandshakeHeader {
    pub typ: HandshakeType,
    pub len: u32, // 24bit 実際は 3byte
}

impl HandshakeHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 { return None; }
        let typ = match buf[0] {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            _ => return None,
        };
        let len = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        Some((HandshakeHeader { typ, len }, 4))
    }
}

#[derive(Debug)]
pub struct ClientHello<'a> {
    pub random: [u8; 32],
    pub legacy_session_id: &'a [u8],
    pub cipher_suites: &'a [u8],
    pub extensions: &'a [u8],
}

impl<'a> ClientHello<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<(Self, usize)> {
        if buf.len() < 34 { return None; }
        let random = buf[0..32].try_into().unwrap();
        let mut idx = 32;
        let sid_len = buf[idx] as usize; idx+=1;
        if buf.len() < idx+sid_len+2 { return None; }
        let session = &buf[idx .. idx+sid_len]; idx+=sid_len;
        let suite_len = ((buf[idx] as usize)<<8)|(buf[idx+1] as usize); idx+=2;
        if buf.len()<idx+suite_len+1 { return None; }
        let suites = &buf[idx .. idx+suite_len]; idx+=suite_len;
        let comp_len = buf[idx] as usize; idx+=1+comp_len; // skip compression
        if buf.len()<idx+2 { return None; }
        let ext_len = ((buf[idx] as usize)<<8)|(buf[idx+1] as usize); idx+=2;
        if buf.len()<idx+ext_len { return None; }
        let exts = &buf[idx .. idx+ext_len]; idx+=ext_len;
        Some((ClientHello{random,legacy_session_id:session,cipher_suites:suites,extensions:exts}, idx))
    }
}

pub mod rand;
pub mod sha256;
pub mod hmac;
pub mod hkdf;
pub mod chacha20;
pub mod poly1305;
pub mod aead;
pub mod aes;
pub mod aes_gcm;
pub mod tls;
pub mod tls13;
pub mod ocsp;
pub mod memfd_secret;

// 以降のメッセージは後続フェーズで追加予定 