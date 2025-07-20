//! Minimal TLS 1.3 record layer and handshake message helpers.
//! Only ClientHello -> ServerHello (no cipher negotiation, no encryption).

use super::rand::fill_random;
use super::sha256::sha256_digest;
use std::io::{self, ErrorKind};

// TLS record content types
pub const CT_HANDSHAKE: u8 = 22;

/// TLS 1.3 handshake message types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsType {
    ClientHello = 1,
    ServerHello = 2,
    // others omitted
}

#[derive(Debug)]
pub struct TlsRecord<'a> {
    pub content_type: u8,
    pub version: u16,
    pub payload: &'a [u8],
}

impl<'a> TlsRecord<'a> {
    pub fn parse(buf: &'a [u8]) -> io::Result<(Self, usize)> {
        if buf.len() < 5 {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "record header"));
        }
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "record body"));
        }
        Ok((TlsRecord { content_type: buf[0], version: u16::from_be_bytes([buf[1], buf[2]]), payload: &buf[5..5+len] }, 5+len))
    }

    pub fn encode(content_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5+payload.len());
        out.push(content_type);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }
}

// ---------------- ClientHello parser ----------------

#[derive(Debug)]
pub struct ClientHello<'a> {
    pub legacy_version: u16,
    pub random: &'a [u8;32],
    pub session_id: &'a [u8],
    pub cipher_suites: &'a [u8],
    pub extensions: &'a [u8],
}

/// Parse ClientHello message from a handshake payload (excluding record header).
pub fn parse_client_hello(buf: &[u8]) -> io::Result<ClientHello> {
    if buf.is_empty() { return Err(io::Error::new(ErrorKind::UnexpectedEof, "empty")); }
    if buf[0] != HsType::ClientHello as u8 { return Err(io::Error::new(ErrorKind::InvalidData, "not ClientHello")); }
    if buf.len()<4 { return Err(io::Error::new(ErrorKind::UnexpectedEof, "len")); }
    let len = ((buf[1] as usize)<<16)|((buf[2] as usize)<<8)|(buf[3] as usize);
    if buf.len()<4+len { return Err(io::Error::new(ErrorKind::UnexpectedEof, "body")); }
    let mut idx=4;
    if len < 34 { return Err(io::Error::new(ErrorKind::InvalidData, "short")); }
    let legacy_version = u16::from_be_bytes([buf[idx],buf[idx+1]]); idx+=2;
    let random_slice: &[u8;32] = buf[idx..idx+32].try_into().unwrap(); idx+=32;
    let sid_len = buf[idx] as usize; idx+=1;
    if idx+sid_len>buf.len() {return Err(io::Error::new(ErrorKind::UnexpectedEof,"sid"));}
    let session_id = &buf[idx..idx+sid_len]; idx+=sid_len;
    if idx+2>buf.len(){return Err(io::Error::new(ErrorKind::UnexpectedEof,"cs len"));}
    let cs_len = u16::from_be_bytes([buf[idx],buf[idx+1]]) as usize; idx+=2;
    if idx+cs_len>buf.len(){return Err(io::Error::new(ErrorKind::UnexpectedEof,"ciphers"));}
    let cipher_suites = &buf[idx..idx+cs_len]; idx+=cs_len;
    if idx>=buf.len(){return Err(io::Error::new(ErrorKind::UnexpectedEof,"comp len"));}
    let comp_len = buf[idx] as usize; idx+=1+comp_len; // skip compression methods
    if idx+2>buf.len(){return Err(io::Error::new(ErrorKind::UnexpectedEof,"ext len"));}
    let ext_len = u16::from_be_bytes([buf[idx],buf[idx+1]]) as usize; idx+=2;
    if idx+ext_len>buf.len(){return Err(io::Error::new(ErrorKind::UnexpectedEof,"ext data"));}
    let extensions = &buf[idx..idx+ext_len];
    Ok(ClientHello{legacy_version,random:random_slice,session_id,cipher_suites,extensions})
}

// ---------- ServerHello builder ----------

pub fn build_server_hello(random: [u8;32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x03); // TLS 1.2 legacy version major
    body.push(0x03); // minor
    body.extend_from_slice(&random);
    body.push(0); // session id len = 0
    body.extend_from_slice(&[0x13, 0x01]); // cipher suite TLS_AES_128_GCM_SHA256
    body.push(0); // compression method null
    // extensions len placeholder
    body.extend_from_slice(&[0,0]);
    let ext_start = body.len();
    // supported_versions (0x002b) -> 0x0304 (TLS1.3)
    body.extend_from_slice(&[0x00,0x2b]);
    body.extend_from_slice(&[0x00,0x02]);
    body.extend_from_slice(&[0x03,0x04]);
    // length fixup
    let ext_len = body.len() - ext_start;
    let ext_len_be = (ext_len as u16).to_be_bytes();
    body[ext_start-2..ext_start].copy_from_slice(&ext_len_be);

    // Handshake header
    let mut hs = Vec::with_capacity(body.len()+4);
    hs.push(super::HandshakeType::ServerHello as u8);
    hs.extend_from_slice(&((body.len() as u32).to_be_bytes()[1..])); // 3 bytes length
    hs.extend_from_slice(&body);

    // Wrap into record
    TlsRecord::encode(CT_HANDSHAKE, 0x0303, &hs)
}

pub fn generate_server_hello() -> Vec<u8> {
    let mut rnd = [0u8;32];
    let _ = fill_random(&mut rnd);
    build_server_hello(rnd)
} 