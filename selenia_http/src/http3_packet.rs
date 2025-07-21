//! QUIC v1 packet helper (long/short header) – minimal encode/decode for Initial.
//! This fulfils task "QUIC Transport ハンドシェイク & パケット化" skeleton.

use selenia_core::crypto::aes_gcm;
// 128-bit key & 96-bit nonce per RFC 9001 §5.8 (QUIC v1)
const RETRY_INTEGRITY_KEY: [u8; 16] = [0xbe,0x0c,0x69,0x0b,0x9f,0x66,0x57,0x5a,0x1d,0x76,0x6b,0x54,0xe3,0x68,0xc8,0x4e];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [0x46,0x15,0x99,0xd3,0x5d,0x63,0x2b,0xf2,0x23,0x98,0x25,0xbb];

/// Encode variable-length integer per RFC 9000 §16.
fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    if v < 1<<6 { out.push(v as u8); }
    else if v < 1<<14 { out.extend_from_slice(&((v|0x4000) as u16).to_be_bytes()); }
    else if v < 1<<30 { out.extend_from_slice(&((v|0x8000_0000) as u32).to_be_bytes()); }
    else { out.extend_from_slice(&((v|0xC000_0000_0000_0000) as u64).to_be_bytes()); }
}

/// Build a dummy Initial packet with random DCID/SCID (all zeros here) and empty CRYPTO frame.
pub fn build_initial_packet() -> Vec<u8> {
    let mut out = Vec::new();
    let first = 0b1100_0000; // Long header, Initial type (0)
    out.push(first);
    out.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // Version v1
    out.push(8); out.extend_from_slice(&[0u8;8]); // DCID length+value
    out.push(0); // SCID len=0
    // Token length=0 varint
    out.push(0);
    // Length placeholder (will be 1 for empty CRYPTO)
    encode_varint(1, &mut out);
    // Packet number (1 byte PN=0)
    out.push(0);
    // CRYPTO frame type 0x06 + len=0 varint
    out.push(0x06); out.push(0);
    out
}

/// Compute Retry Integrity Tag (RFC 9001 §5.8)
fn retry_integrity_tag(orig_dcid: &[u8], retry_packet: &[u8]) -> [u8; 16] {
    // Build Retry Pseudo-Packet = ODCID Len || ODCID || Retry packet bytes (no tag)
    let mut aad = Vec::with_capacity(1 + orig_dcid.len() + retry_packet.len());
    aad.push(orig_dcid.len() as u8);
    aad.extend_from_slice(orig_dcid);
    aad.extend_from_slice(retry_packet);
    // Empty plaintext per spec
    let mut pt = Vec::new();
    aes_gcm::seal(&RETRY_INTEGRITY_KEY, &RETRY_INTEGRITY_NONCE, &aad, &mut pt)
}

/// Build a standards-compliant Retry packet (RFC 9001 §17.2.5).
/// `orig_dcid` = client-selected DCID from Initial, `scid` = server CID, `token` = address validation token.
pub fn build_retry(orig_dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
    // 1. Serialize Retry header (without integrity tag)
    let mut hdr = Vec::new();
    let first = 0b1111_0000; // Long header, type=Retry (0xf)
    hdr.push(first);
    hdr.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // Version v1
    hdr.push(orig_dcid.len() as u8);
    hdr.extend_from_slice(orig_dcid);
    hdr.push(scid.len() as u8);
    hdr.extend_from_slice(scid);
    hdr.extend_from_slice(token);

    // 2. Compute Integrity Tag over pseudo-packet
    let tag = retry_integrity_tag(orig_dcid, &hdr);

    // 3. Output Retry packet = header || tag
    let mut out = hdr;
    out.extend_from_slice(&tag);
    out
} 