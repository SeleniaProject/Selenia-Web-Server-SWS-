//! QUIC v1 packet helper (long/short header) – minimal encode/decode for Initial.
//! This fulfils task "QUIC Transport ハンドシェイク & パケット化" skeleton.

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