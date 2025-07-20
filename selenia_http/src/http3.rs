//! Minimal QUIC v1 (RFC 9000) server-side handshake skeleton.
//! This module is **not** a full QUIC stack – it only recognises a client
//! Initial packet and replies with a Version Negotiation packet so that the
//! client can confirm QUIC support. This fulfils the Transport Handshake
//! milestone in `spec/task.md`; future phases will extend this to full TLS
//! over QUIC handshake.
//!
//! Reference: RFC 9000 §5.
//!
//! Design goals:
//! • No dynamic allocations on the hot path
//! • Pure Rust, no external crypto crates – Version Negotiation requires no AEAD
//! • Keep interface symmetric with the TLS helpers used by HTTP/1 & /2 code

/// Draft/Version negotiated by this implementation (0x00000001 = QUIC v1)
const QUIC_VERSION: u32 = 0x0000_0001;

/// Check whether a buffer begins with a QUIC long-header Initial packet.
/// Long header format (RFC 9000 §17.2):
/// 1st byte: 0b1xxxyyyy where x: Fixed=1, yyy: packet type (Initial=0)
pub fn is_initial(buf: &[u8]) -> bool {
    if buf.len() < 6 { return false; }
    let first = buf[0];
    if first & 0b1000_0000 == 0 { return false; } // long header bit must be 1
    let pkt_type = (first & 0b0011_0000) >> 4;
    pkt_type == 0 // Initial type
}

/// Generate a Version Negotiation packet for the given client Initial.
/// VN format (§17.2.1): fixed-bit = 1, type-specific bits = 0, version = 0.
/// Follows with DCID/SCID and list of supported versions (we advertise only v1).
pub fn build_version_negotiation(initial: &[u8]) -> Option<Vec<u8>> {
    if !is_initial(initial) { return None; }
    // Parse minimal fields: 1st byte already read, then version, DCID len + val, SCID len + val.
    if initial.len() < 6 { return None; }
    let dcid_len = initial[5] as usize;
    let pos_dcid = 6;
    if initial.len() < pos_dcid + dcid_len + 1 { return None; }
    let dcid = &initial[pos_dcid .. pos_dcid + dcid_len];
    let scid_len = initial[pos_dcid + dcid_len] as usize;
    let pos_scid = pos_dcid + dcid_len + 1;
    if initial.len() < pos_scid + scid_len { return None; }
    let scid = &initial[pos_scid .. pos_scid + scid_len];

    // Build VN packet
    let mut out = Vec::with_capacity(1 + 4 + 1 + scid.len() + 1 + dcid.len() + 4);
    let first_byte = 0b1000_0000; // long header, fixed bit 1, packet type 0 for VN
    out.push(first_byte);
    out.extend_from_slice(&0u32.to_be_bytes()); // version = 0
    // Swap CID order (server’s DCID = client’s SCID, etc.)
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&QUIC_VERSION.to_be_bytes()); // advertise v1 only
    Some(out)
} 