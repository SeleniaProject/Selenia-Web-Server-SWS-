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

use std::collections::{HashMap, VecDeque};
use super::qpack::{Encoder as QpackEncoder, Decoder as QpackDecoder};
use crate::http3_packet; // for Retry construction

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

// ---------------- 0-RTT Detection -----------------
/// Return true if the buffer is a QUIC 0-RTT Protected packet (long header type=1)
pub fn is_zero_rtt(buf: &[u8]) -> bool {
    if buf.len()<1 { return false; }
    let b=buf[0];
    if b & 0x80 ==0 {return false;}
    let typ = (b & 0b0011_0000)>>4;
    typ==1 // 0-RTT
}

// ---------------- Retry Packet --------------------
/// Build a standards-compliant Retry packet using helper in `http3_packet`.
pub fn build_retry(initial: &[u8], server_scid: &[u8], token: &[u8]) -> Option<Vec<u8>> {
    if !is_initial(initial) { return None; }
    // Extract client DCID (original DCID) from Initial packet (after len byte)
    let dcid_len = initial.get(5).copied()? as usize;
    if initial.len() < 6 + dcid_len { return None; }
    let orig_dcid = &initial[6 .. 6+dcid_len];
    Some(http3_packet::build_retry(orig_dcid, server_scid, token))
}

// ---------------- Datagram Extension ---------------
/// Encode a QUIC Datagram frame (draft-ietf-quic-datagram-04 type 0x30 with length varint).
pub fn encode_datagram(stream_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16+payload.len());
    out.push(0x30); // frame type
    // Varint encode length and stream_id (simplified 1-byte if <64)
    if stream_id<64 {
        out.push(stream_id as u8);
    } else {
        out.extend_from_slice(&(stream_id as u16).to_be_bytes());
    }
    let len=payload.len();
    if len<64 { out.push(len as u8);} else { out.extend_from_slice(&(len as u16).to_be_bytes()); }
    out.extend_from_slice(payload);
    out
}

pub fn decode_datagram(buf: &[u8]) -> Option<(u64, &[u8])> {
    if buf.first()!=Some(&0x30) {return None;}
    if buf.len()<3 {return None;}
    let mut idx=1;
    let sid = buf[idx] as u64; idx+=1; // simplistic varint 1-byte
    let len = buf[idx] as usize; idx+=1;
    if buf.len()<idx+len {return None;}
    Some((sid,&buf[idx..idx+len]))
} 

// ---------------- Stream & Flow Control ----------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamType { BiDi, Uni }

#[derive(Debug)]
pub struct StreamState {
    pub id: u64,
    pub stream_type: StreamType,
    pub send_offset: usize,
    pub recv_offset: usize,
    pub window: i32,
}

impl StreamState {
    fn new(id: u64, stype: StreamType, init_win: i32) -> Self {
        Self { id, stream_type: stype, send_offset:0, recv_offset:0, window:init_win }
    }
}

#[derive(Default)]
pub struct FlowMgr {
    conn_window: i32,
    stream_windows: HashMap<u64, i32>,
}

impl FlowMgr {
    pub fn new() -> Self { Self { conn_window: 16_384, stream_windows: HashMap::new() } }

    pub fn consume(&mut self, stream_id:u64, len:i32) -> bool {
        let sw = self.stream_windows.entry(stream_id).or_insert(16_384);
        if *sw < len || self.conn_window < len { return false; }
        *sw -= len; self.conn_window -= len; true
    }

    pub fn update_window(&mut self, stream_id:Option<u64>, inc:i32) {
        if let Some(id)=stream_id {
            *self.stream_windows.entry(id).or_insert(0) += inc;
        } else { self.conn_window += inc; }
    }
}

#[derive(Default)]
pub struct Scheduler {
    queue: VecDeque<u64>,
    pending: HashMap<u64, usize>,
}

impl Scheduler {
    pub fn enqueue(&mut self, stream_id:u64, bytes:usize) {
        let entry = self.pending.entry(stream_id).or_insert(0);
        *entry += bytes;
        if !self.queue.contains(&stream_id) { self.queue.push_back(stream_id); }
    }

    pub fn next(&mut self) -> Option<u64> {
        while let Some(id) = self.queue.pop_front() {
            if let Some(rem) = self.pending.get_mut(&id) {
                if *rem > 0 {
                    *rem -= 1; // arbitrary 1-byte quantum
                    if *rem > 0 { self.queue.push_back(id); }
                    return Some(id);
                }
            }
        }
        None
    }
} 

#[derive(Default)]
pub struct ZeroRttBuffer {
    /// Buffered 0-RTT QUIC packets. Each entry is the raw packet bytes as received.
    packets: VecDeque<Vec<u8>>,
}

impl ZeroRttBuffer {
    /// Push a new 0-RTT packet into the buffer.
    pub fn push(&mut self, pkt: &[u8]) {
        // Copy the packet so that the lifetime is detached from the original receive buffer.
        self.packets.push_back(pkt.to_vec());
    }

    /// Drain all buffered packets and return them as a vector in arrival order.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        self.packets.drain(..).collect()
    }

    /// Returns true if at least one packet is buffered.
    pub fn is_empty(&self) -> bool { self.packets.is_empty() }
}

#[derive(Default)]
pub struct ConnectionCtx {
    pub scheduler: Scheduler,
    pub flow: FlowMgr,
    qenc: QpackEncoder,
    qdec: QpackDecoder,
    /// Buffer for received 0-RTT Protected packets until the handshake completes.
    zero_rtt: ZeroRttBuffer,
}

impl ConnectionCtx {
    pub fn new() -> Self { Self { scheduler: Scheduler::default(), flow: FlowMgr::new(), qenc: QpackEncoder, qdec: QpackDecoder, zero_rtt: ZeroRttBuffer::default() } }

    /// Encode headers into HTTP/3 HEADERS frame (type 0x1) returning payload.
    pub fn encode_headers(&mut self, headers:&[(String,String)]) -> Vec<u8> {
        self.qenc.encode_ref(headers)
    }

    pub fn decode_headers(&mut self, payload:&[u8]) -> Option<Vec<(String,String)>> { self.qdec.decode_ref(payload) }

    // ---------------- 0-RTT helpers ----------------

    /// Offer a raw QUIC packet to the connection. If it is a 0-RTT Protected packet, the
    /// packet is buffered and the function returns `true`. Otherwise `false` is returned so
    /// the caller can continue normal processing.
    pub fn maybe_buffer_0rtt(&mut self, packet:&[u8]) -> bool {
        if is_zero_rtt(packet) {
            self.zero_rtt.push(packet);
            return true;
        }
        false
    }

    /// Flushes all buffered 0-RTT packets, returning them in arrival order. This should be
    /// called immediately after the handshake is confirmed (TLS Finished processed) so that
    /// the application can re-inject the packets into the normal processing pipeline.
    pub fn flush_0rtt(&mut self) -> Vec<Vec<u8>> {
        self.zero_rtt.drain()
    }
} 

pub use crate::http3_packet::build_initial_packet; 