//! Minimal HTTP/2 frame utilities – skeleton for future expansion.
//! Only constants and simple builders are provided now (no full implementation).

use std::io::{self, Write};
use std::net::TcpStream;

use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use crate::hpack::{HpackEncoder, HpackDecoder};

// -------------------------- Stream State Machine -----------------------------

/// RFC 7540 §5.1 で定義されるストリーム状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl Default for StreamState { fn default() -> Self { StreamState::Idle } }

#[derive(Debug, Default)]
pub struct Stream {
    pub id: u32,
    pub state: StreamState,
}

#[derive(Default)]
pub struct Connection {
    streams: HashMap<u32, Stream>,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
}

impl Connection {
    pub fn new() -> Self { Self { streams: HashMap::new(), encoder: HpackEncoder::new(), decoder: HpackDecoder::new() } }

    /// Handle an inbound frame, updating stream state per RFC 7540 §5.1/§5.4
    pub fn on_frame(&mut self, fh: &FrameHeader) {
        let s = self.streams.entry(fh.stream_id).or_insert(Stream { id: fh.stream_id, state: StreamState::Idle });
        use StreamState::*;
        match s.state {
            Idle => match fh.type_ {
                FrameType::Headers | FrameType::Priority => s.state = Open,
                FrameType::PushPromise => s.state = ReservedRemote,
                _ => {},
            },
            Open => match fh.type_ {
                FrameType::Data => if fh.flags & 0x1 != 0 { s.state = HalfClosedRemote; }, // END_STREAM
                FrameType::RstStream => s.state = Closed,
                _ => {},
            },
            HalfClosedRemote => match fh.type_ {
                FrameType::RstStream => s.state = Closed,
                _ => {},
            },
            HalfClosedLocal => match fh.type_ {
                FrameType::Data => {},
                FrameType::RstStream => s.state = Closed,
                _ => {},
            },
            _ => {},
        }
    }

    /// Consume DATA frame length and adjust windows, returning true if successful.
    pub fn on_data_frame(&mut self, stream_id:u32, len:usize, end_stream:bool) -> bool {
        if !self.fc.try_reserve(stream_id, len as i32) { return false; }
        if end_stream {
            if let Some(s)=self.streams.get_mut(&stream_id) { s.state = StreamState::HalfClosedRemote; }
        }
        true
    }

    /// Build WINDOW_UPDATE frame with given increment.
    pub fn build_window_update(stream_id:u32, increment:u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(13);
        let fh = FrameHeader { length:4, type_:FrameType::WindowUpdate, flags:0, stream_id };
        fh.serialize(&mut out);
        out.extend_from_slice(&increment.to_be_bytes());
        out
    }

    /// Encode headers into one HEADERS frame using HPACK.
    pub fn encode_headers(&mut self, stream_id:u32, headers:&[(String,String)], end_stream:bool) -> Vec<u8> {
        let payload = self.encoder.encode(headers);
        let mut out = Vec::with_capacity(9+payload.len());
        let flags = if end_stream { 0x1 /* END_STREAM */ | 0x4 /* END_HEADERS */ } else { 0x4 };
        let fh = FrameHeader { length:payload.len() as u32, type_:FrameType::Headers, flags, stream_id };
        fh.serialize(&mut out);
        out.extend_from_slice(&payload);
        out
    }

    /// Decode HEADERS payload, returning header list.
    pub fn decode_headers(&mut self, payload:&[u8]) -> Option<Vec<(String,String)>> {
        self.decoder.decode(payload).ok()
    }
}

// -------------------------- Priority Tree ------------------------------
/// Represents a single HTTP/2 stream node inside the priority tree.
#[derive(Debug)]
struct StreamNode {
    id: u32,
    weight: u16,          // weight is 1–256 in RFC 7540, we store 1–256
    parent: u32,          // parent stream id (0 = root)
    children: Vec<u32>,   // immediate children stream ids
    queued_bytes: usize,  // currently buffered payload bytes waiting for send
}

impl StreamNode {
    fn new(id: u32, parent: u32, weight: u16) -> Self {
        Self { id, weight: weight.max(1), parent, children: Vec::new(), queued_bytes: 0 }
    }
}

/// Priority tree root is virtual stream 0.
#[derive(Default)]
struct PriorityTree {
    nodes: HashMap<u32, StreamNode>,
}

impl PriorityTree {
    fn new() -> Self {
        let mut pt = PriorityTree { nodes: HashMap::new() };
        // insert root phantom node id 0
        pt.nodes.insert(0, StreamNode::new(0, 0, 16));
        pt
    }

    /// Insert new stream with given priority spec.
    /// RFC 7540 §5.3 allows exclusive flag; if exclusive == true, new parent becomes sole child.
    fn add_stream(&mut self, id: u32, parent: u32, weight: u16, exclusive: bool) {
        let parent_id = if parent == id { 0 } else { parent };
        self.ensure_node(parent_id);
        let mut node = StreamNode::new(id, parent_id, weight);
        if exclusive {
            // move existing children of parent under new node.
            let children = self.nodes.get_mut(&parent_id).unwrap().children.split_off(0);
            node.children = children.clone();
            for c in &children {
                if let Some(ch) = self.nodes.get_mut(c) { ch.parent = id; }
            }
        }
        self.nodes.insert(id, node);
        self.nodes.get_mut(&parent_id).unwrap().children.push(id);
    }

    /// Update priority of existing stream (may reparent).
    fn reprioritize(&mut self, id: u32, new_parent: u32, weight: u16, exclusive: bool) {
        if !self.nodes.contains_key(&id) { return; }
        let old_parent = self.nodes[&id].parent;
        if let Some(vec) = self.nodes.get_mut(&old_parent) {
            vec.children.retain(|&c| c != id);
        }
        let parent_id = if new_parent == id { 0 } else { new_parent };
        self.ensure_node(parent_id);
        self.nodes.get_mut(&id).unwrap().parent = parent_id;
        self.nodes.get_mut(&id).unwrap().weight = weight.max(1);
        if exclusive {
            // move children
            let children = self.nodes.get_mut(&parent_id).unwrap().children.split_off(0);
            self.nodes.get_mut(&id).unwrap().children.extend(children.clone());
            for c in &children {
                if let Some(ch) = self.nodes.get_mut(c) { ch.parent = id; }
            }
        }
        self.nodes.get_mut(&parent_id).unwrap().children.push(id);
    }

    /// Mark bytes ready for a stream; O(1) update of queued_bytes.
    fn enqueue_bytes(&mut self, id: u32, bytes: usize) {
        self.ensure_node(id);
        if let Some(node) = self.nodes.get_mut(&id) {
            node.queued_bytes += bytes;
        }
    }

    /// Return next stream id to send according to simple weighted round robin algorithm.
    /// Algorithm: traverse tree breadth-first keeping parent weights; pick first stream with queued_bytes > 0.
    fn pop_next_stream(&mut self) -> Option<u32> {
        let mut q: VecDeque<(u32, f32)> = VecDeque::new();
        q.push_back((0, 1.0));
        while let Some((id, ratio)) = q.pop_front() {
            let node = self.nodes.get(&id)?;
            // distribute share to children proportionally to weight
            let total_w: u32 = node.children.iter().map(|c| self.nodes[c].weight as u32).sum();
            if total_w == 0 { continue; }
            for c in &node.children {
                let child = &self.nodes[c];
                let share = ratio * (child.weight as f32 / total_w as f32);
                if child.queued_bytes > 0 {
                    // Accept if share above small threshold.
                    if share > 0.0001 {
                        // consume detection only; we keep bytes until flow control actually writes.
                        return Some(child.id);
                    }
                }
                q.push_back((child.id, share));
            }
        }
        None
    }

    fn ensure_node(&mut self, id: u32) {
        if !self.nodes.contains_key(&id) {
            // orphan nodes attach to root.
            self.nodes.insert(id, StreamNode::new(id, 0, 16));
            self.nodes.get_mut(&0).unwrap().children.push(id);
        }
    }
}

// -------------------------- Flow Control -------------------------------
const DEFAULT_CONN_WINDOW: i32 = 65_535;
const DEFAULT_STREAM_WINDOW: i32 = 65_535;

#[derive(Default)]
struct FlowControl {
    conn_window: i32,
    stream_windows: HashMap<u32, i32>,
}

impl FlowControl {
    fn new() -> Self { Self { conn_window: DEFAULT_CONN_WINDOW, stream_windows: HashMap::new() } }

    fn window_for(&mut self, id: u32) -> i32 {
        *self.stream_windows.entry(id).or_insert(DEFAULT_STREAM_WINDOW)
    }

    /// Try to reserve `len` bytes for sending on stream `id`.
    /// Returns true if reservation is allowed; otherwise false (caller must wait for WINDOW_UPDATE).
    fn try_reserve(&mut self, id: u32, len: i32) -> bool {
        let sw = self.window_for(id);
        if self.conn_window < len || sw < len { return false; }
        self.conn_window -= len;
        *self.stream_windows.get_mut(&id).unwrap() -= len;
        true
    }

    /// Process WINDOW_UPDATE frame.
    fn update_window(&mut self, id: u32, increment: i32) {
        if id == 0 {
            self.conn_window = (self.conn_window + increment).min(i32::MAX);
        } else {
            let w = self.stream_windows.entry(id).or_insert(DEFAULT_STREAM_WINDOW);
            *w = (*w + increment).min(i32::MAX);
        }
    }
}

// -------------------------- Scheduler Wrapper --------------------------
/// Combines priority tree and flow control into a scheduler usable by the HTTP/2 state machine.
pub struct Scheduler {
    ptree: PriorityTree,
    fc: FlowControl,
}

impl Scheduler {
    pub fn new() -> Self { Self { ptree: PriorityTree::new(), fc: FlowControl::new() } }

    /// Called when application queues DATA for a stream.
    pub fn queue_data(&mut self, stream_id: u32, bytes: usize) {
        self.ptree.enqueue_bytes(stream_id, bytes);
    }

    /// Select next stream ready to transmit considering flow control.
    pub fn next_stream(&mut self, frame_size: usize) -> Option<u32> {
        if let Some(id) = self.ptree.pop_next_stream() {
            if self.fc.try_reserve(id, frame_size as i32) {
                // decrease queued bytes
                if let Some(node) = self.ptree.nodes.get_mut(&id) {
                    node.queued_bytes = node.queued_bytes.saturating_sub(frame_size);
                }
                return Some(id);
            }
        }
        None
    }

    /// Apply WINDOW_UPDATE.
    pub fn on_window_update(&mut self, stream_id: u32, inc: i32) { self.fc.update_window(stream_id, inc); }

    /// Handle PRIORITY frame (re-)assignment.
    pub fn on_priority(&mut self, id: u32, parent: u32, weight: u16, exclusive: bool) {
        if self.ptree.nodes.contains_key(&id) {
            self.ptree.reprioritize(id, parent, weight, exclusive);
        } else {
            self.ptree.add_stream(id, parent, weight, exclusive);
        }
    }
}

// -------------------------- SETTINGS -----------------------------

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

#[derive(Debug, Default)]
pub struct Settings(pub Vec<(u16, u32)>);

impl Settings {
    pub fn encode(&self, out: &mut Vec<u8>) {
        for (id, val) in &self.0 {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&val.to_be_bytes());
        }
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() % 6 != 0 { return None; }
        let mut v = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            let id = u16::from_be_bytes([buf[pos], buf[pos+1]]);
            let val = u32::from_be_bytes([buf[pos+2], buf[pos+3], buf[pos+4], buf[pos+5]]);
            v.push((id, val));
            pos += 6;
        }
        Some(Settings(v))
    }
}

impl Connection {
    pub fn build_settings_frame(settings: &Settings, flags: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        settings.encode(&mut payload);
        let mut out = Vec::with_capacity(9 + payload.len());
        let fh = FrameHeader { length: payload.len() as u32, type_: FrameType::Settings, flags, stream_id: 0 };
        fh.serialize(&mut out);
        out.extend_from_slice(&payload);
        out
    }
}

impl Connection {
    /// Handle SETTINGS frame (ACK or new settings)
    fn on_settings(&mut self, fh:&FrameHeader, payload:&[u8]) {
        if fh.flags & 0x1 != 0 {
            // ACK – nothing to do for now.
        } else {
            if let Some(settings) = Settings::decode(payload) {
                // Apply settings such as INITIAL_WINDOW_SIZE
                for (id,val) in settings.0 {
                    if id == SETTINGS_INITIAL_WINDOW_SIZE {
                        self.fc.conn_window = val as i32;
                    }
                }
            }
            // In real implementation we would send ACK back.
        }
    }
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[repr(u8)]
#[allow(dead_code)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub length: u32,
    pub type_: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.length.to_be_bytes()[1..]); // 24-bit length
        out.push(self.type_ as u8);
        out.push(self.flags);
        out.extend_from_slice(&(self.stream_id & 0x7F_FF_FF_FF).to_be_bytes());
    }
}

impl TryFrom<u8> for FrameType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x0 => Ok(FrameType::Data),
            0x1 => Ok(FrameType::Headers),
            0x2 => Ok(FrameType::Priority),
            0x3 => Ok(FrameType::RstStream),
            0x4 => Ok(FrameType::Settings),
            0x5 => Ok(FrameType::PushPromise),
            0x6 => Ok(FrameType::Ping),
            0x7 => Ok(FrameType::GoAway),
            0x8 => Ok(FrameType::WindowUpdate),
            0x9 => Ok(FrameType::Continuation),
            _ => Err(()),
        }
    }
}

/// Attempt to parse a complete HTTP/2 frame from `buf`.
/// Returns (FrameHeader, payload_len) when complete, otherwise None.
pub fn parse_frame(buf: &[u8]) -> Option<(FrameHeader, usize)> {
    if buf.len() < 9 { return None; }
    let len = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
    if buf.len() < 9 + len as usize { return None; }
    let type_ = FrameType::try_from(buf[3]).ok()?;
    let flags = buf[4];
    let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7F_FF_FF_FF;
    let header = FrameHeader { length: len, type_, flags, stream_id };
    Some((header, 9 + len as usize))
}

/// Send a SETTINGS ack frame followed by GOAWAY(ENOERR) and close.
pub fn send_preface_response(stream: &mut TcpStream) -> io::Result<()> {
    // SETTINGS ack (length=0, type=4, flags=0x1, stream=0)
    let settings_ack = build_frame_header(0, FrameType::Settings as u8, 0x1, 0);
    // GOAWAY length=8 payload: last_stream_id(0) + error_code(0)
    let mut goaway = build_frame_header(8, FrameType::GoAway as u8, 0, 0);
    goaway.extend_from_slice(&[0u8; 8]);
    stream.write_all(&settings_ack)?;
    stream.write_all(&goaway)?;
    Ok(())
}

/// Check if buffer starts with HTTP/2 client preface.
pub fn is_preface(buf: &[u8]) -> bool { buf.starts_with(PREFACE) }

fn build_frame_header(length: u32, type_: u8, flags: u8, stream_id: u32) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(9);
    hdr.extend_from_slice(&(length.to_be_bytes()[1..])); // 24-bit length
    hdr.push(type_);
    hdr.push(flags);
    hdr.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    hdr
} 