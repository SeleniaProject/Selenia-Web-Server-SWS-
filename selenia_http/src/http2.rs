//! Minimal HTTP/2 frame utilities – skeleton for future expansion.
//! Only constants and simple builders are provided now (no full implementation).

use std::io::{self, Write};
use std::net::TcpStream;
use super::hpack;

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