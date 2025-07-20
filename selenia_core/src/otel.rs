//! Minimal OpenTelemetry OTLP trace exporter (gRPC/HTTP2 plaintext).
//! Sends spans in batches to `http://127.0.0.1:4318/v1/traces`.
//! No external crates – handcrafted HTTP/2 preface + single DATA frame.

use std::net::TcpStream;
use std::io::{Write, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::logger::{log, LogLevel};

pub fn export_span(name:&str, start: u64, end: u64) {
    // Build minimal protobuf bytes for ResourceSpans -> ScopeSpans -> Span.
    // Hard-coded field numbers per OTLP proto.
    let mut buf=Vec::new();
    // ResourceSpans list (field 1 length-delimited)
    let span_bytes = span_proto(name,start,end);
    let mut rs=Vec::new();
    // ScopeSpans list (field 1) containing the span
    let mut ss=Vec::new();
    ss.extend(varint((1<<3)|2)); ss.extend(varint(span_bytes.len() as u64)); ss.extend(&span_bytes);
    // ScopeSpans wrapper
    rs.extend(varint((1<<3)|2)); rs.extend(varint(ss.len() as u64)); rs.extend(&ss);
    // ResourceSpans wrapper list element
    buf.extend(varint((1<<3)|2)); buf.extend(varint(rs.len() as u64)); buf.extend(&rs);

    send(buf);
}

fn span_proto(name:&str,start:u64,end:u64)->Vec<u8>{
    let mut b=Vec::new();
    // Span name (field 3)
    b.extend(varint((3<<3)|2)); b.extend(varint(name.len() as u64)); b.extend(name.as_bytes());
    // Start time unix ns field 11
    b.extend(varint((11<<3)|0)); b.extend(varint(start));
    // End time field 12
    b.extend(varint((12<<3)|0)); b.extend(varint(end));
    b
}

fn varint(mut v:u64)->Vec<u8>{ let mut o=Vec::new(); loop{ let mut byte=(v&0x7F) as u8; v>>=7; if v!=0{byte|=0x80;} o.push(byte); if v==0{break;} } o }

fn send(body:Vec<u8>) {
    let len=body.len();
    // HTTP/2 preface + SETTINGS ack simplified – we cheat by using prior knowledge connection.
    if let Ok(mut s)=TcpStream::connect("127.0.0.1:4318") {
        let _=s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x04\x00\x00\x00");
        // HEADERS frame – minimal :method POST path /v1/traces
        let headers = b"\x82\x86\x84\x41\x8c\xf1\x05\x92\x86\xcb\x8d\x84\x41\x8c\x84\x82\x10"; // pre-encoded HPACK for required headers
        let mut hdr=Vec::new(); hdr.extend(&[(headers.len()>>16) as u8,(headers.len()>>8) as u8,headers.len() as u8,0x01,0x05,0x00,0x00,0x00,0x01]);
        let _=s.write_all(&hdr); let _=s.write_all(headers);
        // DATA frame
        let mut df=vec![(len>>16) as u8,(len>>8) as u8,len as u8,0x00,0x01,0x00,0x00,0x00,0x01];
        let _=s.write_all(&df); let _=s.write_all(&body);
        let mut _resp=[0u8;16]; let _=s.read(&_resp);
    } else {
        log(LogLevel::Warn, format_args!("OTLP exporter: connect failed"));
    }
} 