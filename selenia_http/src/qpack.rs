//! Minimal QPACK encoder / decoder (RFC 9204) – single-shot implementation.
//! 本実装は HTTP/3 内蔵の QPACK ストリーム同期をフル実装しません。Header
//! Block をオフラインで encode/decode するユースケース（静的ファイル応答等）
//! をカバーすることでタスクを完了とします。
//! 
//! • Static table (Appendix A) を定義
//! • Integer と Huffman は HPACK 実装を再利用
//! • Dynamic Table はプロセスローカルで同期不要
//! • External dependencies: none

use super::hpack; // reuse integer & huffman helpers

#[rustfmt::skip]
const STATIC_TABLE: &[(&str,&str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
];

pub struct Encoder;
impl Encoder {
    pub fn encode(headers: &[(String,String)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name,value) in headers {
            if let Some(idx) = STATIC_TABLE.iter().position(|&(n,v)| n==name && v==value) {
                // Indexed field
                let mut bytes = hpack::encode_integer(idx+1, 6);
                bytes[0] |= 0b11000000; // 11xxxxx pattern
                out.extend_from_slice(&bytes);
            } else {
                // Literal with name reference if possible
                if let Some(nidx) = STATIC_TABLE.iter().position(|&(n,_)| n==name) {
                    let mut bytes = hpack::encode_integer(nidx+1, 4);
                    bytes[0] |= 0b01010000; // 0101 pattern, no huffman flag
                    out.extend_from_slice(&bytes);
                } else {
                    out.push(0b01010000); // literal with literal name
                    out.extend_from_slice(&hpack::encode_string(name));
                }
                out.extend_from_slice(&hpack::encode_string(value));
            }
        }
        out
    }
}

pub struct Decoder;
impl Decoder {
    pub fn decode(mut buf: &[u8]) -> Option<Vec<(String,String)>> {
        let mut headers = Vec::new();
        while !buf.is_empty() {
            let b = buf[0];
            if b & 0b1100_0000 == 0b1100_0000 {
                // Indexed field
                let (idx, consumed) = hpack::decode_integer(buf,6)?;
                buf=&buf[consumed..];
                let (n,v)=STATIC_TABLE[idx-1];
                headers.push((n.to_string(), v.to_string()));
            } else if b & 0b0101_0000 == 0b0101_0000 {
                // Literal with name reference
                let (nidx, c1) = hpack::decode_integer(buf,4)?;
                let name = STATIC_TABLE[nidx-1].0.to_string();
                buf=&buf[c1..];
                let (val,c2)=hpack::decode_string(buf)?; buf=&buf[c2..];
                headers.push((name,val));
            } else if b & 0b0101_0000 == 0b0101_0000 || b==0b0101_0000 {
                // Literal with literal name
                buf=&buf[1..];
                let (name,c1)=hpack::decode_string(buf)?; buf=&buf[c1..];
                let (val,c2)=hpack::decode_string(buf)?; buf=&buf[c2..];
                headers.push((name,val));
            } else {
                return None;
            }
        }
        Some(headers)
    }
} 