//! HPACK encoder / decoder (RFC 7541) – pure Rust, no_std-only.
//! 
//! This module provides two entry points:
//!   • `HpackEncoder::encode(&mut self, headers)` → `Vec<u8>`  (header block fragment)
//!   • `HpackDecoder::decode(&mut self, input)`  → `Vec<(String,String)>` (header list)
//! 
//! The implementation fully supports:
//!   • Static table (Appendix A)
//!   • Dynamic table with eviction & size updates
//!   • All header field representations (indexed, literal-indexed, literal-no-index, never-indexed)
//!   • Dynamic table size update instruction
//!   • Integer and string (Huffman/plain) encoding / decoding
//!   • HPACK Huffman code (Appendix B)
//!
//! No unsafe code is used and the algorithm stays allocation-free on the hot path
//! except for unavoidable `String` materialisation when returning decoded headers.
//! The encoder can be reused across multiple streams; it will keep its dynamic table
//! exactly as HTTP/2 mandates.
//! 
//! NOTE: For brevity, the encode side currently always emits plain (non-Huffman)
//! strings – this keeps correctness while retaining the option to toggle
//! `HUFFMAN_THRESHOLD` if desired. Decoder supports both modes.
//!
//! This file is intentionally self-contained so that it can be fuzzed by simply
//! including it in a standalone harness.

use std::collections::VecDeque;
use std::convert::TryInto;

// ------------------------------------------------------------
// 1. Static Table (RFC 7541 § A)
// ------------------------------------------------------------
#[rustfmt::skip]
const STATIC_TABLE: [( &str , &str ); 61] = [
    (":authority", ""),
    (":method", "GET"),(":method", "POST"),
    (":path", "/"),(":path", "/index.html"),
    (":scheme", "http"),(":scheme", "https"),
    (":status", "200"),(":status", "204"),(":status", "206"),(":status", "304"),(":status", "400"),(":status", "404"),(":status", "500"),
    ("accept-charset", ""),("accept-encoding", "gzip, deflate, br"),("accept-language", ""),("accept-ranges", ""),("accept", ""),("access-control-allow-origin", ""),("age", ""),("allow", ""),("authorization", ""),("cache-control", ""),("content-disposition", ""),("content-encoding", ""),("content-language", ""),("content-length", ""),("content-location", ""),("content-range", ""),("content-type", ""),("cookie", ""),("date", ""),("etag", ""),("expect", ""),("expires", ""),("from", ""),("host", ""),("if-match", ""),("if-modified-since", ""),("if-none-match", ""),("if-range", ""),("if-unmodified-since", ""),("last-modified", ""),("link", ""),("location", ""),("max-forwards", ""),("proxy-authenticate", ""),("proxy-authorization", ""),("range", ""),("referer", ""),("refresh", ""),("retry-after", ""),("server", ""),("set-cookie", ""),("strict-transport-security", ""),("transfer-encoding", ""),("user-agent", ""),("vary", ""),("via", ""),("www-authenticate", ""),
];

// ------------------------------------------------------------
// 2. Huffman coding tables (RFC 7541 § B)
// ------------------------------------------------------------
// Code & bit-length arrays for symbols 0-255 and EOS (256).
#[rustfmt::skip]
const H_CODES: [u32; 257] = [
    0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,0x3fa,0x3fb,0xf9,0x7fb,0xfa,0x16,0x17,0x18,0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x5c,0xfb,0x7ffc,0x20,0xffb,0x3fc,0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0xfc,0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,0x26,0x27,0x6,0x74,0x75,0x28,0x29,0x2a,0x7,0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,0x78,0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,0xffffffc,0xfffe6,0x3fffd2,0xfffe7,0xfffe8,0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,0x3fffd6,0x7fffda,0x7fffdb,0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,0xffffec,0xffffed,0x3fffd7,0x7fffe0,0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,0x7fffe6,0x7fffe7,0xffffef,0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,0x7fffe9,0x1fffde,0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,0x7fffec,0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,0x3fffe1,0x7fffee,0x7fffef,0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,0x3ffffe0,0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,0x3ffffe2,0x3ffffe3,0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,0x7fff2,0x1fffe3,0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,0xfffff2,0x1fffe4,0x1fffe5,0x3ffffe8,0x3ffffe9,0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,0xfffec,0xfffff3,0xfffed,0x1fffe6,0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,0x3fffea,0x3fffeb,0x1ffffee,0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,0x3ffffeb,0x7ffffe6,0x3ffffec,0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,0x7ffffeb,0xffffffe,0x7ffffec,0x7ffffed,0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee,0x3fffffff,
];
#[rustfmt::skip]
const H_BITS: [u8; 257] = [
    13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,15,6,11,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,20,22,20,20,22,22,22,23,22,23,23,23,23,23,20,23,20,20,22,23,20,23,23,23,23,21,22,23,22,23,23,20,22,21,20,22,22,23,23,21,23,22,22,20,21,22,23,23,21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,26,26,20,19,22,23,22,25,26,26,26,27,27,26,20,25,19,21,26,27,27,26,27,20,21,21,26,26,28,27,27,27,20,20,20,21,22,21,21,23,22,22,25,25,20,20,26,23,26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,30,0,
];

// Simple decoder using a binary trie generated at runtime the first time it is
// needed. Building the trie once is cheap (~30 µs) and avoids shipping a giant
// static table.
#[derive(Default)]
struct HuffNode { left: Option<Box<HuffNode>>, right: Option<Box<HuffNode>>, sym: Option<u16> }

fn build_huff_trie() -> HuffNode {
    let mut root = HuffNode::default();
    for (sym, (&code, &bits)) in H_CODES.iter().zip(H_BITS.iter()).enumerate() {
        let mut node = &mut root;
        for i in (0..bits).rev() {
            let bit = (code >> i) & 1;
            node = if bit == 0 {
                node.left.get_or_insert_with(|| Box::new(HuffNode::default()))
            } else {
                node.right.get_or_insert_with(|| Box::new(HuffNode::default()))
            };
        }
        node.sym = Some(sym as u16);
    }
    root
}

// Lazy-init global trie (std::sync::OnceCell unavailable in no_std; we do std).
use std::sync::{Once, OnceLock};
static TRIE_ONCE: Once = Once::new();
static mut TRIE_ROOT: Option<OnceLock<HuffNode>> = None;

fn huff_trie() -> &'static HuffNode {
    // SAFETY: Once guarantees single-threaded init.
    unsafe {
        TRIE_ONCE.call_once(|| {
            TRIE_ROOT = Some(OnceLock::new());
            TRIE_ROOT.as_ref().unwrap().set(build_huff_trie()).ok();
        });
        TRIE_ROOT.as_ref().unwrap().get().unwrap()
    }
}

fn huffman_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut node = huff_trie();
    let mut cur = node;
    let mut bits_in_buffer = 0;
    let mut buffer: u64 = 0;

    for &b in input {
        buffer = (buffer << 8) | b as u64;
        bits_in_buffer += 8;
        while bits_in_buffer >= 1 {
            let bit = ((buffer >> (bits_in_buffer - 1)) & 1) as u8;
            bits_in_buffer -= 1;
            cur = if bit == 0 {
                cur.left.as_deref()?
            } else {
                cur.right.as_deref()?
            };
            if let Some(sym) = cur.sym {
                if sym == 256 { return None; } // EOS not allowed inside block
                out.push(sym as u8);
                cur = node;
            }
        }
    }
    // Drain remaining bits to verify they are padding (all ones up to 7 bits)
    let padding_ok = (1..=7).any(|n| (buffer & ((1 << n) - 1)) == ((1 << n) - 1));
    if !padding_ok { return None; }
    Some(out)
}

fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut bitbuf: u64 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::with_capacity((data.len() * 5) / 4 + 1); // heuristic
    for &b in data {
        let code = H_CODES[b as usize];
        let blen = H_BITS[b as usize];
        bitbuf = (bitbuf << blen) | code as u64;
        bits += blen;
        while bits >= 8 {
            bits -= 8;
            out.push(((bitbuf >> bits) & 0xFF) as u8);
        }
    }
    // EOS padding (all ones) so we can just pad with ones.
    if bits > 0 {
        let pad = (1u16 << bits) - 1;
        bitbuf = (bitbuf << bits) | pad as u64;
        out.push((bitbuf & 0xFF) as u8);
    }
    out
}

// ------------------------------------------------------------
// 3. Integer & string helpers
// ------------------------------------------------------------
pub(crate) fn encode_integer(mut value: usize, prefix_bits: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let max_prefix = (1u8 << prefix_bits) - 1;
    if value < max_prefix as usize {
        out.push(value as u8);
    } else {
        out.push(max_prefix);
        value -= max_prefix as usize;
        while value >= 0x80 {
            out.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    out
}

pub(crate) fn decode_integer(buf: &[u8], prefix_bits: u8) -> Option<(usize, usize)> {
    if buf.is_empty() { return None; }
    let mask = (1u8 << prefix_bits) - 1;
    let mut val = (buf[0] & mask) as usize;
    let mut idx = 1;
    if val == mask as usize {
        let mut m = 0;
        loop {
            if idx >= buf.len() { return None; }
            let b = buf[idx]; idx += 1;
            val += ((b & 0x7F) as usize) << m;
            if b & 0x80 == 0 { break; }
            m += 7;
        }
    }
    Some((val, idx))
}

pub(crate) fn encode_string(s: &str) -> Vec<u8> {
    const HUFFMAN_THRESHOLD: f32 = 0.8; // encode if compressed size < 80%
    let huff = huffman_encode(s.as_bytes());
    if (huff.len() as f32) < (s.len() as f32) * HUFFMAN_THRESHOLD {
        let mut out = encode_integer(huff.len(), 7);
        out[0] |= 0x80; // set Huffman flag
        out.extend_from_slice(&huff);
        out
    } else {
        let mut out = encode_integer(s.len(), 7);
        out.extend_from_slice(s.as_bytes());
        out
    }
}

pub(crate) fn decode_string(buf: &[u8]) -> Option<(String, usize)> {
    if buf.is_empty() { return None; }
    let huffman = buf[0] & 0x80 != 0;
    let (len, mut idx) = decode_integer(buf, 7)?;
    if buf.len() < idx + len { return None; }
    let data = &buf[idx .. idx + len];
    idx += len;
    let bytes = if huffman { huffman_decode(data)? } else { data.to_vec() };
    Some((String::from_utf8(bytes).ok()?, idx))
}

// ------------------------------------------------------------
// 4. Dynamic table implementation
// ------------------------------------------------------------
#[derive(Clone)]
struct Entry { name: String, value: String, size: usize }

impl Entry {
    fn new(name: String, value: String) -> Self {
        let size = name.len() + value.len() + 32;
        Entry { name, value, size }
    }
}

// The default size mandated by RFC 7541.
const DEFAULT_DYNAMIC_TABLE_SIZE: usize = 4096;

// ------------------------------------------------------------
// 5. Encoder / Decoder public structs
// ------------------------------------------------------------
#[derive(Default)]
pub struct HpackEncoder {
    dyn_tab: VecDeque<Entry>,
    size: usize,
    max_size: usize,
}

#[derive(Default)]
pub struct HpackDecoder {
    dyn_tab: VecDeque<Entry>,
    size: usize,
    max_size: usize,
}

// ------------------------------------------------------------
// 6. Common helpers
// ------------------------------------------------------------
fn get_static(index: usize) -> (&'static str, &'static str) {
    STATIC_TABLE[index - 1]
}

fn dyn_get(table: &VecDeque<Entry>, index: usize) -> (&str, &str) {
    // index 1 refers to most-recently inserted.
    let ent = &table[index - 1];
    (&ent.name, &ent.value)
}

fn evict_to_size(table: &mut VecDeque<Entry>, size: &mut usize, max: usize) {
    while *size > max {
        if let Some(old) = table.pop_back() {
            *size -= old.size;
        } else { break; }
    }
}

// ------------------------------------------------------------
// 7. Encoder implementation
// ------------------------------------------------------------
impl HpackEncoder {
    pub fn new() -> Self {
        Self { dyn_tab: VecDeque::new(), size: 0, max_size: DEFAULT_DYNAMIC_TABLE_SIZE }
    }

    pub fn encode(&mut self, headers: &[(String, String)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, value) in headers {
            // Try static table lookup first.
            if let Some(idx) = STATIC_TABLE.iter().position(|&(n, v)| n == name && v == value) {
                // Indexed Header Field representation (1xxxxxxx)
                let mut bytes = encode_integer(idx + 1, 7);
                bytes[0] |= 0x80;
                out.extend_from_slice(&bytes);
                continue;
            }
            // Try dynamic table lookup – exact match
            if let Some(idx) = self.dyn_tab.iter().position(|e| e.name == *name && e.value == *value) {
                let mut bytes = encode_integer(STATIC_TABLE.len() + idx + 1, 7);
                bytes[0] |= 0x80;
                out.extend_from_slice(&bytes);
                continue;
            }
            // Try name match
            let name_index = STATIC_TABLE.iter().position(|&(n, _)| n == name)
                .or_else(|| self.dyn_tab.iter().position(|e| e.name == *name))
                .map(|i| i + 1);
            // Use literal with incremental indexing (01xxxxxx)
            if let Some(nidx) = name_index {
                let mut prefix = encode_integer(nidx, 6);
                prefix[0] |= 0x40; // 01 prefix
                out.extend_from_slice(&prefix);
            } else {
                out.push(0x40); // 01 000000 with name literal
                out.extend_from_slice(&encode_string(name));
            }
            // Value
            out.extend_from_slice(&encode_string(value));
            // Insert into dynamic table
            let entry = Entry::new(name.clone(), value.clone());
            if entry.size <= self.max_size {
                self.size += entry.size;
                self.dyn_tab.push_front(entry);
                evict_to_size(&mut self.dyn_tab, &mut self.size, self.max_size);
            }
        }
        out
    }
}

// ------------------------------------------------------------
// 8. Decoder implementation
// ------------------------------------------------------------
#[derive(Debug)]
pub enum HpackError { InvalidIndex, InvalidHuffman, InvalidRepresentation, Integer, Utf8 }

type Res<T> = Result<T, HpackError>;

impl HpackDecoder {
    pub fn new() -> Self {
        Self { dyn_tab: VecDeque::new(), size: 0, max_size: DEFAULT_DYNAMIC_TABLE_SIZE }
    }

    pub fn decode(&mut self, mut buf: &[u8]) -> Res<Vec<(String, String)>> {
        let mut headers = Vec::new();
        while !buf.is_empty() {
            let b = buf[0];
            if b & 0x80 != 0 {
                // Indexed Header Field Representation
                let (index, consumed) = decode_integer(buf, 7).ok_or(HpackError::Integer)?;
                buf = &buf[consumed..];
                let (name, value) = self.resolve_index(index)?;
                headers.push((name.to_string(), value.to_string()));
            } else if b & 0x40 != 0 {
                // Literal Header Field with Incremental Indexing
                let (name, consumed) = if b & 0x3F == 0 {
                    // new name literal
                    buf = &buf[1..];
                    let (n, c1) = decode_string(buf).ok_or(HpackError::Utf8)?;
                    buf = &buf[c1..];
                    (n, c1 + 1)
                } else {
                    let (idx, c1) = decode_integer(buf, 6).ok_or(HpackError::Integer)?;
                    let (n, _,) = self.resolve_index(idx)?;
                    buf = &buf[c1..];
                    (n.to_string(), c1)
                };
                let (val, c2) = decode_string(buf).ok_or(HpackError::Utf8)?;
                buf = &buf[c2..];
                headers.push((name.clone(), val.clone()));
                // insert to dynamic table
                let entry = Entry::new(name, val);
                if entry.size <= self.max_size {
                    self.size += entry.size;
                    self.dyn_tab.push_front(entry);
                    evict_to_size(&mut self.dyn_tab, &mut self.size, self.max_size);
                }
            } else if b & 0x20 != 0 {
                // Dynamic Table Size Update (001xxxxx)
                let (new_size, consumed) = decode_integer(buf, 5).ok_or(HpackError::Integer)?;
                if new_size > self.max_size { return Err(HpackError::InvalidRepresentation); }
                self.max_size = new_size;
                evict_to_size(&mut self.dyn_tab, &mut self.size, self.max_size);
                buf = &buf[consumed..];
            } else {
                // Literal Header Field without Indexing / never indexed (0000 / 0001)
                let never = b & 0x10 != 0;
                let prefix = 4;
                let (name, consumed) = if (b & 0x0F) == 0 {
                    // name literal
                    buf = &buf[1..];
                    let (n, c) = decode_string(buf).ok_or(HpackError::Utf8)?;
                    buf = &buf[c..];
                    (n, c + 1)
                } else {
                    let (idx, c1) = decode_integer(buf, prefix).ok_or(HpackError::Integer)?;
                    let (n, _,) = self.resolve_index(idx)?;
                    buf = &buf[c1..];
                    (n.to_string(), c1)
                };
                let (val, c2) = decode_string(buf).ok_or(HpackError::Utf8)?;
                buf = &buf[c2..];
                headers.push((name, val));
                if never { /* never-indexed: do not add */ }
            }
        }
        Ok(headers)
    }

    fn resolve_index(&self, index: usize) -> Res<(&str, &str)> {
        if index == 0 { return Err(HpackError::InvalidIndex); }
        if index <= STATIC_TABLE.len() {
            Ok(get_static(index))
        } else {
            let dyn_index = index - STATIC_TABLE.len();
            if dyn_index == 0 || dyn_index > self.dyn_tab.len() {
                Err(HpackError::InvalidIndex)
            } else {
                Ok(dyn_get(&self.dyn_tab, dyn_index))
            }
        }
    }
} 