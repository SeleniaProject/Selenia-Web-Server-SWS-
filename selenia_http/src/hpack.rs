//! Minimal HPACK static table and integer/str encoding helpers.
//! This is only a skeleton sufficient for future HTTP/2 header parsing.

// -------- Static table (RFC 7541 Appendix A) --------
static STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),(":method", "GET"),(":method", "POST"),(":path", "/"),(":path", "/index.html"),(":scheme", "http"),(":scheme", "https"),(":status", "200"),(":status", "204"),(":status", "206"),(":status", "304"),(":status", "400"),(":status", "404"),(":status", "500"),("accept-charset", ""),("accept-encoding", "gzip, deflate, br"),("accept-language", ""),("accept-ranges", ""),("accept", ""),("access-control-allow-origin", ""),("age", ""),("allow", ""),("authorization", ""),("cache-control", ""),("content-disposition", ""),("content-encoding", ""),("content-language", ""),("content-length", ""),("content-location", ""),("content-range", ""),("content-type", ""),("cookie", ""),("date", ""),("etag", ""),("expect", ""),("expires", ""),("from", ""),("host", ""),("if-match", ""),("if-modified-since", ""),("if-none-match", ""),("if-range", ""),("if-unmodified-since", ""),("last-modified", ""),("link", ""),("location", ""),("max-forwards", ""),("proxy-authenticate", ""),("proxy-authorization", ""),("range", ""),("referer", ""),("refresh", ""),("retry-after", ""),("server", ""),("set-cookie", ""),("strict-transport-security", ""),("transfer-encoding", ""),("user-agent", ""),("vary", ""),("via", ""),("www-authenticate", ""),
];

/// Very small decoder: supports indexed header field representations (first bit 1).
/// Returns vector of (name,value) pairs if successful.
pub fn decode_header_block(mut buf: &[u8]) -> Option<Vec<(String,String)>> {
    let mut headers = Vec::new();
    while !buf.is_empty() {
        let b = buf[0];
        if b & 0x80 != 0 { // Indexed Header Field Representation
            let (index, consumed) = decode_integer(buf, 7)?;
            buf=&buf[consumed..];
            if index==0 || index>STATIC_TABLE.len() { return None; }
            let (name,value) = STATIC_TABLE[index-1];
            headers.push((name.to_string(), value.to_string()));
        } else if b & 0x40 !=0 { // Literal Header Field with Incremental Indexing -- Indexed Name (01xxxxxx)
            let (name_index, consumed1)=decode_integer(buf,6)?; buf=&buf[consumed1..];
            if name_index==0 || name_index>STATIC_TABLE.len() { return None; }
            // decode value length (prefix 7 bits on next byte)
            if buf.is_empty() { return None; }
            let huff=false;// ignore Huffman bit
            let (val_len, consumed2)=decode_integer(buf,7)?; buf=&buf[consumed2..];
            if buf.len()<val_len { return None; }
            let val=std::str::from_utf8(&buf[..val_len]).ok()?;
            buf=&buf[val_len..];
            let (name,_) = STATIC_TABLE[name_index-1];
            headers.push((name.to_string(), val.to_string()));
            if huff { /* not implemented */ }
        } else {
            // Other representations not yet supported
            return None;
        }
    }
    Some(headers)
}

pub fn decode_integer(input: &[u8], prefix_bits: u8) -> Option<(usize, usize)> {
    let mask = (1u8 << prefix_bits) - 1;
    if input.is_empty() { return None; }
    let mut value = (input[0] & mask) as usize;
    let mut idx = 1;
    if value == mask as usize {
        let mut m = 0;
        loop {
            if idx >= input.len() { return None; }
            let b = input[idx]; idx +=1;
            value += ((b & 0x7F) as usize) << m;
            if b & 0x80 == 0 { break; }
            m +=7;
        }
    }
    Some((value, idx))
}

pub fn encode_integer(mut value: usize, prefix_bits: u8) -> Vec<u8> {
    let mask = (1u8 << prefix_bits) - 1;
    let mut out = Vec::new();
    if value < mask as usize {
        out.push(value as u8);
    } else {
        out.push(mask);
        value -= mask as usize;
        while value >= 0x80 {
            out.push((value as u8 & 0x7F) | 0x80);
            value >>=7;
        }
        out.push(value as u8);
    }
    out
} 