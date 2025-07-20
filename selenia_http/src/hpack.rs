//! Minimal HPACK static table and integer/str encoding helpers.
//! This is only a skeleton sufficient for future HTTP/2 header parsing.

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