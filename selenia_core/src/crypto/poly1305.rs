//! Poly1305 one-time authenticator (RFC 8439) minimal implementation.

pub fn poly1305_tag(msg: &[u8], key: &[u8;32]) -> [u8;16] {
    // r: clamp bits
    let mut r = [0u32;5];
    r[0] = (u32::from_le_bytes([key[0],key[1],key[2],key[3]])    ) & 0x3ffffff;
    r[1] = (u32::from_le_bytes([key[3],key[4],key[5],key[6]])>>2) & 0x3ffff03;
    r[2] = (u32::from_le_bytes([key[6],key[7],key[8],key[9]])>>4) & 0x3ffc0ff;
    r[3] = (u32::from_le_bytes([key[9],key[10],key[11],key[12]])>>6) & 0x3f03fff;
    r[4] = (u32::from_le_bytes([key[12],key[13],key[14],key[15]])>>8) & 0x00fffff;

    let mut acc = [0u32;5];
    let mut n = msg;
    while !n.is_empty() {
        let mut block = [0u8;17]; // 16 bytes + 1
        let take = n.len().min(16);
        block[..take].copy_from_slice(&n[..take]);
        block[take] = 1; // add 1 bit (little endian => byte)

        let mut t = [0u32;5];
        t[0] = (u32::from_le_bytes([block[0],block[1],block[2],block[3]])) & 0x3ffffff;
        t[1] = (u32::from_le_bytes([block[3],block[4],block[5],block[6]])>>2) & 0x3ffffff;
        t[2] = (u32::from_le_bytes([block[6],block[7],block[8],block[9]])>>4) & 0x3ffffff;
        t[3] = (u32::from_le_bytes([block[9],block[10],block[11],block[12]])>>6) & 0x3ffffff;
        t[4] = (u32::from_le_bytes([block[12],block[13],block[14],block[15]])>>8) | ((block[16] as u32) << 16);

        // acc += t
        let mut carry: u64 = 0;
        for i in 0..5 {
            carry = carry + acc[i] as u64 + t[i] as u64;
            acc[i] = carry as u32 & 0x3ffffff;
            carry >>= 26;
        }
        acc[0] += (carry as u32) * 5;
        // acc = acc * r (mod 2^130-5)
        let mut prod = [0u64;5];
        for i in 0..5 {
            for j in 0..5 {
                prod[(i+j)%5] += (acc[i] as u64) * (r[j] as u64);
            }
        }
        // partial reduction
        let mut c=0u64;
        for i in 0..5 {
            prod[i]+=c;
            acc[i] = (prod[i] & 0x3ffffff) as u32;
            c = prod[i] >> 26;
        }
        acc[0] += (c as u32)*5;

        n = &n[take..];
    }

    // final reduction
    let mut c = acc[0] >> 26; acc[0] &= 0x3ffffff; acc[1]+=c;
    c = acc[1] >> 26; acc[1] &= 0x3ffffff; acc[2]+=c;
    c = acc[2] >> 26; acc[2] &= 0x3ffffff; acc[3]+=c;
    c = acc[3] >> 26; acc[3] &= 0x3ffffff; acc[4]+=c;
    c = acc[4] >> 26; acc[4] &= 0x3ffffff; acc[0]+= (c as u32) *5;

    // compare to p
    let mut s = acc;
    s[0] = s[0].wrapping_add(5);
    let mut carry = s[0] >> 26; s[0] &= 0x3ffffff;
    for i in 1..5 {
        s[i] = s[i].wrapping_add(carry);
        carry = s[i] >> 26; s[i] &= 0x3ffffff;
    }
    let mask = (carry ^1) -1; // all 1 if no carry (acc >= p)
    for i in 0..5 { acc[i] = (acc[i] & !mask) | (s[i] & mask); }

    // serialize (little endian 128-bit)
    let mut tag = [0u8;16];
    let mut t=0u32;
    t = acc[0] | (acc[1]<<26);
    tag[0..4].copy_from_slice(&t.to_le_bytes());
    t = (acc[1]>>6) | (acc[2]<<20);
    tag[4..8].copy_from_slice(&t.to_le_bytes());
    t = (acc[2]>>12) | (acc[3]<<14);
    tag[8..12].copy_from_slice(&t.to_le_bytes());
    t = (acc[3]>>18) | (acc[4]<<8);
    tag[12..16].copy_from_slice(&t.to_le_bytes());

    // add s (key[16..32])
    let mut carry_u16: u16 = 0;
    for i in 0..16 {
        let sum = (tag[i] as u16) + (key[16+i] as u16) + carry_u16;
        tag[i] = sum as u8;
        carry_u16 = sum >> 8;
    }

    tag
} 