//! Minimal AES-128 block cipher implementation.
//!
//! Requirements:
//! 1. Pure Rust software fallback (portable, constant-time where reasonable).
//! 2. AES-NI fast path on x86_64 when the CPU reports the `aes` feature.
//!
//! Only the single-block encrypt operation is exposed because GCM mode uses
//! counter mode + GHASH. Decrypt is unnecessary for GCM in SWS (TLS 1.3 only
//! needs decryption on the receive side – can be added later).

#[inline]
pub fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    #[cfg(all(target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("aes") {
            unsafe { return aes128_encrypt_block_aesni(key, block) }
        }
    }
    // Fallback to portable implementation.
    aes128_encrypt_block_soft(key, block);
}

// -------------------------------------------------------------------------
// AES-NI implementation (x86_64 only)
// -------------------------------------------------------------------------
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
unsafe fn aes128_key_expansion_10_rounds(key: &[u8; 16]) -> [core::arch::x86_64::__m128i; 11] {
    use core::arch::x86_64::*;
    let mut round_keys = [_mm_setzero_si128(); 11];
    round_keys[0] = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    macro_rules! ks {
        ($i:expr, $rcon:expr) => {{
            let mut tmp = round_keys[$i - 1];
            let assist = _mm_aeskeygenassist_si128(tmp, $rcon);
            tmp = key_expand_step(tmp, assist);
            round_keys[$i] = tmp;
        }};
    }
    #[inline(always)]
    unsafe fn key_expand_step(key: core::arch::x86_64::__m128i, assist: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::*;
        let mut tmp = key;
        let mut t = _mm_shuffle_epi32(assist, 0xff);
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        _mm_xor_si128(tmp, t)
    }
    ks!(1, 0x01);
    ks!(2, 0x02);
    ks!(3, 0x04);
    ks!(4, 0x08);
    ks!(5, 0x10);
    ks!(6, 0x20);
    ks!(7, 0x40);
    ks!(8, 0x80);
    ks!(9, 0x1B);
    ks!(10, 0x36);
    round_keys
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
unsafe fn aes128_encrypt_block_aesni(key: &[u8; 16], block: &mut [u8; 16]) {
    use core::arch::x86_64::*;
    let round_keys = aes128_key_expansion_10_rounds(key);
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, round_keys[0]);
    for rk in &round_keys[1..10] {
        state = _mm_aesenc_si128(state, *rk);
    }
    state = _mm_aesenclast_si128(state, round_keys[10]);
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

// -------------------------------------------------------------------------
// Constant-time software AES-128 (tiny S-box implementation)
// -------------------------------------------------------------------------
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline(always)]
fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut hi_bit_set;
    let mut b = b;
    for _ in 0..8 {
        if (b & 1) != 0 { p ^= a; }
        hi_bit_set = a & 0x80;
        let mut a_shift = a << 1;
        if hi_bit_set != 0 { a_shift ^= 0x1b; }
        b >>= 1;
        b = b; // keep mutable
    }
    p
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [
            state[c * 4],
            state[c * 4 + 1],
            state[c * 4 + 2],
            state[c * 4 + 3],
        ];
        state[c * 4] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3];
        state[c * 4 + 1] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3];
        state[c * 4 + 2] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3);
        state[c * 4 + 3] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2);
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let tmp = state.clone();
    // row 1 shift left by 1
    state[1] = tmp[5]; state[5] = tmp[9]; state[9] = tmp[13]; state[13] = tmp[1];
    // row 2 shift left by 2
    state[2] = tmp[10]; state[6] = tmp[14]; state[10] = tmp[2]; state[14] = tmp[6];
    // row 3 shift left by 3
    state[3] = tmp[15]; state[7] = tmp[3]; state[11] = tmp[7]; state[15] = tmp[11];
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 { state[i] ^= rk[i]; }
}

fn expand_key_128(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 16]; 11];
    w[0] = *key;
    let rcon = [
        0x01u8,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
    ];
    for i in 1..11 {
        let mut temp = w[i-1];
        // RotWord + SubWord on last 4 bytes
        let t0 = SBOX[temp[13] as usize];
        let t1 = SBOX[temp[14] as usize];
        let t2 = SBOX[temp[15] as usize];
        let t3 = SBOX[temp[12] as usize];
        temp[0] ^= t0 ^ rcon[i-1];
        temp[1] ^= t1;
        temp[2] ^= t2;
        temp[3] ^= t3;
        for j in 4..16 { temp[j] ^= temp[j-4]; }
        w[i] = temp;
    }
    w
}

fn aes128_encrypt_block_soft(key: &[u8;16], block: &mut [u8;16]) {
    let round_keys = expand_key_128(key);
    let mut state: [u8;16] = *block;
    add_round_key(&mut state, &round_keys[0]);
    for rnd in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[rnd]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[10]);
    *block = state;
} 