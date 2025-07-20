//! ChaCha20 stream cipher (RFC8439) minimal implementation.
//! 32-byte key, 12-byte nonce, 32-bit block counter.

#[inline]
fn rotl(a: u32, n: u32) -> u32 { (a << n) | (a >> (32 - n)) }

#[inline]
fn quarter(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = rotl(state[d], 16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = rotl(state[b], 12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = rotl(state[d], 8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = rotl(state[b], 7);
}

fn chacha20_block(key: &[u8;32], nonce: &[u8;12], counter: u32, out: &mut [u8;64]) {
    const CONSTS: [u32;4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut state = [0u32;16];
    state[..4].copy_from_slice(&CONSTS);
    for i in 0..8 {
        state[4+i] = u32::from_le_bytes([key[i*4],key[i*4+1],key[i*4+2],key[i*4+3]]);
    }
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0],nonce[1],nonce[2],nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4],nonce[5],nonce[6],nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8],nonce[9],nonce[10],nonce[11]]);

    let orig = state;
    for _ in 0..10 { // 20 rounds => 10 double rounds
        // column
        quarter(&mut state, 0,4,8,12);
        quarter(&mut state, 1,5,9,13);
        quarter(&mut state, 2,6,10,14);
        quarter(&mut state, 3,7,11,15);
        // diagonal
        quarter(&mut state, 0,5,10,15);
        quarter(&mut state, 1,6,11,12);
        quarter(&mut state, 2,7,8,13);
        quarter(&mut state, 3,4,9,14);
    }
    for i in 0..16 { state[i] = state[i].wrapping_add(orig[i]); }
    for (i,word) in state.iter().enumerate() {
        out[i*4..][..4].copy_from_slice(&word.to_le_bytes());
    }
}

/// XOR `data` in place with ChaCha20 keystream.
pub fn chacha20_xor_in_place(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut ctr = counter;
    let mut offset = 0usize;
    let mut block = [0u8; 64];
    let len = data.len();
    while offset < len {
        chacha20_block(key, nonce, ctr, &mut block);
        ctr = ctr.wrapping_add(1);
        let n = (len - offset).min(64);
        for i in 0..n {
            data[offset + i] ^= block[i];
        }
        offset += n;
    }
} 