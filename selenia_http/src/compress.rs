//! コンテンツ圧縮フィルタ（現状はプレースホルダ）。
//! 外部クレート禁止のため、将来的に独自 DEFLATE/Brotli 実装を追加予定。

fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        let mut c = (crc ^ (b as u32)) & 0xFF;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        crc = (crc >> 8) ^ c;
    }
    !crc
}

fn gzip_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 25);
    // GZIP header
    out.extend_from_slice(&[
        0x1f, 0x8b, // ID
        0x08,       // deflate
        0x00,       // flags
        0x00, 0x00, 0x00, 0x00, // mtime
        0x00, // extra flags
        0xff, // OS unknown
    ]);
    // DEFLATE store block (uncompressed)
    // BFINAL=1, BTYPE=00
    out.push(0x01);
    let len = data.len() as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&( !len ).to_le_bytes());
    out.extend_from_slice(data);
    // CRC32
    let crc = crc32(data);
    out.extend_from_slice(&crc.to_le_bytes());
    // ISIZE
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

pub enum Encoding { Identity, Gzip, Brotli, Zstd }

/// Encode buffer with specified content encoding.
pub fn encode(data: &[u8], enc: Encoding) -> Vec<u8> {
    match enc {
        Encoding::Identity => data.to_vec(),
        Encoding::Gzip => gzip_fixed(data),
        Encoding::Brotli => brotli_uncompressed(data),
        Encoding::Zstd => zstd_uncompressed(data),
    }
}

// ------------- Brotli --------------
fn brotli_uncompressed(data: &[u8]) -> Vec<u8> {
    // Minimal Brotli stream: single last meta-block, uncompressed (ID=1)
    // Spec: https://www.rfc-editor.org/rfc/rfc7932
    // Header: 3 bits (last=1, type=00), length varint (data len << 1 | 1)
    let mut out = Vec::with_capacity(data.len()+4);
    // last=1, type=00 => bits 0b001 (LSB first)
    let mut header = 0b001u8; // (last=1)+(type=00)
    let mut nbits = 3u8;
    let mut len = data.len() as u32;
    // write header bits LSB-first into first byte
    let mut byte = 0u8;
    let mut written =0;
    for i in 0..3 { if (header>>i)&1==1 { byte |=1<<written; } written+=1; }
    // length varint
    loop {
        let mut bits = (len & 0x7F) as u8;
        len >>=7;
        if len==0 { bits |=0x80; }
        for i in 0..8 {
            if (bits>>i)&1==1 { byte |=1<<written; }
            written+=1;
            if written==8 { out.push(byte); byte=0; written=0; }
        }
        if bits & 0x80 !=0 { break; }
    }
    if written>0 { out.push(byte); }
    // align to next byte boundary already ensured
    out.extend_from_slice(data);
    out
}

// ------------- Zstd ----------------
fn zstd_uncompressed(data: &[u8]) -> Vec<u8> {
    // Minimal skippable frame (magic 0x184D2A50) per Zstd spec.
    let mut out = Vec::with_capacity(data.len()+8);
    out.extend_from_slice(&0x184D2A50u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

// ---------------- fixed huffman -----------------

struct BitWriter {
    buf: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    fn new() -> Self { BitWriter{buf:Vec::new(),cur:0,nbits:0} }
    fn write_bits(&mut self, mut val: u16, mut len: u8) {
        while len>0 {
            let avail = 8 - self.nbits;
            let take = len.min(avail);
            let bits = val & ((1<<take)-1);
            self.cur |= ((bits as u8) << self.nbits);
            self.nbits += take;
            val >>= take;
            len -= take;
            if self.nbits==8 {
                self.buf.push(self.cur);
                self.cur=0; self.nbits=0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits>0 { self.buf.push(self.cur); }
        self.buf
    }
}

fn rev_bits(x: u16, len: u8) -> u16 {
    let mut r=0; for i in 0..len { if x & (1<<i)!=0 { r|=1<<(len-1-i); } } r
}

fn lit_code(byte: u8) -> (u16,u8) {
    if byte<=143 {
        let code = byte as u16 + 0x30; // 8 bits
        (rev_bits(code,8),8)
    } else { // 144-255
        let code = (byte as u16 -144)+0x190; //9 bits
        (rev_bits(code,9),9)
    }
}

fn end_block_code() -> (u16,u8) { (0b0000000,7) } // 256

fn deflate_fixed_block(data: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new();
    // BFINAL=1, BTYPE=01 (fixed)
    w.write_bits(0b1,1);
    w.write_bits(0b01,2);
    for &b in data {
        let (code,len)=lit_code(b);
        w.write_bits(code,len);
    }
    let (endc,endl)=end_block_code();
    w.write_bits(endc,endl);
    w.finish()
}

fn gzip_fixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len()+30);
    // header same as gzip_store
    out.extend_from_slice(&[0x1f,0x8b,0x08,0x00,0,0,0,0,0x00,0xff]);
    let def = deflate_fixed_block(data);
    out.extend_from_slice(&def);
    let crc = crc32(data);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
} 