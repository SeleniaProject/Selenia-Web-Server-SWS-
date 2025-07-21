//! W3C Trace Context (traceparent) utilities.
//! Provides parse and generate helpers for automatic propagation.

use crate::crypto::rand::fill_random;

#[derive(Clone,Copy)]
pub struct TraceContext {
    pub trace_id: [u8;16],
    pub span_id: [u8;8],
    pub sampled: bool,
}

// internal hex helpers
fn to_hex(bytes:&[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }
fn from_hex(s:&str) -> Option<Vec<u8>> {
    if s.len()%2!=0 { return None; }
    let mut out=Vec::with_capacity(s.len()/2);
    let bytes=s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = char::from(bytes[i]).to_digit(16)?;
        let lo = char::from(bytes[i+1]).to_digit(16)?;
        out.push(((hi<<4)|lo) as u8);
    }
    Some(out)
}

impl TraceContext {
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len()!=4 || parts[0]!="00" { return None; }
        let trace_id_bytes = from_hex(parts[1])?;
        let span_id_bytes = from_hex(parts[2])?;
        if trace_id_bytes.len()!=16 || span_id_bytes.len()!=8 { return None; }
        let mut trace_id=[0u8;16]; trace_id.copy_from_slice(&trace_id_bytes);
        let mut span_id=[0u8;8]; span_id.copy_from_slice(&span_id_bytes);
        let sampled = parts[3]=="01";
        Some(TraceContext{trace_id,span_id,sampled})
    }

    pub fn generate() -> Self {
        let mut trace_id=[0u8;16]; let _=fill_random(&mut trace_id);
        let mut span_id=[0u8;8]; let _=fill_random(&mut span_id);
        Self{trace_id,span_id,sampled:true}
    }

    pub fn header(&self) -> String {
        format!("00-{}-{}-{:02x}", to_hex(&self.trace_id), to_hex(&self.span_id), if self.sampled { 1 } else { 0 })
    }
} 