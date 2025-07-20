#![no_main]
use libfuzzer_sys::fuzz_target;
use selenia_http::hpack::HpackDecoder;

fuzz_target!(|data: &[u8]| {
    let mut dec = HpackDecoder::new();
    let _ = dec.decode(data);
}); 