#![no_main]
use libfuzzer_sys::fuzz_target;
use selenia_http::parser::Parser;

fuzz_target!(|data: &[u8]| {
    let mut p = Parser::new();
    let _ = p.advance(data);
}); 