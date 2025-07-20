#![no_main]
use libfuzzer_sys::fuzz_target;
use selenia_http::http3::{is_initial, build_version_negotiation};

fuzz_target!(|data: &[u8]| {
    if is_initial(data) {
        let _ = build_version_negotiation(data);
    }
}); 