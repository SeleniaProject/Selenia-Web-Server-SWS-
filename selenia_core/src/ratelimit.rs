//! Simple token bucket rate-limiter keyed by client IP address.
//! Configurable `capacity` and `refill_per_sec`. No external crates.

use std::collections::HashMap;
use std::sync::{Mutex, Once};
use std::time::{Instant, Duration};

#[derive(Clone)]
struct Bucket { tokens: f64, last: Instant }

static INIT: Once = Once::new();
static mut STATE: Option<Mutex<State>> = None;

struct State {
    cap: f64,
    rate: f64,
    map: HashMap<String, Bucket>,
}

fn state() -> &'static Mutex<State> {
    unsafe {
        INIT.call_once(|| {
            STATE = Some(Mutex::new(State{cap:60.0, rate:1.0, map:HashMap::new()}));
        });
        STATE.as_ref().unwrap()
    }
}

pub fn configure(capacity:u32, refill_per_sec:u32) {
    let mut st=state().lock().unwrap();
    st.cap=capacity as f64;
    st.rate=refill_per_sec as f64;
}

pub fn allow(ip:&str) -> bool {
    let mut st=state().lock().unwrap();
    let now=Instant::now();
    let b = st.map.entry(ip.to_string()).or_insert(Bucket{tokens:st.cap,last:now});
    let elapsed=now.duration_since(b.last).as_secs_f64();
    b.tokens=(b.tokens + elapsed*st.rate).min(st.cap);
    b.last=now;
    if b.tokens>=1.0 { b.tokens-=1.0; true } else { false }
} 