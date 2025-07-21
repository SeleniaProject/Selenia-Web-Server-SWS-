//! Very simple WAF hook point.
//! Plugins can register filters that inspect (method, path, headers) and decide to allow or block.

use std::sync::{RwLock, Once};
use std::time::Instant;

// ---------------- Built-in heuristics WAF ----------------

/// Simple heuristic rules (substring match) compiled into the binary.
static COMMON_ATTACK_PATTERNS: &[&str] = &[
    "../",               // directory traversal
    "%2e%2e/",           // encoded traversal
    "union select",      // SQLi
    "<script",           // XSS
    "\x3cscript",        // encoded XSS
    " or 1=1",           // SQLi boolean
    "etc/passwd",        // sensitive file
];

/// Filter that blocks requests whose path or headers contain common attack patterns.
struct BuiltinWaf;

impl RequestFilter for BuiltinWaf {
    fn check(&self, _method: &str, path: &str, headers: &[(String,String)]) -> bool {
        let mut target = path.to_ascii_lowercase();
        for (k,v) in headers { if k.eq_ignore_ascii_case("user-agent") || k.eq_ignore_ascii_case("referer") {
            target.push_str(&v.to_ascii_lowercase()); }
        }
        for pat in COMMON_ATTACK_PATTERNS { if target.contains(pat) { return false; } }
        true
    }
}

// Auto-register built-in rules at first use
fn ensure_builtin() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| { register_filter(BuiltinWaf); });
}

static INIT: Once = Once::new();
static mut FILTERS: Option<RwLock<Vec<Box<dyn RequestFilter + Send + Sync>>>> = None;

fn filters() -> &'static RwLock<Vec<Box<dyn RequestFilter + Send + Sync>>> {
    unsafe {
        INIT.call_once(|| {
            FILTERS = Some(RwLock::new(Vec::new()));
        });
        FILTERS.as_ref().unwrap()
    }
}

/// Trait for request filtering.
pub trait RequestFilter {
    /// Return true to allow request, false to block.
    fn check(&self, method: &str, path: &str, headers: &[(String,String)]) -> bool;
}

/// Register a new filter (called by plugins).
pub fn register_filter<F: RequestFilter + Send + Sync + 'static>(f: F) {
    filters().write().unwrap().push(Box::new(f));
}

/// Evaluate all filters. Returns true if all passed.
pub fn evaluate(method: &str, path: &str, headers: &[(String,String)]) -> bool {
    ensure_builtin();
    for filt in filters().read().unwrap().iter() {
        if !filt.check(method, path, headers) { return false; }
    }
    true
} 