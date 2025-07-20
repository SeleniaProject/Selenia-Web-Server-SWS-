//! Very simple WAF hook point.
//! Plugins can register filters that inspect (method, path, headers) and decide to allow or block.

use std::sync::{RwLock, Once};

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
    for filt in filters().read().unwrap().iter() {
        if !filt.check(method, path, headers) { return false; }
    }
    true
} 