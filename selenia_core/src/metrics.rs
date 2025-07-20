use std::sync::atomic::{AtomicU64, Ordering};

/// Global counters for Prometheus metrics exposition.
/// No external crate is used; all counters are relaxed atomics.
static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
static ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Increase total HTTP requests.
pub fn inc_requests() { REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed); }
/// Add to total bytes served.
pub fn add_bytes(n: u64) { BYTES_TOTAL.fetch_add(n, Ordering::Relaxed); }
/// Increase error count (4xx/5xx).
pub fn inc_errors() { ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed); }

/// Render metrics in Prometheus exposition format.
pub fn render() -> String {
    format!("# TYPE sws_requests_total counter\nsws_requests_total {}\n# TYPE sws_bytes_total counter\nsws_bytes_total {}\n# TYPE sws_errors_total counter\nsws_errors_total {}\n", REQUESTS_TOTAL.load(Ordering::Relaxed), BYTES_TOTAL.load(Ordering::Relaxed), ERRORS_TOTAL.load(Ordering::Relaxed))
} 