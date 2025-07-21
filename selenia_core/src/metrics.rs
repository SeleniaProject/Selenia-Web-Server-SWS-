use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Global counters for Prometheus metrics exposition.
/// No external crate is used; all counters are relaxed atomics.
static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
static ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);

// -----------------------------------------------------------------------------
// Latency histogram (microseconds) – fixed buckets.
// -----------------------------------------------------------------------------

const LAT_BUCKETS: [u64; 10] = [
    1_000,      // 1 ms
    5_000,      // 5 ms
    10_000,     // 10 ms
    25_000,     // 25 ms
    50_000,     // 50 ms
    100_000,    // 100 ms
    250_000,    // 250 ms
    500_000,    // 500 ms
    1_000_000,  // 1 s
    5_000_000,  // 5 s
];

// Atomic counters per bucket.
static LAT_COUNTS: [AtomicU64; LAT_BUCKETS.len()] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)
];
static LAT_SUM_US: AtomicU64 = AtomicU64::new(0);
static LAT_TOTAL: AtomicU64 = AtomicU64::new(0);

// Reload state gauge (0=Idle,1=ReloadRequest,2=Forking,3=Promote,4=Drain)
static RELOAD_STATE: AtomicU64 = AtomicU64::new(0);

pub fn set_reload_state(v: u64) { RELOAD_STATE.store(v, Ordering::Relaxed); }

/// Observe request latency in `Duration`.
pub fn observe_latency(d: Duration) {
    let us = d.as_micros() as u64;
    // find bucket index
    for (i, &thr) in LAT_BUCKETS.iter().enumerate() {
        if us <= thr {
            LAT_COUNTS[i].fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    LAT_SUM_US.fetch_add(us, Ordering::Relaxed);
    LAT_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Increase total HTTP requests.
pub fn inc_requests() { REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed); }
/// Add to total bytes served.
pub fn add_bytes(n: u64) { BYTES_TOTAL.fetch_add(n, Ordering::Relaxed); }
/// Increase error count (4xx/5xx).
pub fn inc_errors() { ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed); }

/// Render metrics in Prometheus exposition format.
pub fn render() -> String {
    // Counters
    let mut out = format!("# TYPE sws_requests_total counter\nsws_requests_total {}\n# TYPE sws_bytes_total counter\nsws_bytes_total {}\n# TYPE sws_errors_total counter\nsws_errors_total {}\n", REQUESTS_TOTAL.load(Ordering::Relaxed), BYTES_TOTAL.load(Ordering::Relaxed), ERRORS_TOTAL.load(Ordering::Relaxed));

    // Histogram buckets
    out.push_str("# TYPE sws_http_request_duration_seconds histogram\n");
    let mut cumulative = 0u64;
    for (i, &thr) in LAT_BUCKETS.iter().enumerate() {
        let cnt = LAT_COUNTS[i].load(Ordering::Relaxed);
        cumulative += cnt;
        let le = (thr as f64) / 1_000_000f64; // seconds
        out.push_str(&format!("sws_http_request_duration_seconds_bucket{{le=\"{:.3}\"}} {}\n", le, cumulative));
    }
    // +Inf bucket
    let total = LAT_TOTAL.load(Ordering::Relaxed);
    out.push_str(&format!("sws_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n", total));
    let sum_sec = (LAT_SUM_US.load(Ordering::Relaxed) as f64) / 1_000_000f64;
    out.push_str(&format!("sws_http_request_duration_seconds_sum {}\n", sum_sec));
    out.push_str(&format!("sws_http_request_duration_seconds_count {}\n", total));

    // Summary – p50, p90, p99 approximation from histogram.
    out.push_str("# TYPE sws_http_request_duration_seconds summary\n");
    let quantiles = [(0.5f64, "0.5"), (0.9, "0.9"), (0.99, "0.99")];
    for &(q, label) in &quantiles {
        let target = (total as f64 * q).round() as u64;
        let mut acc = 0u64;
        let mut val_sec = 0f64;
        for (i, &thr) in LAT_BUCKETS.iter().enumerate() {
            acc += LAT_COUNTS[i].load(Ordering::Relaxed);
            if acc >= target {
                val_sec = (thr as f64)/1_000_000f64;
                break;
            }
        }
        if total == 0 { val_sec = 0.0; }
        out.push_str(&format!("sws_http_request_duration_seconds{{quantile=\"{}\"}} {:.6}\n", label, val_sec));
    }
    out.push_str(&format!("sws_http_request_duration_seconds_sum {}\n", sum_sec));
    out.push_str(&format!("sws_http_request_duration_seconds_count {}\n", total));

    out.push_str(&format!("# TYPE sws_reload_state gauge\nsws_reload_state {}\n", RELOAD_STATE.load(Ordering::Relaxed)));

    out
} 