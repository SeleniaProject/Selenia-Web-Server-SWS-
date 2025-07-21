//! Adaptive Keep-Alive header tuning based on connection reuse statistics.
//! 
//! This is a very lightweight heuristic – **not** a full-blown predictive
//! model – but it is good enough to dynamically adjust the `timeout` and `max`
//! values of the `Keep-Alive` response header so that busy deployments keep
//! connections open longer while low-traffic servers release them sooner.
//!
//! Algorithm (per DESIGN.md §2.1):
//! 1. Count *new* TCP connections and *reused* requests on an existing
//!    connection over a sliding window.
//! 2. If the *reuse ratio* (`reused / new`) > 1.5 we extend the timeout
//!    gradually up to 120 s and `max` up to 500.
//! 3. If the ratio < 0.5 we shorten the timeout down to 10 s and `max` 50.
//! 4. Values decay slowly (EMA) so they do not oscillate.
//!
//! All counters are global atomics so that tuning is **lock-free** and cheap
//! even under heavy load.

use core::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// --- Tunable constants ------------------------------------------------------

const TIMEOUT_MIN: u32 = 10;
const TIMEOUT_MAX: u32 = 120;
const MAX_MIN: u32 = 50;
const MAX_MAX: u32 = 500;

// Exponential-moving-average factor (0 < α ≤ 1).  Smaller = smoother.
const ALPHA: f64 = 0.2;

// Re-evaluation period (milliseconds).  A coarse period keeps overhead low.
const PERIOD_MS: u64 = 5_000;

// --- Global state -----------------------------------------------------------

static NEW_CONN: AtomicU64 = AtomicU64::new(0);
static REUSE_REQ: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_CUR: AtomicU64 = AtomicU64::new(30); // start at 30 s
static MAX_CUR: AtomicU64 = AtomicU64::new(100);
static LAST_EVAL: AtomicU64 = AtomicU64::new(0);

#[inline]
fn now_ms() -> u64 { Instant::now().elapsed().as_millis() as u64 }

/// Record a **new** TCP connection.
pub fn record_new_conn() {
    NEW_CONN.fetch_add(1, Ordering::Relaxed);
    maybe_eval();
}

/// Record a **reused** request on an existing keep-alive connection.
pub fn record_reuse_req() {
    REUSE_REQ.fetch_add(1, Ordering::Relaxed);
    maybe_eval();
}

/// Current Keep-Alive parameters (timeout, max) to be advertised.
#[inline]
pub fn current() -> (u32, u32) {
    (
        TIMEOUT_CUR.load(Ordering::Relaxed) as u32,
        MAX_CUR.load(Ordering::Relaxed) as u32,
    )
}

// -----------------------------------------------------------------------------
// Internal – evaluate ratio and update parameters.
// -----------------------------------------------------------------------------

fn maybe_eval() {
    let last = LAST_EVAL.load(Ordering::Acquire);
    let now = now_ms();
    if now - last < PERIOD_MS { return; }
    if LAST_EVAL
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        // Another thread is doing the evaluation.
        return;
    }

    let new = NEW_CONN.swap(0, Ordering::AcqRel) as f64;
    let reuse = REUSE_REQ.swap(0, Ordering::AcqRel) as f64;

    // Avoid division by zero.
    let ratio = if new < 1.0 { 0.0 } else { reuse / new };

    // Desired targets based on ratio thresholds.
    let (timeout_target, max_target) = if ratio > 1.5 {
        (TIMEOUT_MAX, MAX_MAX)
    } else if ratio < 0.5 {
        (TIMEOUT_MIN, MAX_MIN)
    } else {
        // Within hysteresis – keep current.
        let cur_t = TIMEOUT_CUR.load(Ordering::Relaxed) as u32;
        let cur_m = MAX_CUR.load(Ordering::Relaxed) as u32;
        (cur_t, cur_m)
    };

    // Apply EMA smoothing.
    let cur_timeout = TIMEOUT_CUR.load(Ordering::Relaxed) as f64;
    let cur_max = MAX_CUR.load(Ordering::Relaxed) as f64;

    let new_timeout = (1.0 - ALPHA) * cur_timeout + ALPHA * (timeout_target as f64);
    let new_max = (1.0 - ALPHA) * cur_max + ALPHA * (max_target as f64);

    TIMEOUT_CUR.store(new_timeout.round() as u64, Ordering::Release);
    MAX_CUR.store(new_max.round() as u64, Ordering::Release);
} 