#![cfg(unix)]
//! Minimal POSIX signal handling without external crates.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use libc::{sigaction, sighandler_t, SIGINT, SIGTERM, SA_RESTART};

static INIT: Once = Once::new();
static TERMINATE: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sig(_sig: i32) {
    TERMINATE.store(true, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers (idempotent).
pub fn init_term_signals() {
    INIT.call_once(|| unsafe {
        let handler: sighandler_t = handle_sig as sighandler_t;
        let action = sigaction {
            sa_sigaction: handler,
            sa_flags: SA_RESTART,
            sa_mask: std::mem::zeroed(),
        };
        let _ = sigaction(SIGINT, &action, std::ptr::null_mut());
        let _ = sigaction(SIGTERM, &action, std::ptr::null_mut());
    });
}

/// Returns true if termination signal received.
pub fn should_terminate() -> bool { TERMINATE.load(Ordering::SeqCst) } 