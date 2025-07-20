#![cfg(unix)]
//! Minimal POSIX signal handling without external crates.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use libc::{sigaction, sighandler_t, SIGINT, SIGTERM, SA_RESTART, SIGHUP};

static INIT: Once = Once::new();
static TERMINATE: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sig(sig: i32) {
    match sig {
        SIGINT | SIGTERM => TERMINATE.store(true, Ordering::SeqCst),
        SIGHUP => RELOAD.store(true, Ordering::SeqCst),
        _ => {},
    }
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
        let _ = sigaction(SIGHUP, &action, std::ptr::null_mut());
    });
}

/// Returns true if termination signal received.
pub fn should_terminate() -> bool { TERMINATE.load(Ordering::SeqCst) }

/// Returns true if reload requested (SIGHUP) and clears flag.
pub fn take_reload_request() -> bool {
    RELOAD.swap(false, Ordering::SeqCst)
} 