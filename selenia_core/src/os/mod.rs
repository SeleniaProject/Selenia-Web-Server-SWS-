//! OS-specific I/O 抽象層 (epoll/kqueue/IOCP)。
//! 外部クレート無依存で最小限の機能を提供する。

#[cfg(target_os = "linux")]
mod epoll;

#[cfg(target_os = "linux")]
pub use epoll::*;

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os="openbsd"))]
mod kqueue;

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os="openbsd"))]
pub use kqueue::*;

// EventLoop implementation is selected per platform at compile time and re-exported.
// Linux → epoll, BSD/macOS → kqueue, others → stub.

#[cfg(target_os = "linux")]
mod event_loop;
#[cfg(target_os = "linux")]
pub use event_loop::EventLoop;

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
mod event_loop_kqueue;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub use event_loop_kqueue::EventLoop;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd")))]
mod event_loop_stub;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd")))]
pub use event_loop_stub::EventLoop;

pub mod interest;
pub use interest::{Interest, Token, Event};
pub mod poller;

// The canonical `Token` alias as exported from `interest.rs` is re-exported
// above with `pub use interest::Token;` to provide a single authoritative
// definition across the crate.  A duplicated definition here would create
// two distinct types that cannot be compared and would quickly lead to
// confusing compilation errors.  Therefore the legacy alias has been
// removed.

/// Portable error type for the OS abstraction layer.
#[derive(Debug)]
pub enum OsError {
    /// Raw OS error number (positive errno / Win32 error code).
    Sys(i32),
    /// Operation is not supported on the current platform.
    Unsupported,
} 