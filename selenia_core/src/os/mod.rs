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

/// 汎用イベントソース識別子
pub type Token = usize;

/// 共通エラー型
#[derive(Debug)]
pub enum OsError {
    Sys(i32),
    Unsupported,
} 