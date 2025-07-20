#![cfg(any(target_os = "macos", target_os = "freebsd", target_os="openbsd"))]

//! Kqueue-based EventLoop implementation for BSD family systems.
//! Mirrors the Linux epoll variant to maintain a consistent public API.

use super::{kqueue::Kqueue, kqueue::KEvent, Token};
use super::interest::Interest;
use std::collections::HashMap;
use std::io::{Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};

/// Internal registration record.
struct Entry {
    fd: RawFd,
    interest: Interest,
}

/// Cross-platform EventLoop backed by kqueue.
pub struct EventLoop {
    kq: Kqueue,
    entries: HashMap<Token, Entry>,
    next_token: Token,
    events: Vec<KEvent>,
}

impl EventLoop {
    /// Creates a new kqueue instance and supporting buffers.
    pub fn new() -> Result<Self> {
        Ok(EventLoop {
            kq: Kqueue::new()?,
            entries: HashMap::new(),
            next_token: 1, // 0 is reserved
            events: vec![KEvent::default(); 1024],
        })
    }

    /// Registers an FD with given interest, returning a unique Token.
    pub fn register<T: AsRawFd>(&mut self, io: &T, interest: Interest) -> Result<Token> {
        let fd = io.as_raw_fd();
        let token = self.next_token;
        self.next_token += 1;
        let (r, w) = match interest {
            Interest::Readable => (true, false),
            Interest::Writable => (false, true),
            Interest::ReadWrite => (true, true),
        };
        self.kq.add(fd, token, r, w)?;
        self.entries.insert(token, Entry { fd, interest });
        Ok(token)
    }

    /// Waits for events and returns at most `events.len()` ready items.
    pub fn poll(&mut self, timeout_ms: isize) -> Result<Vec<(Token, bool, bool)>> {
        let n = self.kq.wait(&mut self.events, timeout_ms)?;
        let mut out = Vec::with_capacity(n);
        for ev in self.events.iter().take(n) {
            out.push((ev.token, ev.readable, ev.writable));
        }
        Ok(out)
    }

    /// Deregisters the FD associated with the token.
    pub fn deregister(&mut self, token: Token) -> Result<()> {
        if let Some(entry) = self.entries.remove(&token) {
            self.kq.delete(entry.fd)?;
        }
        Ok(())
    }
} 