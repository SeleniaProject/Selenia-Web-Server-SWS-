//! Windows-specific EventLoop backed by IOCP.
#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::io::Result;
use std::os::windows::io::{AsRawSocket, RawSocket};

use super::interest::{Event, Interest, Token};
use super::iocp::Iocp;
use super::poller::Poller;

/// Cross-platform EventLoop facade for Windows.
pub struct EventLoop {
    iocp: Iocp,
    next_token: Token,
    entries: HashMap<Token, RawSocket>,
    events: Vec<Event>,
}

impl EventLoop {
    /// Constructs a new IOCP-backed event loop with pre-allocated buffer.
    pub fn new() -> Result<Self> {
        Ok(Self {
            iocp: Iocp::new()?,
            next_token: 1, // 0 is reserved sentinel as on Unix variants.
            entries: HashMap::new(),
            events: vec![Event { token: 0, readable: false, writable: false }; 1024],
        })
    }

    /// Registers `io` with the completion port and returns an opaque token.
    pub fn register<T: AsRawSocket>(&mut self, io: &T, interest: Interest) -> Result<Token> {
        let handle = io.as_raw_socket();
        let token = self.next_token;
        self.next_token += 1;
        self.iocp.add(handle as usize, token, interest)?;
        self.entries.insert(token, handle);
        Ok(token)
    }

    /// Waits for I/O completions, returning `(token, readable, writable)` tuples.
    pub fn poll(&mut self, timeout_ms: isize) -> Result<Vec<(Token, bool, bool)>> {
        let ready = self.iocp.wait(&mut self.events, timeout_ms)?;
        let mut out = Vec::with_capacity(ready);
        for ev in self.events.iter().take(ready) {
            out.push((ev.token, ev.readable, ev.writable));
        }
        Ok(out)
    }

    /// Removes the associated handle; closing the socket is sufficient on Windows.
    pub fn deregister(&mut self, token: Token) -> Result<()> {
        self.entries.remove(&token);
        Ok(())
    }
} 