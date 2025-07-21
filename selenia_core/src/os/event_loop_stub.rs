#![cfg(not(unix))]

//! Fallback EventLoop stub for non-Unix targets.
//! It satisfies the trait surface but does no polling; the HTTP server
//! on non-Unix targets uses a thread-per-connection model instead.

use crate::os::interest::{Token, Interest};

#[derive(Debug, Default)]
pub struct EventLoop;

impl EventLoop {
    pub fn new() -> Result<Self, ()> { Ok(EventLoop) }
    pub fn register<T>(&mut self, _io:&T, _interest: Interest) -> Result<Token, ()> { Ok(0) }
    pub fn poll(&mut self, _timeout_ms:isize) -> Result<Vec<(Token,bool,bool)>, ()> { Ok(Vec::new()) }
    pub fn deregister(&mut self,_tok:Token) -> Result<(), ()> { Ok(()) }
} 