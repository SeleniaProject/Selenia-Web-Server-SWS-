//! OS 毎の I/O 多重化実装が実装する共通トレイト

use super::interest::{Token, Interest, Event};
use core::result::Result;

pub trait Poller {
    type Error;

    fn add(&self, fd: usize, token: Token, interest: Interest) -> Result<(), Self::Error>;
    fn modify(&self, fd: usize, token: Token, interest: Interest) -> Result<(), Self::Error>;
    fn delete(&self, fd: usize) -> Result<(), Self::Error>;
    fn wait(&self, events: &mut [Event], timeout_ms: isize) -> Result<usize, Self::Error>;
} 