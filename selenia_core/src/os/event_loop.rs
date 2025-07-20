#![cfg(target_os = "linux")]

use super::{epoll::Epoll, epoll::EpollEvent, Token};
use super::interest::Interest;
use std::collections::HashMap;
use std::io::{Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};

/// 内部登録情報
struct Entry {
    fd: RawFd,
    interest: Interest,
}

/// 単純な epoll ベースイベントループ。
pub struct EventLoop {
    ep: Epoll,
    entries: HashMap<Token, Entry>,
    next_token: Token,
    events: Vec<EpollEvent>,
}

impl EventLoop {
    pub fn new() -> Result<Self> {
        Ok(EventLoop {
            ep: Epoll::new()?,
            entries: HashMap::new(),
            next_token: 1, // 0 is reserved
            events: vec![EpollEvent::default(); 1024],
        })
    }

    /// FD を登録し Token を返す。
    pub fn register<T: AsRawFd>(&mut self, io: &T, interest: Interest) -> Result<Token> {
        let fd = io.as_raw_fd();
        let token = self.next_token;
        self.next_token += 1;
        let (r, w) = match interest {
            Interest::Readable => (true, false),
            Interest::Writable => (false, true),
            Interest::ReadWrite => (true, true),
        };
        self.ep.add(fd, token, r, w)?;
        self.entries.insert(token, Entry { fd, interest });
        Ok(token)
    }

    /// 登録済み FD の待機。timeout_ms <0 でブロック。戻り値は (token, readable, writable) の列挙。
    pub fn poll(&mut self, timeout_ms: isize) -> Result<Vec<(Token, bool, bool)>> {
        let n = self.ep.wait(&mut self.events, timeout_ms)?;
        let mut out = Vec::with_capacity(n);
        for ev in self.events.iter().take(n) {
            out.push((ev.token, ev.readable, ev.writable));
        }
        Ok(out)
    }

    /// FD を削除
    pub fn deregister(&mut self, token: Token) -> Result<()> {
        if let Some(entry) = self.entries.remove(&token) {
            self.ep.delete(entry.fd)?;
        }
        Ok(())
    }
} 