use super::{OsError, Token};
use std::io::{Error, Result};
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

const MAX_EVENTS: usize = 1024;

#[derive(Debug)]
pub struct Epoll {
    fd: RawFd,
}

impl Epoll {
    pub fn new() -> Result<Self> {
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        Ok(Epoll { fd })
    }

    pub fn add(&self, fd: RawFd, token: Token, readable: bool, writable: bool) -> Result<()> {
        let mut ev = libc::epoll_event {
            events: ((readable as u32) * libc::EPOLLIN as u32)
                | ((writable as u32) * libc::EPOLLOUT as u32),
            u64: token as u64,
        };
        let res = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
        if res < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn modify(&self, fd: RawFd, token: Token, readable: bool, writable: bool) -> Result<()> {
        let mut ev = libc::epoll_event {
            events: ((readable as u32) * libc::EPOLLIN as u32)
                | ((writable as u32) * libc::EPOLLOUT as u32),
            u64: token as u64,
        };
        let res = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_MOD, fd, &mut ev) };
        if res < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn delete(&self, fd: RawFd) -> Result<()> {
        let res = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
        if res < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn wait(&self, events: &mut [EpollEvent], timeout_ms: isize) -> Result<usize> {
        // Keep a temporary buffer of raw epoll_event so we do not rely on transmuting between
        // our safe wrapper and the libc representation. This avoids undefined behaviour caused by
        // mismatching struct layouts and different padding on various architectures.
        let mut raw: Vec<libc::epoll_event> = Vec::with_capacity(events.len());
        // SAFETY: The buffer is immediately initialised by the kernel through epoll_wait; the
        // kernel completely overwrites every entry up to the returned length. We therefore do not
        // need to pre-initialise the memory here.
        unsafe { raw.set_len(events.len()); }

        let n = unsafe {
            libc::epoll_wait(
                self.fd,
                raw.as_mut_ptr(),
                raw.len() as i32,
                timeout_ms as i32,
            )
        };
        if n < 0 {
            return Err(Error::last_os_error());
        }

        // Translate the raw events into our portable EpollEvent representation.
        for (dst, src) in events.iter_mut().zip(raw.iter().take(n as usize)) {
            let ev = src.events;
            dst.token = src.u64 as Token;
            dst.readable = ev & (libc::EPOLLIN as u32) != 0;
            dst.writable = ev & (libc::EPOLLOUT as u32) != 0;
        }
        Ok(n as usize)
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EpollEvent {
    pub token: Token,
    pub readable: bool,
    pub writable: bool,
}

impl Default for EpollEvent {
    fn default() -> Self {
        EpollEvent {
            token: 0,
            readable: false,
            writable: false,
        }
    }
} 