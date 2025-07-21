use super::{OsError, Token};
use std::io::{Error, Result};
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

#[derive(Debug)]
pub struct Kqueue {
    kq: RawFd,
}

impl Kqueue {
    pub fn new() -> Result<Self> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(Error::last_os_error());
        }
        Ok(Kqueue { kq })
    }

    pub fn add(&self, fd: RawFd, token: Token, readable: bool, writable: bool) -> Result<()> {
        let mut changes = Vec::new();
        if readable {
            changes.push(libc::kevent {
                ident: fd as _,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD as u16,
                fflags: 0,
                data: 0,
                udata: token as _,
            });
        }
        if writable {
            changes.push(libc::kevent {
                ident: fd as _,
                filter: libc::EVFILT_WRITE,
                flags: libc::EV_ADD as u16,
                fflags: 0,
                data: 0,
                udata: token as _,
            });
        }
        let res = unsafe { libc::kevent(self.kq, changes.as_ptr(), changes.len() as i32, std::ptr::null_mut(), 0, std::ptr::null()) };
        if res < 0 { return Err(Error::last_os_error()); }
        Ok(())
    }

    pub fn delete(&self, fd: RawFd) -> Result<()> {
        let change = libc::kevent {
            ident: fd as _,
            filter: libc::EVFILT_READ,
            flags: libc::EV_DELETE as u16,
            fflags: 0,
            data: 0,
            udata: 0 as _,
        };
        unsafe { libc::kevent(self.kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        Ok(())
    }

    pub fn wait(&self, events: &mut [KEvent], timeout_ms: isize) -> Result<usize> {
        let mut raw: Vec<libc::kevent> = Vec::with_capacity(events.len());
        unsafe { raw.set_len(events.len()); }
        let ts = if timeout_ms >= 0 {
            libc::timespec {
                tv_sec: (timeout_ms / 1000) as _,
                tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
            }
        } else {
            libc::timespec { tv_sec: 0, tv_nsec: 0 }
        };
        let n = unsafe {
            libc::kevent(
                self.kq,
                std::ptr::null(),
                0,
                raw.as_mut_ptr(),
                raw.len() as i32,
                if timeout_ms >= 0 { &ts } else { std::ptr::null() },
            )
        };
        if n < 0 {
            return Err(Error::last_os_error());
        }
        for (dst, src) in events.iter_mut().zip(raw.iter().take(n as usize)) {
            dst.token = src.udata as Token;
            match src.filter {
                x if x == libc::EVFILT_READ => {
                    dst.readable = true;
                    dst.writable = false;
                }
                x if x == libc::EVFILT_WRITE => {
                    dst.readable = false;
                    dst.writable = true;
                }
                _ => {
                    dst.readable = false;
                    dst.writable = false;
                }
            }
        }
        Ok(n as usize)
    }
}

impl Drop for Kqueue { fn drop(&mut self){ unsafe{libc::close(self.kq);} } }

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KEvent {
    pub token: Token,
    pub readable: bool,
    pub writable: bool,
} 