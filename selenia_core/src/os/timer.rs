//! Cross-platform high-resolution timer abstraction.
//!
//! This module provides a lightweight wrapper over the native timer
//! facilities offered by each platform, unifying them behind a single
//! `Timer` API:
//!
//! * Linux   → `timerfd_create` (CLOCK_MONOTONIC)
//! * macOS/BSD → `kqueue` + `EVFILT_TIMER`
//! * Windows  → `CreateWaitableTimerExW`
//!
//! The implementation intentionally exposes only the primitives required by
//! SWS: create a timer with a given interval (one-shot or periodic) and wait
//! for its expiry.  Higher-level scheduling is built on top of this. 
use std::io::{Error, Result};

/// Portable timer handle.
pub struct Timer(TimerInner);

impl Timer {
    /// Creates a new timer that expires after `interval_ms`. If `periodic` is
    /// true the timer will automatically re-arm with the same interval.
    pub fn new(interval_ms: u64, periodic: bool) -> Result<Self> {
        TimerInner::new(interval_ms, periodic).map(Self)
    }

    /// Blocks the current thread until the timer expires.
    pub fn wait(&self) -> Result<()> {
        self.0.wait()
    }
}

// -----------------------------------------------------------------------------
// Platform-specific implementations
// -----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::prelude::FromRawFd;
    use std::fs::File;
    use std::io::Read;

    pub struct TimerInner {
        fd: File,
        periodic: bool,
    }

    impl TimerInner {
        pub fn new(interval_ms: u64, periodic: bool) -> Result<Self> {
            // SAFETY: timerfd_create is an async-signal-safe system call.
            let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
            if fd < 0 {
                return Err(Error::last_os_error());
            }

            let new_value = libc::itimerspec {
                it_interval: if periodic {
                    libc::timespec {
                        tv_sec: (interval_ms / 1000) as _,
                        tv_nsec: ((interval_ms % 1000) * 1_000_000) as _,
                    }
                } else {
                    libc::timespec { tv_sec: 0, tv_nsec: 0 }
                },
                it_value: libc::timespec {
                    tv_sec: (interval_ms / 1000) as _,
                    tv_nsec: ((interval_ms % 1000) * 1_000_000) as _,
                },
            };

            // SAFETY: the call takes a valid fd and pointer.
            let res = unsafe { libc::timerfd_settime(fd, 0, &new_value, std::ptr::null_mut()) };
            if res < 0 {
                return Err(Error::last_os_error());
            }

            let file = unsafe { File::from_raw_fd(fd) };
            Ok(Self { fd: file, periodic })
        }

        pub fn wait(&self) -> Result<()> {
            let mut buf = [0u8; 8];
            // Reading clears the expirations counter.
            self.fd.read_exact(&mut buf)?;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
use sys::TimerInner; 

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os="openbsd"))]
mod sys {
    use super::*;
    use std::os::unix::io::RawFd;
    use std::mem::{self, MaybeUninit};

    #[repr(C)]
    struct KEvent(libc::kevent);

    pub struct TimerInner {
        kq: RawFd,
        ident: libc::uintptr_t,
    }

    impl TimerInner {
        pub fn new(interval_ms: u64, periodic: bool) -> Result<Self> {
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return Err(Error::last_os_error());
            }
            let ident = 1; // arbitrary ID for the timer
            let flags = if periodic { libc::EV_ADD | libc::EV_ENABLE } else { libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT };
            let mut kev = libc::kevent {
                ident,
                filter: libc::EVFILT_TIMER,
                flags: flags as u16,
                fflags: 0,
                data: interval_ms as i64, // data is milliseconds for EVFILT_TIMER
                udata: std::ptr::null_mut(),
            };
            let res = unsafe { libc::kevent(kq, &mut kev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            if res < 0 {
                return Err(Error::last_os_error());
            }
            Ok(Self { kq, ident })
        }

        pub fn wait(&self) -> Result<()> {
            let mut kev: libc::kevent = unsafe { mem::zeroed() };
            let res = unsafe { libc::kevent(self.kq, std::ptr::null(), 0, &mut kev, 1, std::ptr::null()) };
            if res < 0 {
                return Err(Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for TimerInner {
        fn drop(&mut self) {
            unsafe { libc::close(self.kq) };
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os="openbsd"))]
use sys::TimerInner;

#[cfg(target_os = "windows")]
mod sys {
    use super::*;
    use core::ptr::null_mut;

    type HANDLE = *mut core::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;

    const FALSE: BOOL = 0;
    const WAIT_OBJECT_0: DWORD = 0x00000000;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateWaitableTimerExW(
            lpTimerAttributes: *mut core::ffi::c_void,
            lpTimerName: *const u16,
            dwFlags: DWORD,
            dwDesiredAccess: DWORD,
        ) -> HANDLE;

        fn SetWaitableTimer(
            hTimer: HANDLE,
            lpDueTime: *const i64,
            lPeriod: i32,
            pfnCompletionRoutine: *mut core::ffi::c_void,
            lpArgToCompletionRoutine: *mut core::ffi::c_void,
            fResume: BOOL,
        ) -> BOOL;

        fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;

        fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    pub struct TimerInner {
        handle: HANDLE,
    }

    impl TimerInner {
        pub fn new(interval_ms: u64, periodic: bool) -> Result<Self> {
            unsafe {
                let handle = CreateWaitableTimerExW(null_mut(), null_mut(), 0, 0x001F0003);
                if handle.is_null() {
                    return Err(Error::last_os_error());
                }
                // Due time is specified as 100-ns intervals *relative* (negative)
                let mut due_time: i64 = -((interval_ms as i64) * 10_000);
                let period = if periodic { interval_ms as i32 } else { 0 };
                let ok = SetWaitableTimer(handle, &due_time as *const _, period, null_mut(), null_mut(), FALSE);
                if ok == FALSE {
                    return Err(Error::last_os_error());
                }
                Ok(Self { handle })
            }
        }

        pub fn wait(&self) -> Result<()> {
            const INFINITE: DWORD = 0xFFFFFFFF;
            let res = unsafe { WaitForSingleObject(self.handle, INFINITE) };
            if res != WAIT_OBJECT_0 {
                return Err(Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for TimerInner {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

#[cfg(target_os = "windows")]
use sys::TimerInner;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "windows")))]
mod sys {
    use super::*;

    pub struct TimerInner;

    impl TimerInner {
        pub fn new(_interval_ms: u64, _periodic: bool) -> Result<Self> { Err(Error::new(std::io::ErrorKind::Unsupported, "timer unsupported")) }
        pub fn wait(&self) -> Result<()> { Err(Error::new(std::io::ErrorKind::Unsupported, "timer unsupported")) }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "windows")))]
use sys::TimerInner; 