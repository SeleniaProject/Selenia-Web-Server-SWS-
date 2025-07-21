//! Minimal libc shim providing only the symbols referenced by Selenia.
//! This avoids pulling the real `libc` crate (external dependency) while
//! still linking against the platform C runtime.
#![allow(non_camel_case_types, non_snake_case, dead_code)]

pub type c_void = core::ffi::c_void;
pub type size_t = usize;
pub type c_char = i8;
pub type c_uint = u32;
pub type c_int = i32;

// ---------- Linux epoll ----------
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct epoll_event {
    pub events: u32,
    pub u64: u64,
}

#[cfg(target_os = "linux")]
extern "C" {
    pub fn epoll_create1(flags: c_int) -> c_int;
    pub fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut epoll_event) -> c_int;
    pub fn epoll_wait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int) -> c_int;
    pub fn close(fd: c_int) -> c_int;
}

// epoll constants
#[cfg(target_os = "linux")]
pub const EPOLL_CLOEXEC: c_int = 0x80000;
#[cfg(target_os = "linux")]
pub const EPOLL_CTL_ADD: c_int = 1;
#[cfg(target_os = "linux")]
pub const EPOLL_CTL_MOD: c_int = 3;
#[cfg(target_os = "linux")]
pub const EPOLL_CTL_DEL: c_int = 2;
#[cfg(target_os = "linux")]
pub const EPOLLIN: c_int = 0x001;
#[cfg(target_os = "linux")]
pub const EPOLLOUT: c_int = 0x004;

// ---------- BSD kqueue ----------
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
extern "C" {
    pub fn kqueue() -> c_int;
    pub fn kevent(kq: c_int, changelist: *const kevent, nchanges: c_int, eventlist: *mut kevent, nevents: c_int, timeout: *const timespec) -> c_int;
    pub fn close(fd: c_int) -> c_int;
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
#[repr(C)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
#[repr(C)]
pub struct kevent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: usize,
}

// Constants (subset)
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub const EVFILT_READ: i16 = -1;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub const EVFILT_WRITE: i16 = -2;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub const EV_ADD: u16 = 0x0001;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub const EV_DELETE: u16 = 0x0002; 

// ---------- dlopen (Unix) ----------
#[cfg(unix)]
extern "C" {
    pub fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    pub fn dlclose(handle: *mut c_void) -> c_int;
}
#[cfg(unix)]
pub const RTLD_NOW: c_int = 2; 