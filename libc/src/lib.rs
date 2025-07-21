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

// ------------- syscall, memfd_secret, signals (Linux) -------------
#[cfg(target_os = "linux")]
pub type c_long = i64;

#[cfg(target_os = "linux")]
pub const SYS_memfd_secret: c_long = 447;
#[cfg(target_os = "linux")]
pub const MFD_CLOEXEC: c_uint = 0x0001;

#[cfg(target_os = "linux")]
extern "C" {
    pub fn syscall(num: c_long, ...) -> c_long;
}

// signals
#[cfg(target_os = "linux")]
pub type sighandler_t = extern "C" fn(c_int);

#[cfg(target_os = "linux")]
pub const SIGINT: c_int = 2;
#[cfg(target_os = "linux")]
pub const SIGTERM: c_int = 15;
#[cfg(target_os = "linux")]
pub const SIGHUP: c_int = 1;
#[cfg(target_os = "linux")]
pub const SA_RESTART: c_uint = 0x10000000; 

// Common integer typedefs
pub type ssize_t = isize;
pub type off_t = i64;

// errno constants (subset)
pub const ENOSYS: c_int = 38;

// ftruncate / fcntl --------------------------------------
#[cfg(target_os = "linux")]
extern "C" {
    pub fn ftruncate(fd: c_int, length: off_t) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

pub const F_ADD_SEALS: c_int = 1033;
pub const F_SEAL_WRITE: c_int = 0x0008;

// Additional memfd constant
pub const SYS_memfd_create: c_long = 319;

// syscall numbers (x86_64) used in seccomp ----------------
pub const SYS_read: c_long = 0;
pub const SYS_write: c_long = 1;
pub const SYS_close: c_long = 3;
pub const SYS_futex: c_long = 202;
pub const SYS_epoll_wait: c_long = 232;
pub const SYS_epoll_ctl: c_long = 233;
pub const SYS_epoll_create1: c_long = 291;
pub const SYS_clock_nanosleep: c_long = 230;
pub const SYS_restart_syscall: c_long = 219;
pub const SYS_exit: c_long = 60;
pub const SYS_exit_group: c_long = 231;

// prctl ---------------------------------------------------
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
pub const PR_SET_SECCOMP: c_int = 22;
pub const SECCOMP_MODE_FILTER: c_int = 2;

#[cfg(target_os = "linux")]
extern "C" {
    pub fn prctl(option: c_int, ...) -> c_int;
    pub fn __errno_location() -> *mut c_int;
}

// sigaction prototype (re-defined with sa_sigaction field) ---------
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct sigaction {
    pub sa_sigaction: sighandler_t,
    pub sa_flags: c_uint,
    pub sa_restorer: *mut c_void,
    pub sa_mask: u64,
}

#[cfg(target_os = "linux")]
extern "C" {
    pub fn sigaction(signum: c_int, act: *const sigaction, oldact: *mut sigaction) -> c_int;
} 

#[cfg(target_os = "linux")]
extern "C" {
    pub fn sendfile(out_fd: c_int, in_fd: c_int, offset: *mut off_t, count: size_t) -> ssize_t;
} 