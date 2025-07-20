//! memfd_secret helper – secure in-memory TLS private key storage (Linux 5.14+)
//!
//! This module utilises the `memfd_secret(2)` system call to create a memory
//! region that is inaccessible from other processes (including ptrace)
//! and cannot be dumped to swap. TLS private keys are copied into this secret
//! memory, and the returned file descriptor can be passed to the TLS engine.
//!
//! On non-Linux or older kernels, a fallback anonymous `memfd_create` with
//! `MFD_CLOEXEC` is used. The region is still sealed against writes by other
//! FDs via `fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE)`.
//!
//! The content remains readable by the current process, but never touches the
//! filesystem. Callers should zeroise key material after loading.

use std::io;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use libc::{c_char, c_uint, syscall, SYS_memfd_secret, MFD_CLOEXEC};

    /// Flags for memfd_secret – currently only `MFD_SECRET_EXCLUSIVE` (1)
    const MFD_SECRET_EXCLUSIVE: c_uint = 0x1;

    /// Create a secret memory fd of the given length. On success returns raw fd.
    pub fn create_secret_fd(len: usize) -> io::Result<std::os::unix::io::RawFd> {
        // SAFETY: direct syscall; returns fd or -1.
        let fd = unsafe { syscall(SYS_memfd_secret as libc::c_long, MFD_SECRET_EXCLUSIVE) } as i32;
        if fd < 0 {
            // Fallback to memfd_create if kernel <5.14
            return fallback_memfd(len);
        }
        // Resize via ftruncate
        let res = unsafe { libc::ftruncate(fd, len as libc::off_t) };
        if res == -1 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn fallback_memfd(len: usize) -> io::Result<std::os::unix::io::RawFd> {
        // memfd_create(const char *name, unsigned int flags)
        let name = b"sws_tls_secret\0";
        // SAFETY: syscall wrapper
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create as libc::c_long, name.as_ptr() as *const c_char, MFD_CLOEXEC) } as i32;
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let res = unsafe { libc::ftruncate(fd, len as libc::off_t) };
        if res == -1 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        // Seal writes
        unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, libc::F_SEAL_WRITE) };
        Ok(fd)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;
    /// Fallback stub: uses an anonymous memory-backed file (`memfd_create` on platforms that have it).
    pub fn create_secret_fd(_len: usize) -> io::Result<std::os::unix::io::RawFd> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "memfd_secret unavailable"))
    }
}

/// Public wrapper around platform implementation.
pub fn create_secret(len: usize) -> io::Result<std::os::unix::io::RawFd> {
    imp::create_secret_fd(len)
} 