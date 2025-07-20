//! OS entropy abstraction.
//! Provides `fill_random` and `random_u64` helpers without external crates.

use std::io;

#[cfg(unix)]
mod imp {
    use super::*;
    use libc::{c_void, size_t};

    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        // Prefer getrandom(2) if available (since Linux 3.17, glibc 2.25).
        #[cfg(any(target_os="linux", target_os="android"))]
        {
            extern "C" {
                fn getrandom(buf: *mut c_void, buflen: size_t, flags: libc::c_uint) -> libc::ssize_t;
            }
            const GRND_NONBLOCK: libc::c_uint = 0x0001;
            let mut filled = 0;
            while filled < buf.len() {
                let ret = unsafe {
                    getrandom(buf[filled..].as_mut_ptr() as *mut c_void,
                               (buf.len()-filled) as size_t,
                               GRND_NONBLOCK)
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // Fallback to /dev/urandom on ENOSYS
                    if err.raw_os_error() == Some(libc::ENOSYS) { break; }
                    return Err(err);
                }
                filled += ret as usize;
            }
            if filled == buf.len() { return Ok(()); }
        }
        // Fallback: read from /dev/urandom
        let mut f = std::fs::File::open("/dev/urandom")?;
        use std::io::Read;
        f.read_exact(buf)?;
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use winapi::um::ntsecapi::RtlGenRandom;

    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        let ret = unsafe { RtlGenRandom(buf.as_mut_ptr() as *mut _, buf.len() as u32) };
        if ret==0 { Err(io::Error::new(io::ErrorKind::Other,"RtlGenRandom failed")) } else { Ok(()) }
    }
}

/// Fill slice with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    imp::fill(buf)
}

/// Return a random u64.
pub fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = fill_random(&mut b);
    u64::from_le_bytes(b)
} 