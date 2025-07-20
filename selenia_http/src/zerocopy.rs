//! Zero-copy file transfer helpers (sendfile / TransmitFile).
//! Currently only Linux sendfile is implemented; other platforms fall back to std::io::copy.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Transfer entire `file_len` bytes from `file` to `stream`.
/// Chooses the most efficient zero-copy path when available.
pub fn transfer(stream: &TcpStream, file: &File, file_len: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Error;
        use libc::{off_t, sendfile};

        let out_fd = stream.as_raw_fd();
        let in_fd = file.as_raw_fd();
        let mut offset: off_t = 0;

        while (offset as u64) < file_len {
            let remaining = file_len - offset as u64;
            let count = remaining.min(1 << 30) as usize; // up to 1 GiB per call to avoid EINVAL on some kernels
            let ret = unsafe { sendfile(out_fd, in_fd, &mut offset, count) };
            if ret < 0 {
                return Err(Error::last_os_error());
            }
            if ret == 0 { break; }
        }
        return Ok(());
    }
    #[cfg(not(target_os="linux"))]
    {
        // Portable fallback – copy via userspace buffer (64 KiB).
        let mut reader = file;
        let mut writer = stream; // Obtain mutable borrow for Write trait
        let mut buf = [0u8; 65536];
        let mut written: u64 = 0;
        while written < file_len {
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            writer.write_all(&buf[..n])?;
            written += n as u64;
        }
        return Ok(());
    }
} 