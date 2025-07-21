//! Zero-copy file transfer helpers (sendfile / TransmitFile).
//! Linux uses `sendfile`, Windows uses `TransmitFile`; other platforms fall back to buffered `std::io::copy`. // comment in English per guidelines

use std::fs::File;
use std::io::{self};
use std::net::TcpStream;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "windows")]
use std::os::windows::io::{AsRawHandle, AsRawSocket};

#[cfg(target_os = "windows")]
#[link(name = "Ws2_32")]
extern "system" {
    fn TransmitFile(
        h_socket: usize, // SOCKET
        h_file: usize,   // HANDLE
        n_number_of_bytes_to_write: u32,
        n_number_of_bytes_per_send: u32,
        lp_overlapped: *mut core::ffi::c_void,
        lp_transmit_buffers: *mut core::ffi::c_void,
        dw_flags: u32,
    ) -> i32;
}

/// Transfer entire `file_len` bytes from `file` to `stream`.
/// Chooses the most efficient zero-copy path when available.
pub fn transfer(stream: &TcpStream, file: &File, file_len: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use libc::{off_t, sendfile};

        let out_fd = stream.as_raw_fd();
        let in_fd = file.as_raw_fd();
        let mut offset: off_t = 0;

        while (offset as u64) < file_len {
            let remaining = file_len - offset as u64;
            let count = remaining.min(1 << 30) as usize; // up to 1 GiB per call to avoid EINVAL on some kernels
            let ret = unsafe { sendfile(out_fd, in_fd, &mut offset, count) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if ret == 0 { break; }
        }
        return Ok(());
    }
    #[cfg(target_os="windows")]
    {
        // Try TransmitFile for zero-copy on Windows (falls back to buffered copy on failure).
        const TF_USE_DEFAULT_WORKER: u32 = 0x00000000;
        let sock = stream.as_raw_socket() as usize;
        let handle = file.as_raw_handle() as usize;
        // TransmitFile parameters: write entire file in one go. Windows limits to 2^32-1 bytes; ensure safe cast.
        let to_write = if file_len > u32::MAX as u64 { u32::MAX } else { file_len as u32 };
        let ok = unsafe {
            TransmitFile(
                sock,
                handle,
                to_write,
                0,                // nNumberOfBytesPerSend=0 -> use default chunk size
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                TF_USE_DEFAULT_WORKER,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        // If TransmitFile failed, fall back to user-space copy.
        // No early return here; execution will continue to portable fallback below.
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