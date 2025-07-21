//! Accept thread implementation with SO_REUSEPORT.
//! Only compiled on Unix platforms; Windows uses IOCP with a single listener.

#![cfg(unix)]

use std::io::{Error, Result};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::mpsc::Sender;
use std::thread;

/// Create a TcpListener with SO_REUSEPORT enabled and bound to `addr`.
pub fn create_reuseport_listener(addr: &str) -> Result<TcpListener> {
    use std::mem::size_of_val;
    use std::ffi::CString;

    // Resolve address using libc's getaddrinfo for IPv4/IPv6 flexibility.
    let c_addr = CString::new(addr).unwrap();
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_PASSIVE;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let gai_ret = unsafe { libc::getaddrinfo(c_addr.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if gai_ret != 0 {
        return Err(Error::new(std::io::ErrorKind::InvalidInput, "invalid address"));
    }
    let mut last_err = None;
    let mut ptr = res;
    while !ptr.is_null() {
        let ai = unsafe { &*ptr };
        unsafe {
            let fd = libc::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if fd < 0 {
                last_err = Some(Error::last_os_error());
                ptr = ai.ai_next;
                continue;
            }
            // Enable SO_REUSEADDR and SO_REUSEPORT.
            let on: libc::c_int = 1;
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &on as *const _ as _, size_of_val(&on) as _);
            #[cfg(target_os = "linux")]
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &on as *const _ as _, size_of_val(&on) as _);

            if libc::bind(fd, ai.ai_addr, ai.ai_addrlen) == 0 && libc::listen(fd, 1024) == 0 {
                // Success.
                let lst = TcpListener::from_raw_fd(fd);
                unsafe { libc::freeaddrinfo(res) };
                return Ok(lst);
            }
            last_err = Some(Error::last_os_error());
            libc::close(fd);
        }
        ptr = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    Err(last_err.unwrap_or_else(|| Error::new(std::io::ErrorKind::Other, "create listener failed")))
}

/// Spawn an accept thread for `listener`. Accepted streams are sent to `chan`.
pub fn spawn_accept_thread(listener: TcpListener, chan: Sender<TcpStream>) {
    thread::Builder::new()
        .name("accept-thread".into())
        .spawn(move || loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let _ = stream.set_nonblocking(true);
                    let _ = chan.send(stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(e) => {
                    eprintln!("[ACCEPT ERROR] {}", e);
                    thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        })
        .expect("spawn accept thread");
} 