#![cfg(target_os = "windows")]
//! IOCP-based Poller implementation for Windows.
//!
//! This module provides a minimal, self-contained wrapper around Win32
//! I/O Completion Ports that matches the `Poller` trait used throughout
//! the project.  All FFI bindings are declared locally to avoid relying
//! on external crates.
//!
//! The implementation intentionally focuses on the subset of operations
//! required by SWS: associating a socket/file handle with the completion
//! port and waiting for completion packets.  It does **not** issue the
//! asynchronous read/write operations themselves; higher layers are
//! expected to manage that.

use core::ptr::null_mut;
use std::io::{Error, Result};
use std::os::windows::io::RawSocket;

use super::interest::{Event, Interest, Token};
use super::poller::Poller;

// -----------------------------------------------------------------------------
// Win32 FFI (manually declared to keep the crate dependency-free)
// -----------------------------------------------------------------------------

type BOOL = i32;
type DWORD = u32;
type HANDLE = *mut core::ffi::c_void;

const FALSE: BOOL = 0;
const INVALID_HANDLE_VALUE: HANDLE = (-1isize) as HANDLE;

#[repr(C)]
struct OVERLAPPED {
    internal: usize,
    internal_high: usize,
    offset: DWORD,
    offset_high: DWORD,
    h_event: HANDLE,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateIoCompletionPort(
        FileHandle: HANDLE,
        ExistingCompletionPort: HANDLE,
        CompletionKey: usize,
        NumberOfConcurrentThreads: DWORD,
    ) -> HANDLE;

    fn GetQueuedCompletionStatus(
        CompletionPort: HANDLE,
        lpNumberOfBytesTransferred: *mut DWORD,
        lpCompletionKey: *mut usize,
        lpOverlapped: *mut *mut OVERLAPPED,
        dwMilliseconds: DWORD,
    ) -> BOOL;

    fn PostQueuedCompletionStatus(
        CompletionPort: HANDLE,
        dwNumberOfBytesTransferred: DWORD,
        dwCompletionKey: usize,
        lpOverlapped: *mut OVERLAPPED,
    ) -> BOOL;

    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

// -----------------------------------------------------------------------------
// IOCP wrapper
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct Iocp {
    port: HANDLE,
}

impl Iocp {
    /// Creates a new completion port with the system default number of worker
    /// threads (`NumberOfConcurrentThreads = 0`).
    pub fn new() -> Result<Self> {
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
        if port.is_null() {
            return Err(Error::last_os_error());
        }
        Ok(Self { port })
    }

    /// Associates `handle` with the completion port, using `key` for
    /// identification when packets are dequeued.
    fn add_handle(&self, handle: HANDLE, key: usize) -> Result<()> {
        let result = unsafe { CreateIoCompletionPort(handle, self.port, key, 0) };
        if result.is_null() {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Iocp {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.port) };
    }
}

// -----------------------------------------------------------------------------
// Poller trait
// -----------------------------------------------------------------------------

impl Poller for Iocp {
    type Error = Error;

    fn add(&self, fd: usize, token: Token, _interest: Interest) -> Result<(), Self::Error> {
        // On Windows a socket handle can be safely cast to `HANDLE` as both are
        // pointer-sized opaque values.
        self.add_handle(fd as HANDLE, token)
    }

    fn modify(&self, _fd: usize, _token: Token, _interest: Interest) -> Result<(), Self::Error> {
        // Interest changes are a no-op for IOCP because readiness is based on
        // outstanding asynchronous operations rather than subscription masks.
        Ok(())
    }

    fn delete(&self, _fd: usize) -> Result<(), Self::Error> {
        // A handle is automatically disassociated when it is closed, so there
        // is nothing for us to do here.
        Ok(())
    }

    fn wait(&self, events: &mut [Event], timeout_ms: isize) -> Result<usize, Self::Error> {
        let mut ready = 0usize;

        // Convert negative timeout to "infinite" as expected by the Win32 API.
        let mut first_timeout = if timeout_ms < 0 {
            u32::MAX
        } else {
            timeout_ms as u32
        };

        while ready < events.len() {
            let mut bytes: DWORD = 0;
            let mut key: usize = 0;
            let mut overlapped: *mut OVERLAPPED = null_mut();

            let ok = unsafe {
                GetQueuedCompletionStatus(
                    self.port,
                    &mut bytes as *mut _,
                    &mut key as *mut _,
                    &mut overlapped as *mut _,
                    first_timeout,
                )
            };

            // After the first iteration we switch to a non-blocking poll to
            // collect any additional completions that may already be queued.
            first_timeout = 0;

            if ok == FALSE {
                // If `lpOverlapped` is null we encountered a timeout; simply
                // break and return the number of packets collected so far.
                if overlapped.is_null() {
                    break;
                }
                return Err(Error::last_os_error());
            }

            events[ready].token = key as Token;
            // We mark both readability and writability because the specific
            // operation type (read/write/connect) is not distinguished here.
            events[ready].readable = true;
            events[ready].writable = true;
            ready += 1;

            // Reclaim the OVERLAPPED allocation if the caller used a Box.
            if !overlapped.is_null() {
                unsafe { drop(Box::from_raw(overlapped)); }
            }
        }
        Ok(ready)
    }
}
