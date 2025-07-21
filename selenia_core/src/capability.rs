// Minimal capability helpers for Linux.
// On non-Linux platforms functions are no-ops so the caller can remain portable.

#[cfg(target_os = "linux")]
mod imp {
    use libc::c_long;

    /// Drop CAP_NET_BIND_SERVICE from capability bounding set so the process can no longer bind low (<1024) ports.
    /// Call this *after* all required sockets are already bound.
    pub fn drop_net_bind() -> Result<(), String> {
        // Constants taken from linux/prctl.h – kept here to avoid expanding libc dependency.
        const PR_CAPBSET_DROP: c_long = 24;
        const CAP_NET_BIND_SERVICE: c_long = 10;

        // According to prctl(2): PR_CAPBSET_DROP takes 2nd arg = capability to drop.
        let res = unsafe { libc::prctl(PR_CAPBSET_DROP as i32, CAP_NET_BIND_SERVICE as i32, 0, 0, 0) };
        if res == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn drop_net_bind() -> Result<(), String> { Ok(()) }
}

/// Public re-export.
pub use imp::drop_net_bind; 