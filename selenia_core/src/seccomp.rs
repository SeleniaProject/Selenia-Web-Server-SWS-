//! Minimal seccomp‐BPF sandbox (allowlist) for Selenia Web Server.
//! Linux only – on other platforms `install()` is a no-op.
//! The filter permits just the syscalls required by the core runtime:
//!  • read / write / close / futex / epoll / clock_nanosleep / restart_syscall
//!  • exit / exit_group
//! Any other syscall results in `EPERM`.
//! No external crates – uses raw libc bindings.

#[cfg(target_os = "linux")]
mod linux {
    use libc::*;

    const ALLOW: i32 = 0x7fff0000; // SECCOMP_RET_ALLOW
    const ERRNO: i32 = 0x00050000; // SECCOMP_RET_ERRNO | EPERM

    // BPF Macros
    const BPF_LD: u16 = 0x00; const BPF_W: u16 = 0x00; const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05; const BPF_JEQ: u16 = 0x10; const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    #[repr(C)]
    struct sock_filter { code: u16, jt: u8, jf: u8, k: u32 }
    #[repr(C)]
    struct sock_fprog { len: u16, filter: *const sock_filter }

    const fn stmt(code:u16,k:u32)->sock_filter{sock_filter{code,jt:0,jf:0,k}}
    const fn jmp(code:u16,k:u32,jt:u8,jf:u8)->sock_filter{sock_filter{code,jt,jf,k}}

    pub unsafe fn install() -> Result<(),i32> {
        // Syscall numbers we allow (x86_64).
        const SYSCALLS: &[u32] = &[
            SYS_read as u32, SYS_write as u32, SYS_close as u32,
            SYS_futex as u32, SYS_epoll_wait as u32, SYS_epoll_ctl as u32,
            SYS_epoll_create1 as u32, SYS_clock_nanosleep as u32,
            SYS_restart_syscall as u32, SYS_exit as u32, SYS_exit_group as u32,
        ];
        // BPF program layout: load syscall -> compare -> allow else errno
        const LOAD: sock_filter = stmt(BPF_LD|BPF_W|BPF_ABS, 0); // seccomp data offset 0 = nr
        const RET_ERR: sock_filter = stmt(BPF_RET|BPF_K, ERRNO as u32);
        const RET_ALLOW: sock_filter = stmt(BPF_RET|BPF_K, ALLOW as u32);
        // build vector
        const MAX: usize = 32;
        let mut prog: [sock_filter; MAX] = [RET_ALLOW; MAX];
        let mut idx=0;
        prog[idx]=LOAD; idx+=1;
        for &nr in SYSCALLS {
            prog[idx]=jmp(BPF_JMP|BPF_JEQ|BPF_K,nr,0,1); idx+=1;
            prog[idx]=RET_ALLOW; idx+=1;
        }
        prog[idx]=RET_ERR; idx+=1;
        let prog = sock_fprog{ len: idx as u16, filter: prog.as_ptr() };
        // Set no_new_privs
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)!=0 { return Err(*__errno_location()); }
        // Load filter
        if prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const _ as usize) !=0 {
            return Err(*__errno_location());
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    pub unsafe fn install() -> Result<(),i32> { Ok(()) }
}

/// Public wrapper – safe because we examine return code.
pub fn install() -> Result<(), String> {
    unsafe { linux::install().map_err(|e| format!("seccomp install failed: errno {}", e)) }
}

/// Dynamically generate a minimal seccomp filter for the given syscalls and install it.
/// The generator resolves libc syscall numbers at build time using the libc crate constants.
#[cfg(target_os = "linux")]
pub fn generate_and_install(names: &[&str]) -> Result<(), String> {
    use libc::*;
    let mut numbers = Vec::<u32>::new();
    for &n in names {
        let num = match n {
            "read" => SYS_read,
            "write" => SYS_write,
            "close" => SYS_close,
            "futex" => SYS_futex,
            "epoll_wait" => SYS_epoll_wait,
            "epoll_ctl" => SYS_epoll_ctl,
            "epoll_create1" => SYS_epoll_create1,
            "clock_nanosleep" => SYS_clock_nanosleep,
            "restart_syscall" => SYS_restart_syscall,
            "exit" => SYS_exit,
            "exit_group" => SYS_exit_group,
            _ => return Err(format!("unknown syscall '{}'", n)),
        } as u32;
        numbers.push(num);
    }
    unsafe { self::linux::install_dynamic(&numbers) }
}

#[cfg(target_os = "linux")]
mod linux_dynamic_installer {
    use super::*;
    use libc::*;

    pub unsafe fn install_dynamic(syscalls: &[u32]) -> Result<(), String> {
        const ALLOW: i32 = 0x7fff0000;
        const ERRNO: i32 = 0x00050000;
        const BPF_LD: u16 = 0x00; const BPF_W: u16 = 0x00; const BPF_ABS: u16 = 0x20;
        const BPF_JMP: u16 = 0x05; const BPF_JEQ: u16 = 0x10; const BPF_K: u16 = 0x00;
        const BPF_RET: u16 = 0x06;
        #[repr(C)] struct sock_filter{code:u16,jt:u8,jf:u8,k:u32}
        #[repr(C)] struct sock_fprog{len:u16,filter:*const sock_filter}
        const fn stmt(code:u16,k:u32)->sock_filter{sock_filter{code,jt:0,jf:0,k}}
        const fn jmp(code:u16,k:u32,jt:u8,jf:u8)->sock_filter{sock_filter{code,jt,jf,k}}
        const LOAD: sock_filter = stmt(BPF_LD|BPF_W|BPF_ABS, 0);
        const RET_ERR: sock_filter = stmt(BPF_RET|BPF_K, ERRNO as u32);
        const RET_ALLOW: sock_filter = stmt(BPF_RET|BPF_K, ALLOW as u32);

        let mut prog_vec = Vec::<sock_filter>::with_capacity(2*syscalls.len()+2);
        prog_vec.push(LOAD);
        for &nr in syscalls {
            prog_vec.push(jmp(BPF_JMP|BPF_JEQ|BPF_K, nr, 0, 1));
            prog_vec.push(RET_ALLOW);
        }
        prog_vec.push(RET_ERR);
        let prog = sock_fprog{len: prog_vec.len() as u16, filter: prog_vec.as_ptr()};
        if prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 { return Err("prctl NO_NEW_PRIVS failed".into()); }
        if prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const _ as usize)!=0 {
            return Err("prctl SECCOMP failed".into());
        }
        Ok(())
    }
} 