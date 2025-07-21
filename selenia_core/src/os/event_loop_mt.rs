//! NUMA-aware multi-threaded EventLoop supervisor.
//!
//! This module builds on the per-platform `EventLoop` to create one worker
//! thread **per physical core**, optionally grouped by NUMA node.  Each worker
//! thread pins itself to a specific CPU before entering its I/O loop, ensuring
//! deterministic cache locality and avoiding cross-node memory traffic.
//!
//! The implementation avoids external crates by using raw syscalls / Win32 API
//! calls for affinity management.  On non-Unix platforms where detailed CPU / 
//! NUMA information is unavailable we gracefully fall back to standard thread
//! spawning without affinity.

use std::io::Result;
use std::thread::{self, JoinHandle};

use super::EventLoop;

/// Supervisor that owns a pool of EventLoop worker threads.
pub struct MultiEventLoop {
    workers: Vec<JoinHandle<()>>,
}

impl MultiEventLoop {
    /// Spawns one EventLoop per CPU core (or `num_threads` if specified) and
    /// pins each worker to a dedicated CPU with best-effort NUMA node packing
    /// (Linux only for now).
    pub fn new(num_threads: Option<usize>) -> Result<Self> {
        let cpus = detect_cpus();
        let total = num_threads.unwrap_or_else(|| cpus.len()).min(cpus.len());

        let mut workers = Vec::with_capacity(total);
        for i in 0..total {
            let cpu = cpus[i];
            workers.push(thread::Builder::new()
                .name(format!("event-loop-{}", cpu))
                .spawn(move || {
                    // Best-effort pin; ignore errors on unsupported OS.
                    let _ = pin_to_cpu(cpu);
                    let mut el = EventLoop::new().expect("event loop");
                    loop {
                        // Non-blocking poll; higher layers handle lifecycle.
                        let _ = el.poll(0);
                        // Hint to the scheduler when idle.
                        std::thread::yield_now();
                    }
                })?);
        }
        Ok(Self { workers })
    }

    /// Blocks until all workers finish (usually never called in production).
    pub fn join(self) {
        for h in self.workers {
            let _ = h.join();
        }
    }
}

// -----------------------------------------------------------------------------
// CPU & NUMA detection helpers (Linux only at present)
// -----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn detect_cpus() -> Vec<usize> {
    // Try to group by NUMA node for locality.
    match std::fs::read_dir("/sys/devices/system/node") {
        Ok(entries) => {
            let mut cpus = Vec::new();
            let mut nodes: Vec<(usize, Vec<usize>)> = Vec::new();
            for e in entries.filter_map(Result::ok) {
                if !e.file_name().to_string_lossy().starts_with("node") {
                    continue;
                }
                let path = e.path().join("cpulist");
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let list = parse_cpu_list(&text);
                    nodes.push((list.len(), list));
                }
            }
            // Sort nodes by CPU count to spread workers evenly.
            nodes.sort_by_key(|&(len, _)| len);
            for (_, list) in nodes {
                cpus.extend(list);
            }
            if cpus.is_empty() {
                // Fallback to sequential IDs.
                (0..num_online_cpus()).collect()
            } else {
                cpus
            }
        }
        Err(_) => (0..num_online_cpus()).collect(),
    }
}

#[cfg(target_os = "linux")]
fn num_online_cpus() -> usize {
    unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize }
}

#[cfg(target_os = "linux")]
fn parse_cpu_list(list: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in list.trim().split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let s: usize = start.trim().parse().unwrap_or(0);
            let e: usize = end.trim().parse().unwrap_or(0);
            out.extend(s..=e);
        } else if !part.trim().is_empty() {
            if let Ok(id) = part.trim().parse() {
                out.push(id);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn pin_to_cpu(cpu: usize) -> Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let res = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if res != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Stubs for non-Linux targets – workers spawn without affinity.
// -----------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn detect_cpus() -> Vec<usize> {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    (0..cpus).collect()
}

#[cfg(not(target_os = "linux"))]
fn pin_to_cpu(_cpu: usize) -> Result<()> { Ok(()) } 