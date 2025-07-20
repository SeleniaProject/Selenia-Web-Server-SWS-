//! Master/Worker process launcher with Hot-Reload support.
//!
//! Design reference: DESIGN.md §16 "Hot-Reload 状態遷移".
//!
//! Master responsibilities:
//! 1. Load configuration and spawn N worker processes.
//! 2. Listen for SIGHUP to perform zero-downtime reload (fork + exec).
//! 3. Forward SIGTERM/SIGINT to workers and exit on graceful shutdown.
//!
//! Worker responsibilities:
//! * Run `selenia_http::run_server(cfg)`.

use selenia_core::config::ServerConfig;
use selenia_core::locale::register_locale;
use selenia_core::{log_error, log_info, signals};
use selenia_http::run_server;
use std::collections::HashMap;
use std::env;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
mod unix_master {
    use super::*;
    use libc::{kill, pid_t, SIGTERM};

    /// Spawn `count` worker processes by re-execing self with env SWS_ROLE=worker.
    pub fn spawn_workers(count: usize, cfg_path: &str) -> Vec<pid_t> {
        let mut pids = Vec::new();
        for _ in 0..count {
            match unsafe { libc::fork() } {
                -1 => log_error!("fork failed: {}", std::io::Error::last_os_error()),
                0 => {
                    // Child – set role and exec.
                    std::env::set_var("SWS_ROLE", "worker");
                    let exe = env::current_exe().expect("current exe");
                    let _ = Command::new(exe).arg(cfg_path).exec();
                    std::process::exit(1);
                }
                pid => pids.push(pid),
            }
        }
        pids
    }

    /// Send signal to list of pids.
    pub fn signal_all(pids: &[pid_t], sig: i32) {
        for &pid in pids {
            unsafe { kill(pid, sig) };
        }
    }

    /// Blocking wait for any child; returns pid.
    pub fn wait_child() -> Option<pid_t> {
        let mut status: i32 = 0;
        let pid = unsafe { libc::wait(&mut status) };
        if pid > 0 { Some(pid) } else { None }
    }
}

fn main() {
    // CLI subcommand quick dispatch
    let mut args_iter = env::args().skip(1);
    if let Some(cmd) = args_iter.next() {
        match cmd.as_str() {
            "start" => {/* fallthrough to normal flow*/},
            "stop" => { // send SIGTERM to master pid
                #[cfg(unix)] {
                    if let Ok(pid_str)=std::fs::read_to_string("sws.pid") { if let Ok(pid)=pid_str.trim().parse::<i32>() {
                        unsafe{ libc::kill(pid, libc::SIGTERM); }
                        println!("Sent SIGTERM to {}", pid);
                        return;
                    }}
                }
                println!("stop not supported on this platform or pidfile missing"); return;
            },
            "reload" => { #[cfg(unix)] {
                    if let Ok(pid_str)=std::fs::read_to_string("sws.pid") { if let Ok(pid)=pid_str.trim().parse::<i32>() {
                        unsafe{ libc::kill(pid, libc::SIGHUP); }
                        println!("Sent SIGHUP to {}", pid);
                        return;
                    }}
            }
            println!("reload not supported"); return; },
            "benchmark" => { let _=Command::new(env::current_exe().unwrap()).arg("bench").status(); return; },
            "plugin" => { println!("plugin subcommand placeholder"); return; },
            "locale" => { println!("locale compile placeholder"); return; },
            _ => { /* treat as cfg path or default*/ }
        }
    }

    // Detect role.
    let is_worker = env::var("SWS_ROLE").map_or(false, |v| v == "worker");
    let args: Vec<String> = env::args().collect();
    let cfg_path = if args.len() > 1 { &args[1] } else { "config.yaml" };

    // Load configuration once (master reloads on exec).
    let cfg = match ServerConfig::load_from_yaml(cfg_path)
        .or_else(|_| ServerConfig::load_from_file("config.txt")) {
        Ok(c) => c,
        Err(e) => {
            log_error!("Config load failure: {:?}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = cfg.validate() {
        log_error!("Config validation error: {:?}", e);
        std::process::exit(1);
    }

    if is_worker {
        // ---------- Worker Path ----------
        init_locales();
        if let Err(e) = run_server(cfg) {
            log_error!("Server terminated: {}", e);
        }
        return;
    }

    // ---------- Master Path ----------
    #[cfg(unix)]
    {
        signals::init_term_signals();

        let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

        log_info!("Master PID {} starting {} workers", std::process::id(), worker_count);
        let mut workers = unix_master::spawn_workers(worker_count, cfg_path);

        loop {
            if signals::should_terminate() {
                unix_master::signal_all(&workers, SIGTERM);
                break;
            }
            if signals::take_reload_request() {
                log_info!("Hot-reload requested – spawning new workers");
                let new_workers = unix_master::spawn_workers(worker_count, cfg_path);
                unix_master::signal_all(&workers, SIGTERM); // graceful stop old
                workers = new_workers;
            }

            // Reap dead workers.
            while let Some(dead) = unix_master::wait_child() {
                workers.retain(|&pid| pid != dead);
            }

            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        log_info!("Master exiting");
    }

    #[cfg(not(unix))]
    {
        log_error!("Hot-reload master/worker is Unix-only in this build");
    }
}

/// Register English/Japanese placeholder locales.
fn init_locales() {
    let mut en = HashMap::new();
    en.insert("http.not_found".to_string(), "404 Not Found".to_string());
    en.insert(
        "http.method_not_allowed".to_string(),
        "405 Method Not Allowed".to_string(),
    );
    register_locale("en", en);

    let mut ja = HashMap::new();
    ja.insert("http.not_found".to_string(), "404 見つかりません".to_string());
    ja.insert(
        "http.method_not_allowed".to_string(),
        "405 許可されていないメソッドです".to_string(),
    );
    register_locale("ja", ja);
} 