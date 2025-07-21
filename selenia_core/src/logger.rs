use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::{OpenOptions, File};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Severity level for a log entry.
#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info  => "INFO",
            LogLevel::Warn  => "WARN",
            LogLevel::Error => "ERROR",
        };
        write!(f, "{}", s)
    }
}

/// Global stderr logger lock to avoid interleaved output from multiple threads.
static LOGGER_LOCK: Mutex<()> = Mutex::new(());

static mut FILE: Option<Mutex<File>> = None;
static LOG_LEVEL: AtomicUsize = AtomicUsize::new(LogLevel::Info as usize);

pub fn init_file(path:&str) {
    let f = OpenOptions::new().create(true).append(true).open(path).unwrap();
    unsafe { FILE = Some(Mutex::new(f)); }
}

pub fn set_level(level: LogLevel) { LOG_LEVEL.store(level as usize, Ordering::Relaxed); }

pub fn rotate(path:&str) {
    use std::fs;
    // close current and rename
    unsafe {
        if let Some(m) = &FILE {
            // Acquire the lock to flush and unlock the current log file before rotation.
            let _ = m.lock().unwrap();
        }
    } // FILE mutex guard dropped here before rename
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let rotated = format!("{}.{}", path, ts);
    let _ = fs::rename(path, &rotated);
    init_file(path);
}

pub fn log(level: LogLevel, args: fmt::Arguments<'_>) {
    if (level as usize) < LOG_LEVEL.load(Ordering::Relaxed) { return; }
    let _guard = LOGGER_LOCK.lock().unwrap();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let millis = ts.as_secs()*1000 + ts.subsec_millis() as u64;
    let tid = std::thread::current().id();
    let line = format!("[{millis}] [{level}] {:?}: {}\n", tid, args);
    let _ = io::stderr().write_all(line.as_bytes());
    unsafe { if let Some(f) = &FILE { let _ = f.lock().unwrap().write_all(line.as_bytes()); } }
}

// ------------- Convenience macros -------------

/// Emit an INFO level log entry.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Info, format_args!($($arg)*));
    };
}

/// Emit a WARN level log entry.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Warn, format_args!($($arg)*));
    };
}

/// Emit an ERROR level log entry.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Error, format_args!($($arg)*));
    };
} 