use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Write a log line with the given level and formatted message.
pub fn log(level: LogLevel, args: fmt::Arguments<'_>) {
    // Acquire mutex to serialize writes.
    let _guard = LOGGER_LOCK.lock().unwrap();
    // Compute unix millis timestamp.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = ts.as_secs() * 1000 + (ts.subsec_millis() as u64);

    // Thread id (platform independent as u64 via Debug formatting).
    let tid = std::thread::current().id();

    let _ = writeln!(io::stderr(), "[{}] [{}] {:?}: {}", millis, level, tid, args);
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