use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
}

impl LogLevel {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" => Self::None,
            "error" => Self::Error,
            "warning" | "warn" => Self::Warning,
            "info" => Self::Info,
            "debug" => Self::Debug,
            _ => Self::Warning,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Error => "ERROR",
            Self::Warning => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Warning as u8);
static ERROR_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

fn error_file_slot() -> &'static Mutex<Option<File>> {
    ERROR_FILE.get_or_init(|| Mutex::new(None))
}

pub fn set_level(level: LogLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Configures an optional `log.error` file (e.g. `/var/log/xray/error.log`) opened with `O_APPEND`.
/// Log lines continue to be written to stderr as well so systemd journal remains populated.
pub fn set_error_file(path: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        if let Ok(mut guard) = error_file_slot().lock() {
            *guard = None;
        }
        return Ok(());
    }
    let p = Path::new(trimmed);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .map_err(|e| format!("failed to open error log '{trimmed}': {e}"))?;
    if let Ok(mut guard) = error_file_slot().lock() {
        *guard = Some(f);
    }
    Ok(())
}

#[inline]
pub fn is_enabled(level: LogLevel) -> bool {
    let cur = LEVEL.load(Ordering::Relaxed);
    cur > 0 && (level as u8) <= cur
}

pub fn log_msg(level: LogLevel, args: std::fmt::Arguments<'_>) {
    if !is_enabled(level) {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{ts}] {}: {args}\n", level.as_str());
    eprint!("{line}");
    if let Ok(mut guard) = error_file_slot().lock() {
        if let Some(f) = guard.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logger::log_msg($crate::logger::LogLevel::Error, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logger::log_msg($crate::logger::LogLevel::Warning, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logger::log_msg($crate::logger::LogLevel::Info, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::logger::is_enabled($crate::logger::LogLevel::Debug) {
            $crate::logger::log_msg($crate::logger::LogLevel::Debug, format_args!($($arg)*))
        }
    };
}
