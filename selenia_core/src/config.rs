use std::fs;
use std::io;
use std::path::Path;
use std::io::ErrorKind;

/// Server runtime configuration (simple key=value format).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub root_dir: String,
    pub locale: String,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    InvalidFormat(String),
    MissingField(&'static str),
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e)
    }
}

/// Naive YAML parser for the limited subset needed by ServerConfig.
/// It only understands the following structure:
///
/// server:
///   listen:
///     - "0.0.0.0:8080"
///   root_dir: "./www"
///   locale: "ja"
///
impl ServerConfig {
    /// Load configuration from a minimal YAML file. Falls back to Io(NotFound) when file is absent.
    pub fn load_from_yaml<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind()==ErrorKind::NotFound => return Err(ConfigError::Io(e)),
            Err(e) => return Err(ConfigError::Io(e)),
        };

        let mut host: Option<String> = None;
        let mut port: Option<u16> = None;
        let mut root_dir: Option<String> = None;
        let mut locale: Option<String> = None;

        let mut in_server = false;
        let mut server_indent: Option<usize> = None;

        let mut lines = content.lines().peekable();
        while let Some(line_raw) = lines.next() {
            let trimmed = line_raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }

            let indent = line_raw.chars().take_while(|c| c.is_whitespace()).count();

            if !in_server {
                if trimmed.starts_with("server:") {
                    in_server = true;
                    server_indent = Some(indent);
                }
                continue;
            }

            // Leave server block when indentation returns to or above the "server:" line indent
            if let Some(si) = server_indent { if indent<=si { in_server=false; continue; } }

            // Inside server block ------------
            if trimmed.starts_with("listen:") {
                // Expect following indented lines beginning with '-'
                let listen_indent = indent;
                while let Some(peek) = lines.peek() {
                    let p_indent = peek.chars().take_while(|c| c.is_whitespace()).count();
                    let p_trim = peek.trim();
                    if p_indent<=listen_indent { break; }
                    if let Some(addr) = p_trim.strip_prefix('-') {
                        let addr = addr.trim().trim_matches(|c| c=='"' || c=='\'');
                        if let Some((h, p_str)) = addr.rsplit_once(':') {
                            if let Ok(p) = p_str.parse::<u16>() { host=Some(h.to_string()); port=Some(p); }
                        }
                        // first address is enough
                        break;
                    }
                    let _ = lines.next();
                }
            } else if trimmed.starts_with("root_dir:") || trimmed.starts_with("root:") {
                if let Some(v) = trimmed.splitn(2, ':').nth(1) {
                    let val = v.trim().trim_matches(|c| c=='"' || c=='\'');
                    root_dir = Some(val.to_string());
                }
            } else if trimmed.starts_with("locale:") {
                if let Some(v) = trimmed.splitn(2, ':').nth(1) {
                    let val = v.trim().trim_matches(|c| c=='"' || c=='\'');
                    locale = Some(val.to_string());
                }
            }
        }

        Ok(ServerConfig {
            host: host.ok_or(ConfigError::MissingField("host"))?,
            port: port.ok_or(ConfigError::MissingField("port"))?,
            root_dir: root_dir.ok_or(ConfigError::MissingField("root_dir"))?,
            locale: locale.ok_or(ConfigError::MissingField("locale"))?,
        })
    }

    /// Load configuration from a simple key=value file.
    /// Example:
    /// host=0.0.0.0
    /// port=8080
    /// root_dir=www
    /// locale=ja
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let mut host = None;
        let mut port = None;
        let mut root_dir = None;
        let mut locale = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap().trim();
            let val = match parts.next() {
                Some(v) => v.trim(),
                None => return Err(ConfigError::InvalidFormat(line.to_string())),
            };

            match key {
                "host" => host = Some(val.to_string()),
                "port" => port = Some(val.parse::<u16>().map_err(|_| ConfigError::InvalidFormat(line.to_string()))?),
                "root_dir" => root_dir = Some(val.to_string()),
                "locale" => locale = Some(val.to_string()),
                _ => return Err(ConfigError::InvalidFormat(line.to_string())),
            }
        }

        Ok(ServerConfig {
            host: host.ok_or(ConfigError::MissingField("host"))?,
            port: port.ok_or(ConfigError::MissingField("port"))?,
            root_dir: root_dir.ok_or(ConfigError::MissingField("root_dir"))?,
            locale: locale.ok_or(ConfigError::MissingField("locale"))?,
        })
    }
} 