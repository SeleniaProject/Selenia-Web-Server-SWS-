use std::fs;
use std::io;
use std::path::Path;
use std::io::ErrorKind;
use std::env;

/// Runtime configuration loaded from YAML or simple key=value file. Fields are minimal and will
/// grow as project evolves.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// List of listen addresses in "host:port" form (e.g., "0.0.0.0:80").
    pub listen: Vec<String>,
    pub root_dir: String,
    pub locale: String,
    /// Optional TLS certificate and private key paths.
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
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

        let mut listen: Vec<String> = Vec::new();
        let mut root_dir: Option<String> = None;
        let mut locale: Option<String> = None;
        let mut tls_cert: Option<String> = None;
        let mut tls_key: Option<String> = None;

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
                        listen.push(addr.to_string());
                    }
                    let _ = lines.next();
                }
                if listen.is_empty() {
                    return Err(ConfigError::InvalidFormat("listen list empty".into()));
                }
            } else if trimmed.starts_with("root_dir:") || trimmed.starts_with("root:") {
                if let Some(v) = trimmed.splitn(2, ':').nth(1) {
                    let val = v.trim().trim_matches(|c| c=='"' || c=='\'');
                    root_dir = Some(expand_env(val));
                }
            } else if trimmed.starts_with("locale:") {
                if let Some(v) = trimmed.splitn(2, ':').nth(1) {
                    let val = v.trim().trim_matches(|c| c=='"' || c=='\'');
                    locale = Some(expand_env(val));
                }
            } else if trimmed.starts_with("tls:") {
                // Parse nested tls block
                let tls_indent = indent;
                while let Some(peek) = lines.peek() {
                    let p_indent = peek.chars().take_while(|c| c.is_whitespace()).count();
                    let p_trim = peek.trim();
                    if p_indent<=tls_indent { break; }
                    if let Some(v) = p_trim.strip_prefix("cert:") {
                        let val = v.trim().trim_matches(|c| c=='"' || c=='\'');
                        tls_cert = Some(expand_env(val));
                    }
                    if let Some(v) = p_trim.strip_prefix("key:") {
                        let val = v.trim().trim_matches(|c| c=='"' || c=='\'');
                        tls_key = Some(expand_env(val));
                    }
                    let _ = lines.next();
                }
            }
        }

        let listen = listen.into_iter().map(|v| expand_env(&v)).collect();
        Ok(ServerConfig {
            listen,
            root_dir: root_dir.ok_or(ConfigError::MissingField("root_dir"))?,
            locale: locale.ok_or(ConfigError::MissingField("locale"))?,
            tls_cert,
            tls_key,
        })
    }

    /// Legacy key=value loader (host,port,root_dir,locale). Returns single-address listen vector.
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
                "root_dir" => root_dir = Some(expand_env(val)),
                "locale" => locale = Some(expand_env(val)),
                _ => return Err(ConfigError::InvalidFormat(line.to_string())),
            }
        }

        let h = host.ok_or(ConfigError::MissingField("host"))?;
        let p = port.ok_or(ConfigError::MissingField("port"))?;
        Ok(ServerConfig {
            listen: vec![expand_env(&format!("{}:{}", h,p))],
            root_dir: root_dir.ok_or(ConfigError::MissingField("root_dir"))?,
            locale: locale.ok_or(ConfigError::MissingField("locale"))?,
            tls_cert: None,
            tls_key: None,
        })
    }
}

/// Replace occurrences of `${VAR}` in `input` with the value of environment variable `VAR`.
/// Unknown variables are left unchanged. No external crate is used.
fn expand_env(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Find closing brace
            if let Some(rel_end) = bytes[i+2..].iter().position(|&b| b == b'}') {
                let end = i + 2 + rel_end;
                let var_name = &input[i + 2..end];
                if let Ok(val) = env::var(var_name) {
                    out.push_str(&val);
                } else {
                    out.push_str(&format!("${{{}}}", var_name));
                }
                i = end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
} 