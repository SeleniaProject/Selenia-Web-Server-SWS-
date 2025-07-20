use selenia_core::config::ServerConfig;
use selenia_core::locale::translate;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Instant, Duration};

use selenia_core::{log_info, log_warn, log_error};

#[cfg(unix)]
use selenia_core::os::{EventLoop, Interest};
mod parser;
use parser::Parser;
mod compress;

#[cfg(unix)]
/// 同期イベントループベース (epoll/kqueue) HTTP/1.0 サーバ。
pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("{}:{}", cfg.host, cfg.port))?;
    listener.set_nonblocking(true)?;
    log_info!("SWS listening on http://{}:{}", cfg.host, cfg.port);

    let mut ev = EventLoop::new()?;
    let listener_token = ev.register(&listener, Interest::Readable)?;

    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Debug)]
    struct Conn {
        stream: TcpStream,
        buf: Vec<u8>,
        parser: Parser,
        last_active: Instant,
    }

    let mut conns: HashMap<usize, Conn> = HashMap::new();

    loop {
        // 1000ms タイムアウトでポーリング
        let events = ev.poll(1000)?;
        for (token, readable, _writable) in events {
            if token == listener_token && readable {
                // accept ループ
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(true)?;
                            let t = ev.register(&stream, Interest::Readable)?;
                            conns.insert(
                                t,
                                Conn {
                                    stream,
                                    buf: Vec::new(),
                                    parser: Parser::new(),
                                    last_active: Instant::now(),
                                },
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            log_error!("[ACCEPT ERROR] {}", e);
                            break;
                        }
                    }
                }
            } else if readable {
                if let Some(mut conn) = conns.remove(&token) {
                    let mut tmp = [0u8; 1024];
                    match conn.stream.read(&mut tmp) {
                        Ok(0) => {
                            // closed
                            ev.deregister(token)?;
                            continue;
                        }
                        Ok(n) => conn.buf.extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            log_error!("[READ ERROR] {}", e);
                            ev.deregister(token)?;
                            continue;
                        }
                    }

                    conn.last_active = Instant::now();

                    loop {
                        match conn.parser.advance(&conn.buf) {
                            Ok(Some((req, consumed))) => {
                                let close_after = should_close(&req);

                                handle_request(
                                    &mut conn.stream,
                                    req.method,
                                    req.path,
                                    &req.headers,
                                    &cfg,
                                    &cfg.locale,
                                )?;
                                // remove consumed bytes (Parser consumed data)
                                conn.buf.drain(0..consumed);

                                if close_after {
                                    ev.deregister(token)?;
                                    break;
                                } else if conn.buf.is_empty() {
                                    // Keep connection open for next requests
                                    break;
                                }
                            }
                            Ok(None) => break, // need more data
                            Err(_) => {
                                ev.deregister(token)?;
                                break;
                            }
                        }
                    }
                    conns.insert(token, conn);
                }
            }
        }
        // Idle timeout check
        let now = Instant::now();
        let mut to_remove = Vec::new();
        for (&tok, c) in &conns {
            if now.duration_since(c.last_active) > IDLE_TIMEOUT {
                to_remove.push(tok);
            }
        }
        for tok in to_remove {
            if let Some(mut c) = conns.remove(&tok) {
                let _ = ev.deregister(tok);
                let _ = c.stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

// ---------- Windows & other fallback (thread-per-connection) ----------

#[cfg(not(unix))]
pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    use std::net::{TcpListener, TcpStream};
    use std::io::{Read, Write};
    use std::thread;

    let listener = TcpListener::bind(format!("{}:{}", cfg.host, cfg.port))?;
    log_info!("SWS listening on http://{}:{}", cfg.host, cfg.port);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let cfg_clone = cfg.clone();
                let locale = cfg_clone.locale.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    if let Ok(n)=stream.read(&mut buf) {
                        let mut parser = Parser::new();
                        parser.advance(&buf[..n]).ok();
                        // Very naive: always serve index.html
                        let _ = handle_request(&mut stream, "GET", "/", &[], &cfg_clone, &locale);
                    }
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                });
            }
            Err(e) => log_error!("[ACCEPT] {e}"),
        }
    }
    Ok(())
}

fn handle_request(stream: &mut TcpStream, method: &str, path: &str, headers: &[(&str,&str)], cfg: &ServerConfig, locale: &str) -> std::io::Result<()> {
    if method != "GET" && method != "HEAD" {
        respond_simple(stream, 405, translate(locale, "http.method_not_allowed"))?;
        return Ok(());
    }
    let fs_path = sanitize_path(&cfg.root_dir, path);
    let accept_gzip = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Accept-Encoding"))
        .flat_map(|(_, v)| v.split(','))
        .filter_map(|e| {
            let mut parts = e.trim().split(';');
            let enc = parts.next()?.trim();
            let q = parts
                .find_map(|p| {
                    let mut kv = p.trim().split('=');
                    if kv.next()? == "q" { kv.next() } else { None }
                })
                .and_then(|s| s.parse::<f32>().ok())
                .unwrap_or(1.0);
            Some((enc, q))
        })
        .filter(|(enc, q)| *enc == "gzip" && *q > 0.0)
        .next()
        .is_some();

    match fs::read(&fs_path) {
        Ok(contents) => {
            let body = if accept_gzip {
                compress::encode(&contents, compress::Encoding::Gzip)
            } else { contents };
            let mime = guess_mime(&fs_path);
            let mut headers = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: {}\r\nConnection: close\r\n",
                mime
            );
            headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
            if accept_gzip { headers.push_str("Content-Encoding: gzip\r\n"); }
            headers.push_str("\r\n");
            stream.write_all(headers.as_bytes())?;
            if method != "HEAD" {
                stream.write_all(&body)?;
            }
        }
        Err(_) => {
            respond_simple(stream, 404, translate(locale, "http.not_found"))?;
        }
    }
    Ok(())
}

fn respond_simple(stream: &mut TcpStream, status: u16, body: String) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.0 {} \r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        status,
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn guess_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

fn sanitize_path(root_dir: &str, uri_path: &str) -> PathBuf {
    let mut safe_path = uri_path.trim_start_matches('/');
    if safe_path.is_empty() {
        safe_path = "index.html";
    }
    let joined = Path::new(root_dir).join(safe_path);
    if joined.is_dir() {
        joined.join("index.html")
    } else {
        joined
    }
}

fn should_close(req: &parser::Request) -> bool {
    // HTTP/1.0: デフォルト close。
    // HTTP/1.1: Connection: close のみ close。
    if req.version == "HTTP/1.0" {
        return !req.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("Connection") && v.eq_ignore_ascii_case("keep-alive"));
    }
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("Connection") && v.eq_ignore_ascii_case("close") {
            return true;
        }
    }
    false
} 