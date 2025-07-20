use selenia_core::config::ServerConfig;
use selenia_core::locale::translate;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Instant, Duration};
use std::fs::File;

use selenia_core::{log_info, log_warn, log_error};
use selenia_core::metrics;
use selenia_core::signals;
use selenia_core::crypto::tls;

#[cfg(unix)]
use selenia_core::os::{EventLoop, Interest};
mod parser;
use parser::Parser;
mod compress;
mod zerocopy;
mod http2;

#[cfg(unix)]
/// 同期イベントループベース (epoll/kqueue) HTTP/1.0 サーバ。
pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    // Bind all configured listen addresses.
    if cfg.listen.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No listen addresses")); }

    let mut listeners = Vec::new();
    for addr in &cfg.listen {
        let lst = TcpListener::bind(addr)?;
        lst.set_nonblocking(true)?;
        log_info!("SWS listening on http://{}", addr);
        listeners.push(lst);
    }

    let mut ev = EventLoop::new()?;
    signals::init_term_signals();
    use std::collections::HashMap;
    let mut listener_map: HashMap<usize, usize> = HashMap::new(); // token -> index in listeners
    for (idx, lst) in listeners.iter().enumerate() {
        let t = ev.register(lst, Interest::Readable)?;
        listener_map.insert(t, idx);
    }

    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Debug)]
    struct Conn {
        stream: TcpStream,
        buf: Vec<u8>,
        parser: Parser,
        last_active: Instant,
        peer: String,
    }

    let mut conns: HashMap<usize, Conn> = HashMap::new();

    loop {
        if signals::should_terminate() { break; }
        // 1000ms タイムアウトでポーリング
        let events = ev.poll(1000)?;
        for (token, readable, _writable) in events {
            if listener_map.contains_key(&token) && readable {
                // accept ループ
                loop {
                    match listeners[*listener_map.get(&token).unwrap()].accept() {
                        Ok((stream, addr)) => {
                            stream.set_nonblocking(true)?;
                            let t = ev.register(&stream, Interest::Readable)?;
                            conns.insert(
                                t,
                                Conn {
                                    stream,
                                    buf: Vec::new(),
                                    parser: Parser::new(),
                                    last_active: Instant::now(),
                                    peer: addr.to_string(),
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

                    // TLS detection: if first byte indicates handshake (0x16) and buf has at least 5 bytes, treat as TLS
                    if conn.buf.get(0) == Some(&0x16) && conn.buf.len()>=5 {
                        let rec_len = u16::from_be_bytes([conn.buf[3],conn.buf[4]]) as usize;
                        if conn.buf.len() >= 5+rec_len {
                            // For now, always respond with dummy ServerHello and close
                            let sh = tls::generate_server_hello();
                            let _ = conn.stream.write_all(&sh);
                            ev.deregister(token)?;
                            continue;
                        }
                    }

                    // HTTP/2 prior knowledge (PRI * HTTP/2.0...) detection
                    if http2::is_preface(&conn.buf) {
                        let _ = http2::send_preface_response(&mut conn.stream);
                        ev.deregister(token)?;
                        continue;
                    }

                    loop {
                        match conn.parser.advance(&conn.buf) {
                            Ok(Some((req, consumed))) => {
                                let close_after = should_close(&req);

                                let keep_alive = !close_after;
                                handle_request(
                                    &mut conn.stream,
                                    req.version,
                                    req.method,
                                    req.path,
                                    &req.headers,
                                    &cfg,
                                    &cfg.locale,
                                    keep_alive,
                                    &conn.peer,
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

    if cfg.listen.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No listen addresses")); }
    let listener = TcpListener::bind(&cfg.listen[0])?;
    log_info!("SWS listening on http://{}", cfg.listen[0]);

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
                        let _ = handle_request(&mut stream, "HTTP/1.0", "GET", "/", &[], &cfg_clone, &locale, false, "127.0.0.1");
                    }
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                });
            }
            Err(e) => log_error!("[ACCEPT] {e}"),
        }
    }
    Ok(())
}

fn handle_request(stream: &mut TcpStream, version: &str, method: &str, path: &str, headers: &[(&str,&str)], cfg: &ServerConfig, locale: &str, keep_alive: bool, peer: &str) -> std::io::Result<()> {
    if method != "GET" && method != "HEAD" {
        respond_simple(stream, version, 405, translate(locale, "http.method_not_allowed"), keep_alive)?;
        return Ok(());
    }
    // Metrics endpoint high priority
    if path == "/metrics" {
        metrics::inc_requests();
        let body = metrics::render();
        let mut headers = format!("{} 200 OK\r\nContent-Type: text/plain; version=0\r\nContent-Length: {}\r\n", version, body.len());
        if keep_alive {
            headers.push_str("Connection: keep-alive\r\n");
            headers.push_str("Keep-Alive: timeout=30, max=100\r\n");
        } else {
            headers.push_str("Connection: close\r\n");
        }
        headers.push_str("\r\n");
        stream.write_all(headers.as_bytes())?;
        stream.write_all(body.as_bytes())?;
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
            metrics::inc_requests();
            let body = if accept_gzip {
                compress::encode(&contents, compress::Encoding::Gzip)
            } else { contents };
            metrics::add_bytes(body.len() as u64);
            let mime = guess_mime(&fs_path);
            let mut headers = format!(
                "{} 200 OK\r\nContent-Type: {}\r\n",
                version,
                mime
            );
            if let Some(cache) = &cfg.cache {
                headers.push_str(&format!("Cache-Control: max-age={}, stale-while-revalidate={}\r\n", cache.max_age, cache.stale_while_revalidate));
            }
            if keep_alive {
                headers.push_str("Connection: keep-alive\r\n");
                headers.push_str("Keep-Alive: timeout=30, max=100\r\n");
            } else {
                headers.push_str("Connection: close\r\n");
            }
            headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
            if accept_gzip { headers.push_str("Content-Encoding: gzip\r\n"); }
            headers.push_str("\r\n");
            stream.write_all(headers.as_bytes())?;
            if method != "HEAD" {
                if accept_gzip {
                    stream.write_all(&body)?;
                } else {
                    // Zero-copy path
                    if let Ok(file) = File::open(&fs_path) {
                        let _ = zerocopy::transfer(stream, &file, body.len() as u64);
                    } else {
                        stream.write_all(&body)?; // fallback
                    }
                }
            }
            log_info!("{} - \"{} {}\" 200 {}", peer, method, path, body.len());
        }
        Err(_) => {
            metrics::inc_requests(); metrics::inc_errors();
            respond_simple(stream, version, 404, translate(locale, "http.not_found"), keep_alive)?;
            log_info!("{} - \"{} {}\" 404 0", peer, method, path);
        }
    }
    Ok(())
}

fn respond_simple(stream: &mut TcpStream, version: &str, status: u16, body: String, keep_alive: bool) -> std::io::Result<()> {
    let mut headers = format!(
        "{} {} \r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n",
        version,
        status,
        body.len()
    );
    if keep_alive {
        headers.push_str("Connection: keep-alive\r\n");
        headers.push_str("Keep-Alive: timeout=30, max=100\r\n");
    } else {
        headers.push_str("Connection: close\r\n");
    }
    headers.push_str("\r\n");
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