use selenia_core::config::ServerConfig;
use selenia_core::locale::translate;
use std::fs;
use std::io::{Read, Write};
use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Instant, Duration};
// removed unused File import

use selenia_core::{log_info, log_error};
use selenia_core::metrics;
use selenia_core::signals;
use selenia_core::waf;
use selenia_core::crypto::tls13;
use selenia_core::crypto::sha256::sha256_digest;
use selenia_core::traceparent::{TraceContext};

#[cfg(unix)]
use selenia_core::os::{EventLoop, Interest};
#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
mod accept;
#[cfg(unix)]
use accept::{create_reuseport_listener, spawn_accept_thread};
mod parser;
use parser::Parser;
mod compress;
mod zerocopy;
mod hpack;
mod http2;
mod http3;
mod qpack;
mod router;
mod rbac;
mod error;
use error::ErrorKind;
mod http3_packet;
pub use http3_packet::build_retry as build_retry_packet;

#[cfg(unix)]
/// 同期イベントループベース (epoll/kqueue) HTTP/1.0 サーバ。
pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    // Bind all configured listen addresses.
    if cfg.listen.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No listen addresses")); }

    use std::sync::mpsc::channel;
    let mut ev = EventLoop::new()?;
    signals::init_term_signals();

    // Channel from accept threads → event loop thread.
    let (tx, rx) = channel();

    // Spin up accept threads with SO_REUSEPORT enabled listeners.
    for addr in &cfg.listen {
        let lst = create_reuseport_listener(addr)?;
        lst.set_nonblocking(true)?; // extra safety
        log_info!("SWS listening on http://{} (reuseport)", addr);
        spawn_accept_thread(lst, tx.clone());
    }

    // After listeners are bound we no longer need CAP_NET_BIND_SERVICE, drop it and enable seccomp sandbox.
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = selenia_core::capability::drop_net_bind() {
            log_error!("Capability drop failed: {}", e);
        }
        // Install a dedicated seccomp filter tailored to the web server syscalls.
        const SYSCALLS: &[&str] = &[
            "read","write","close","futex","epoll_wait","epoll_ctl","epoll_create1",
            "clock_nanosleep","restart_syscall","exit","exit_group","accept","accept4",
            "socket","bind","listen","setsockopt","recvfrom","sendto","recvmsg","sendmsg",
            "getrandom","fcntl","mmap","munmap","brk","rt_sigreturn","rt_sigaction","sigaltstack"
        ];
        if let Err(e) = selenia_core::seccomp::generate_and_install(SYSCALLS) {
            log_error!("seccomp install failed: {}", e);
        }
    }

    drop(tx); // close senders in this thread

    let mut idle_timeout = Duration::from_secs(30);
    let mut req_count: u64 = 0;
    let mut last_adjust = Instant::now();

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
        if signals::should_terminate() { break Ok(()); }
        if signals::take_reload_request() {
            log_info!("Reload requested (SIGHUP) – rotating log");
            selenia_core::logger::rotate("sws.log");
        }
        // Register new inbound connections from accept threads.
        while let Ok(stream) = rx.try_recv() {
            let t = ev.register(&stream, Interest::Readable)?;
            conns.insert(
                t,
                Conn {
                    stream,
                    buf: Vec::new(),
                    parser: Parser::new(),
                    last_active: Instant::now(),
                    peer: "unknown".into(),
                },
            );
        }

        // Poll event loop with 1000ms timeout.
        let events = ev.poll(1000)?;
        for (token, readable, _writable) in events {
            if readable {
                if let Some(mut conn) = conns.remove(&token) {
                    let mut tmp = [0u8; 1024];
                    match conn.stream.read(&mut tmp) {
                        Ok(0) => {
                            // closed
                            ev.deregister(token)?;
                            continue;
                        }
                        Ok(n) => conn.buf.extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            log_error!("[READ ERROR] {}", e);
                            ev.deregister(token)?;
                            continue;
                        }
                    }

                    conn.last_active = Instant::now();

                    if !selenia_core::ratelimit::allow(&conn.peer) {
                        // 429 Too Many Requests
                        let _ = conn.stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        ev.deregister(token)?; continue;
                    }

                    // TLS detection: if first byte indicates handshake (0x16) and buf has at least 5 bytes, treat as TLS
                    if conn.buf.get(0) == Some(&0x16) && conn.buf.len()>=5 {
                        let rec_len = u16::from_be_bytes([conn.buf[3],conn.buf[4]]) as usize;
                        if conn.buf.len() >= 5+rec_len {
                            let handshake = &conn.buf[5..5+rec_len];
                            if let Ok((resp, _state)) = tls13::process_client_hello(handshake) {
                                let _ = conn.stream.write_all(&resp);
                            }
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
                                req_count += 1;
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
                            Err(e) => {
                                let kind = e.to_error_kind();
                                let _ = respond_error(&mut conn.stream, "HTTP/1.1", kind);
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
            if now.duration_since(c.last_active) > idle_timeout {
                to_remove.push(tok);
            }
        }
        for tok in to_remove {
            if let Some(mut c) = conns.remove(&tok) {
                let _ = ev.deregister(tok);
                let _ = c.stream.shutdown(std::net::Shutdown::Both);
            }
        }

        // Auto-tune idle timeout every 1000 requests or 30 s, whichever comes first
        if req_count >= 1000 || last_adjust.elapsed() > Duration::from_secs(30) {
            // Simple heuristic: if active connections exceed 75% of concurrency, shorten timeout, else lengthen up to 60s.
            let active = conns.len();
            let capacity = cfg.listen.len() * 1024; // arbitrary capacity per listener
            let load = active as f32 / capacity as f32;
            if load > 0.75 {
                idle_timeout = idle_timeout.saturating_sub(Duration::from_secs(5)).max(Duration::from_secs(5));
            } else if load < 0.25 {
                idle_timeout = (idle_timeout + Duration::from_secs(5)).min(Duration::from_secs(60));
            }
            req_count = 0;
            last_adjust = Instant::now();
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
    let start_sys = std::time::SystemTime::now();
    // original start Instant for latency below
    let start = std::time::Instant::now();

    // --- Trace Context ---
    let tp_ctx = headers.iter()
        .find(|(k,_)| k.eq_ignore_ascii_case("traceparent"))
        .and_then(|(_,v)| TraceContext::parse(*v))
        .unwrap_or_else(|| TraceContext::generate());
    let tp_header_line = format!("traceparent: {}\r\n", tp_ctx.header());

    if !waf::evaluate(method, path, &headers.iter().map(|(a,b)|(a.to_string(),b.to_string())).collect::<Vec<_>>()) {
        respond_simple(stream, version, 403, "Forbidden".into(), keep_alive, cfg, &tp_header_line)?;
        let latency = start.elapsed();
        selenia_core::metrics::observe_latency(latency);
        let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let span_name = format!("{} {}", method, path);
        selenia_core::otel::export_span(&span_name, start_ns, end_ns);
        return Ok(());
    }

    if method != "GET" && method != "HEAD" {
        respond_simple(stream, version, 405, translate(locale, "http.method_not_allowed"), keep_alive, cfg, &tp_header_line)?;
        let latency = start.elapsed();
        selenia_core::metrics::observe_latency(latency);
        let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let span_name = format!("{} {}", method, path);
        selenia_core::otel::export_span(&span_name, start_ns, end_ns);
        return Ok(());
    }
    // RBAC check
    let auth = headers.iter().find(|(k,_)| k.eq_ignore_ascii_case("Authorization")).map(|(_,v)| *v);
    if !rbac::validate(path, auth) {
        respond_simple(stream, version, 403, "Forbidden".into(), keep_alive, cfg, &tp_header_line)?;
        let latency = start.elapsed();
        selenia_core::metrics::observe_latency(latency);
        let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let span_name = format!("{} {}", method, path);
        selenia_core::otel::export_span(&span_name, start_ns, end_ns);
        return Ok(());
    }

    // Metrics endpoint high priority
    if path == "/metrics" {
        metrics::inc_requests();
        let body = metrics::render();
        let mut headers = format!("{} 200 OK\r\nContent-Type: text/plain; version=0\r\nContent-Length: {}\r\n", version, body.len());
        headers.push_str(&tp_header_line);
        if keep_alive {
            headers.push_str("Connection: keep-alive\r\n");
            headers.push_str("Keep-Alive: timeout=30, max=100\r\n");
        } else {
            headers.push_str("Connection: close\r\n");
        }
        headers.push_str("\r\n");
        stream.write_all(headers.as_bytes())?;
        stream.write_all(body.as_bytes())?;
        let latency = start.elapsed();
        selenia_core::metrics::observe_latency(latency);
        let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        let span_name = format!("{} {}", method, path);
        selenia_core::otel::export_span(&span_name, start_ns, end_ns);
        return Ok(());
    }

    // Virtual host selection
    let mut effective_root = cfg.root_dir.clone();
    let mut effective_cache = cfg.cache.clone();
    for (k,v) in headers {
        if k.eq_ignore_ascii_case("Host") {
            let host=v.split(':').next().unwrap_or(v);
            if let Some(vh)=cfg.vhosts.iter().find(|vh| vh.domain==host) {
                effective_root=vh.root.clone();
                if vh.cache.is_some() { effective_cache=vh.cache.clone(); }
            }
            break;
        }
    }

    let fs_path = sanitize_path(&effective_root, path);
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

    let meta = match fs::metadata(&fs_path) {
        Ok(m) if m.is_file() => m,
        _ => {
            metrics::inc_requests(); metrics::inc_errors();
            respond_simple(stream, version, 404, translate(locale, "http.not_found"), keep_alive, cfg, &tp_header_line)?;
            log_info!("{} - \"{} {}\" 404 0", peer, method, path);
            let latency = start.elapsed();
            selenia_core::metrics::observe_latency(latency);
            let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
            let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
            let span_name = format!("{} {}", method, path);
            selenia_core::otel::export_span(&span_name, start_ns, end_ns);
            return Ok(());
        }
    };
    let total_len = meta.len();
    // Compute weak ETag based on size and mtime
    let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let msecs = mtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let etag_raw = format!("{}:{}", total_len, msecs);
    let etag_bytes = sha256_digest(etag_raw.as_bytes());
    let etag_str = format!("\"{:x}{:x}{:x}{:x}\"", etag_bytes[0], etag_bytes[1], etag_bytes[2], etag_bytes[3]);
    // Conditional If-None-Match
    for (k,v) in headers {
        if k.eq_ignore_ascii_case("If-None-Match") && *v == etag_str {
            respond_simple(stream, version, 304, String::new(), keep_alive, cfg, &tp_header_line)?;
            let latency = start.elapsed();
            selenia_core::metrics::observe_latency(latency);
            let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
            let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
            let span_name = format!("{} {}", method, path);
            selenia_core::otel::export_span(&span_name, start_ns, end_ns);
            return Ok(());
        }
    }

    // Parse Range header (bytes) – single range only
            let mut range: Option<(u64,u64)> = None;
            for (k,v) in headers {
                if k.eq_ignore_ascii_case("Range") {
                    if let Some(r) = v.strip_prefix("bytes=") {
                        let parts: Vec<&str> = r.split('-').collect();
                        if parts.len()==2 {
                            let start_opt = if !parts[0].is_empty() { parts[0].parse::<u64>().ok() } else { None };
                            let end_opt = if !parts[1].is_empty() { parts[1].parse::<u64>().ok() } else { None };
                            if let Some(s)=start_opt {
                                let e = end_opt.unwrap_or(total_len-1);
                                if s<=e && e<total_len {
                                    range = Some((s,e));
                                }
                            } else if let Some(e)=end_opt { // suffix range
                                if e!=0 {
                                    range = Some((total_len-e, total_len-1));
                                }
                            }
                        }
                    }
                }
            }

            let full_body = fs::read(&fs_path)?;
            let (body, status, content_range_hdr) = if let Some((s,e)) = range {
                let slice = &full_body[s as usize ..= e as usize];
                (slice.to_vec(), 206, Some(format!("bytes {}-{}/{}", s, e, total_len)))
            } else { (full_body, 200, None) };

            metrics::inc_requests();
            metrics::add_bytes(body.len() as u64);

            let mime = guess_mime(&fs_path);
            let mut headers_txt = format!(
                "{} {} OK\r\nContent-Type: {}\r\n",
                version,
                status,
                mime
            );
            if let Some(cr)=content_range_hdr { headers_txt.push_str(&format!("Content-Range: {}\r\n", cr)); }
            if cfg.tls_cert.is_some() {
                headers_txt.push_str("Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
            }
            if let Some(cache)=&effective_cache {
                headers_txt.push_str(&format!("Cache-Control: max-age={}, stale-while-revalidate={}\r\n", cache.max_age, cache.stale_while_revalidate));
            }
            if keep_alive {
                headers_txt.push_str("Connection: keep-alive\r\n");
                headers_txt.push_str("Keep-Alive: timeout=30, max=100\r\n");
            } else {
                headers_txt.push_str("Connection: close\r\n");
            }
            headers_txt.push_str(&format!("ETag: {}\r\n", etag_str));
            headers_txt.push_str(&format!("Content-Length: {}\r\n", body.len()));
            if accept_gzip { headers_txt.push_str("Content-Encoding: gzip\r\n"); }
            headers_txt.push_str(&tp_header_line);
            headers_txt.push_str("\r\n");
            stream.write_all(headers_txt.as_bytes())?;
            if method != "HEAD" {
                stream.write_all(&body)?;
            }
            log_info!("{} - \"{} {}\" {} {}", peer, method, path, status, body.len());
        // Response finished
        
    let latency = start.elapsed();
    selenia_core::metrics::observe_latency(latency);
    // Export OTel span
    let end_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let start_ns = start_sys.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let span_name = format!("{} {}", method, path);
    selenia_core::otel::export_span(&span_name, start_ns, end_ns);
    Ok(())
}

fn respond_simple(stream: &mut TcpStream, version: &str, status: u16, body: String, keep_alive: bool, cfg:&ServerConfig, tp_header:&str) -> std::io::Result<()> {
    let mut headers = format!(
        "{} {} \r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n",
        version,
        status,
        body.len()
    );
    if cfg.tls_cert.is_some() {
        headers.push_str("Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
    }
    if keep_alive {
        headers.push_str("Connection: keep-alive\r\n");
        headers.push_str("Keep-Alive: timeout=30, max=100\r\n");
    } else {
        headers.push_str("Connection: close\r\n");
    }
    headers.push_str(tp_header);
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn respond_error(stream: &mut TcpStream, version: &str, kind: ErrorKind) -> std::io::Result<()> {
    let status = kind.status_code();
    use std::io::Write;
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let resp = format!(
        "{version} {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(resp.as_bytes())
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
    // Remove query string and fragment
    let mut p = uri_path.split(['?', '#']).next().unwrap_or("");
    p = p.trim_start_matches('/');
    if p.is_empty() { p = "index.html"; }

    // Reject paths containing .. or leading with /
    if p.contains("..") { return PathBuf::from("/invalid"); }

    let full = Path::new(root_dir).join(p);
    // Ensure resulting path stays within root_dir canonical path
    if let (Ok(full_canon), Ok(root_canon)) = (full.canonicalize(), Path::new(root_dir).canonicalize()) {
        if !full_canon.starts_with(&root_canon) {
            return PathBuf::from("/invalid");
        }
    }
    if full.is_dir() { full.join("index.html") } else { full }
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