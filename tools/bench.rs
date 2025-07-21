use std::time::{Instant, Duration};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::thread;

fn main() {
    let concurrency = 50;
    let requests = 1000;
    let url = "127.0.0.1:8080";

    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let url = url.to_string();
        handles.push(thread::spawn(move || {
            for _ in 0..requests {
                if let Ok(mut s) = TcpStream::connect(&url) {
                    let _ = s.write_all(b"GET / HTTP/1.0\r\n\r\n");
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                }
            }
        }));
    }
    for h in handles { let _ = h.join(); }
    let dur = Instant::now()-start;
    let total = concurrency*requests;
    println!("{total} requests in {:.2?} => {:.2} req/s", dur, total as f64 / dur.as_secs_f64());
    std::io::stdout().flush().unwrap();
} 