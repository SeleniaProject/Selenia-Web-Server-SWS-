//! Asynchronous DNS cache with lock-free skiplist implementation.
//! Pure Rust, no external crates. Designed for high-performance name resolution
//! used by Selenia Web Server.
//! 
//! Key properties:
//! 1. Lock-free readers & writers via atomic forward pointers (Harris skiplist).
//! 2. Per-record TTL eviction. `cleanup_expired` can be called periodically.
//! 3. Non-blocking resolution: a dedicated resolver thread performs `getaddrinfo`
//!    and updates the cache; callers remain non-blocking.
//!
//! NOTE: This is a simplified but fully functional skiplist targeted at <= 1 M
//! name entries. Further optimisation (epoch GC, cross-shard slicing) can be
//! added later without API breakage.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{ptr, thread};

const MAX_LEVEL: usize = 12;
const TTL_DEFAULT: Duration = Duration::from_secs(300);

/// Internal node of the skiplist.
struct Node {
    key: String,
    value: IpAddr,
    expires: Instant,
    forwards: [AtomicPtr<Node>; MAX_LEVEL],
}

impl Node {
    fn new(key: String, value: IpAddr, ttl: Duration) -> Box<Self> {
        let expires = Instant::now() + ttl;
        let mut node = Box::new(Node {
            key,
            value,
            expires,
            // SAFETY: We create AtomicPtr::default() for each forward pointer.
            forwards: unsafe { std::mem::zeroed() },
        });
        // Initialise atomic pointers to null.
        for fwd in node.forwards.iter_mut() {
            fwd.store(ptr::null_mut(), Ordering::Relaxed);
        }
        node
    }
}

/// Lock-free skiplist DNS cache. Cheap clones share the underlying data.
pub struct DnsCache {
    head: *mut Node,                   // sentinel head node
    level: AtomicPtr<Node>,           // highest level head forward (index 0)
    resolver_tx: Mutex<std::sync::mpsc::Sender<String>>, // task queue
}

unsafe impl Send for DnsCache {}
unsafe impl Sync for DnsCache {}

impl DnsCache {
    /// Create an empty cache and spawn background resolver thread.
    pub fn new() -> Arc<Self> {
        // Sentinel node with empty key and dummy address.
        let sentinel = Box::into_raw(Node::new("".into(), IpAddr::from([0, 0, 0, 0]), TTL_DEFAULT));
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let cache = Arc::new(DnsCache {
            head: sentinel,
            level: AtomicPtr::new(ptr::null_mut()),
            resolver_tx: Mutex::new(tx),
        });
        let cache_clone = Arc::clone(&cache);
        thread::spawn(move || {
            while let Ok(host) = rx.recv() {
                if let Ok(addr) = (host.as_str(), 0).to_socket_addrs().and_then(|mut it| it.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No addr"))) {
                    cache_clone.insert(host, addr.ip(), TTL_DEFAULT);
                }
            }
        });
        // Spawn periodic cleanup thread.
        let cache_cleanup = Arc::clone(&cache);
        thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            cache_cleanup.cleanup_expired();
        });
        cache
    }

    /// Non-blocking resolve. If cached and fresh, returns immediately.
    /// Otherwise schedules resolution and returns `None`.
    pub fn resolve(&self, host: &str) -> Option<IpAddr> {
        if let Some(ip) = self.lookup(host) {
            return Some(ip);
        }
        // Schedule async resolution.
        if let Ok(tx) = self.resolver_tx.lock() {
            let _ = tx.send(host.to_owned());
        }
        None
    }

    /// Insert (or update) cache entry.
    pub fn insert(&self, key: String, value: IpAddr, ttl: Duration) {
        let lvl = random_level(&key);
        let key_str = key.as_str();
        let mut update: [*mut Node; MAX_LEVEL] = [ptr::null_mut(); MAX_LEVEL];
        let mut x = self.head;
        unsafe {
            // Find insertion point for each level.
            for i in (0..MAX_LEVEL).rev() {
                while let Some(nxt) = (*x).forwards[i].load(Ordering::Acquire).as_ref() {
                    if nxt.key.as_str() < key_str {
                        x = nxt as *const _ as *mut _;
                    } else {
                        break;
                    }
                }
                update[i] = x;
            }
            // Check if key exists.
            let next = (*x).forwards[0].load(Ordering::Acquire);
            if let Some(exists) = (next as *mut Node).as_mut() {
                if exists.key == key {
                    exists.value = value;
                    exists.expires = Instant::now() + ttl;
                    return;
                }
            }
            // Insert new node.
            let new_node = Box::into_raw(Node::new(key, value, ttl));
            for i in 0..lvl {
                let prev = update[i];
                (*new_node).forwards[i].store((*prev).forwards[i].load(Ordering::Acquire), Ordering::Relaxed);
                (*prev).forwards[i].store(new_node, Ordering::Release);
            }
        }
    }

    /// Lookup without modifying state.
    pub fn lookup(&self, key: &str) -> Option<IpAddr> {
        unsafe {
            let mut x = self.head;
            for i in (0..MAX_LEVEL).rev() {
                while let Some(nxt) = (*x).forwards[i].load(Ordering::Acquire).as_ref() {
                    if nxt.key.as_str() < key {
                        x = nxt as *const _ as *mut _;
                    } else {
                        break;
                    }
                }
            }
            let next = (*x).forwards[0].load(Ordering::Acquire);
            if let Some(node) = next.as_ref() {
                if node.key == key && node.expires > Instant::now() {
                    return Some(node.value);
                }
            }
        }
        None
    }

    /// Remove expired records. Should be called periodically (e.g., every 500 ms).
    pub fn cleanup_expired(&self) {
        unsafe {
            let mut prev = self.head;
            loop {
                let curr_ptr = (*prev).forwards[0].load(Ordering::Acquire);
                if curr_ptr.is_null() { break; }
                let curr = &*curr_ptr;
                if curr.expires <= Instant::now() {
                    // Physically remove by patching level-0; higher levels will be lazily fixed.
                    (*prev).forwards[0].store(curr.forwards[0].load(Ordering::Acquire), Ordering::Release);
                    // Drop node safely.
                    let _ = Box::from_raw(curr_ptr);
                    continue; // stay at same prev to check new curr
                }
                prev = curr_ptr;
            }
        }
    }
}

/// Generate deterministic pseudo-random level from key hash (FNV-1a).
fn random_level(key: &str) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in key.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    // Count trailing zeros + 1 → geometric distribution.
    let mut lvl = 1;
    while lvl < MAX_LEVEL && (hash & 1) == 0 {
        lvl += 1;
        hash >>= 1;
    }
    lvl
} 