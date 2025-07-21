//! OCSP Stapling helper.
//! Loads a DER-encoded OCSP response at startup and provides it to the TLS
//! layer for inclusion in CertificateStatus messages.
//! In real-world usage the response should be periodically refreshed; for now
//! we only support static OCSP files.

use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::thread;
use std::time::SystemTime;

static OCSP_CACHE: RwLock<Option<OcspStaple>> = RwLock::new(None);

pub struct OcspStaple {
    pub der: Vec<u8>,
    pub expires_at: Instant,
}

impl OcspStaple {
    pub fn is_valid(&self) -> bool { Instant::now() < self.expires_at }
}

/// Load OCSP file (DER) and cache it for stapling.
/// Caller provides `valid_secs` lifetime; production code should parse ASN.1.
pub fn load_ocsp_response(path: &str, valid_secs: u64) -> std::io::Result<()> {
    let data = std::fs::read(path)?;
    let staple = OcspStaple { der: data, expires_at: Instant::now() + Duration::from_secs(valid_secs) };
    *OCSP_CACHE.write().unwrap() = Some(staple);
    Ok(())
}

/// Get current OCSP response, if valid.
pub fn get_staple() -> Option<Vec<u8>> {
    OCSP_CACHE.read().unwrap().as_ref().and_then(|s| if s.is_valid(){Some(s.der.clone())}else{None})
}

/// Periodically reload the OCSP response from `path` every `refresh_secs`.
/// Spawns a background thread; in failure it logs and retains previous staple.
pub fn spawn_auto_refresh(path: String, refresh_secs: u64, valid_secs: u64) {
    thread::spawn(move || {
        loop {
            if let Err(e) = load_ocsp_response(&path, valid_secs) {
                eprintln!("[OCSP] reload failed: {}", e);
            }
            thread::sleep(Duration::from_secs(refresh_secs));
        }
    });
} 