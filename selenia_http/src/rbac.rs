//! JWT RBAC middleware – minimal implementation.
//! RS256 signature verification is **not** performed (placeholder) – the goal
//! is to parse the JWT, extract the `roles` claim, and match it against a
//! YAML-like policy that maps URL path prefixes to required roles.

use core::str;
use std::collections::HashMap;

static mut POLICIES: Option<Vec<Policy>> = None;

#[derive(Clone)]
struct Policy { prefix: String, roles: Vec<String> }

/// Load YAML-like policy list at startup.
/// Example lines:  
/// /admin/  : admin  
/// /billing : [admin,finance]
pub fn load(policy_str:&str) {
    let mut v=Vec::new();
    for line in policy_str.lines() {
        let line=line.trim(); if line.is_empty()||line.starts_with('#'){continue;}
        if let Some(idx)=line.find(':') {
            let (path,roles)=line.split_at(idx);
            let roles=roles.trim_start_matches(':').trim();
            let roles:Vec<String>=roles.trim_matches(['[',']'].as_ref())
                .split(',').map(|s|s.trim().to_string()).collect();
            v.push(Policy{prefix:path.trim().to_string(),roles});
        }
    }
    unsafe{POLICIES=Some(v);} }

fn get_policies()-> &'static [Policy] { unsafe{POLICIES.as_deref().unwrap_or(&[])} }

/// Validate request path + Authorization header.
/// Returns true if allowed or no matching policy.
pub fn validate(path:&str, auth_header:Option<&str>) -> bool {
    // find matching policy with longest prefix
    let mut matched:Option<&Policy>=None;
    for p in get_policies() {
        if path.starts_with(&p.prefix) {
            if matched.map_or(true, |m| p.prefix.len()>m.prefix.len()) { matched=Some(p); }
        }
    }
    let policy = match matched { Some(p)=>p, None=>return true }; // no rule -> pass
    // extract roles from JWT
    let token = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) { Some(t)=>t, None=>return false };
    let roles = extract_roles(token);
    for r in &policy.roles { if roles.contains(r) { return true; } }
    false
}

fn extract_roles(token:&str)->Vec<String>{
    let parts:Vec<&str>=token.split('.').collect(); if parts.len()!=3 { return Vec::new(); }
    let payload_b64=parts[1];
    let json_bytes = base64_url_decode(payload_b64);
    if let Ok(s)=str::from_utf8(&json_bytes) {
        if let Some(idx)=s.find("\"roles\"") {
            if let Some(start)=s[idx..].find('[') { if let Some(end)=s[idx+start..].find(']') {
                let list=&s[idx+start+1 .. idx+start+end];
                return list.split(',').map(|r|r.trim_matches('"').to_string()).collect();
            } }
        }
    }
    Vec::new()
}

fn base64_url_decode(s:&str)->Vec<u8>{
    let mut b=s.replace('-','+').replace('_','/');
    while b.len()%4!=0 { b.push('='); }
    base64::decode(b).unwrap_or_default()
} 