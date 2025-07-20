//! Simplified eBPF inline rule evaluator – placeholder.
//! In production we would JIT‐compile BPF byte-code; here we parse a rule list
//! and register equivalent Rust closures into `waf`.

use crate::waf;

pub fn load_rules(rules:&str) {
    for line in rules.lines() {
        let l=line.trim(); if l.is_empty()||l.starts_with('#'){continue;}
        // syntax: block /path/prefix
        if let Some(path)=l.strip_prefix("block ") {
            let path=path.trim().to_string();
            waf::register_filter(PathBlock{prefix:path});
        }
    }
}

struct PathBlock{prefix:String}
impl waf::RequestFilter for PathBlock {
    fn check(&self, _m:&str, path:&str, _h:&[(String,String)]) -> bool {
        !path.starts_with(&self.prefix)
    }
} 