//! Radix tree based router supporting static, param, and wildcard segments.
//! This minimal implementation is enough for rewrite / proxy matching and will
//! be extended in later phases.

use std::collections::HashMap;

#[derive(Debug, Default)]
struct Node {
    children: HashMap<String, Node>,
    param_child: Option<Box<Node>>, // :param
    wildcard_child: Option<Box<Node>>, // *splat
    handler: Option<usize>, // index into handler table
    segment: String,
}

pub struct Router {
    root: Node,
    handlers: Vec<String>,
}

impl Router {
    pub fn new() -> Self { Self { root: Node::default(), handlers: Vec::new() } }

    pub fn add(&mut self, path: &str, dest: &str) {
        let mut node=&mut self.root;
        for seg in path.trim_start_matches('/').split('/') {
            match seg.chars().next() {
                Some(':') => { node = node.param_child.get_or_insert_with(|| Box::new(Node{segment:seg.to_string(), ..Default::default()})); }
                Some('*') => { node = node.wildcard_child.get_or_insert_with(|| Box::new(Node{segment:seg.to_string(), ..Default::default()})); break; }
                _ => { node = node.children.entry(seg.to_string()).or_default(); node.segment=seg.to_string(); }
            }
        }
        let id=self.handlers.len();
        self.handlers.push(dest.to_string());
        node.handler=Some(id);
    }

    pub fn find(&self, path: &str) -> Option<&str> {
        let mut node=&self.root;
        for seg in path.trim_start_matches('/').split('/') {
            if let Some(next)=node.children.get(seg) { node=next; continue; }
            if let Some(ref param)=node.param_child { node=param; continue; }
            if let Some(ref wc)=node.wildcard_child { node=wc; break; }
            return None;
        }
        node.handler.map(|id| self.handlers[id].as_str())
    }
} 