//! シンプルな HTTP/1.1 リクエストパーサ (ゼロ外部クレート)。
//! 現時点では Request-Line とヘッダ行の分割のみ行い、
//! 検証やボディ処理、値の正規化は後続フェーズで拡張する予定。

use std::str;
use std::fmt;
use super::error::ErrorKind;

#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

#[derive(Debug)]
pub enum ParseError {
    Incomplete,
    Invalid,
}

impl ParseError {
    pub fn to_error_kind(&self) -> ErrorKind {
        match self {
            ParseError::Incomplete => ErrorKind::Internal,
            ParseError::Invalid => ErrorKind::MalformedHeader,
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n" || w == b"\n\n\n\n")
}

/// ストリーム指向ゼロコピー HTTP/1.x パーサ
pub struct Parser {
    state: ParseState,
    index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState { RequestLine, Headers, Done }

impl Parser {
    pub fn new() -> Self {
        Parser { state: ParseState::RequestLine, index: 0 }
    }

    /// buf[consumed..] 以降を解析し、完了時に `Request` を返す
    pub fn advance<'a>(&mut self, buf: &'a [u8]) -> Result<Option<(Request<'a>, usize)>, ParseError> {
        let start = self.index;
        let slice = &buf[start..];

        match self.state {
            ParseState::RequestLine => {
                if let Some(pos) = memchr::memchr(b'\n', slice) {
                    let line = &slice[..pos];
                    let line_str = trim_cr(line);
                    let mut parts = split_ws(line_str);
                    let method = parts.next().ok_or(ParseError::Invalid)?;
                    let path = parts.next().ok_or(ParseError::Invalid)?;
                    let version = parts.next().ok_or(ParseError::Invalid)?;
                    let consumed = start + pos + 1;
                    self.state = ParseState::Headers;
                    self.index = consumed;
                    // fallthrough to header parse with provisional request object
                    let mut provisional = Request { method, path, version, headers: Vec::new(), body: &[] };
                    return self.collect_headers(buf, provisional);
                }
                Ok(None)
            }
            ParseState::Headers => {
                // Should not reach here directly
                Ok(None)
            }
            ParseState::Done => Ok(None),
        }
    }

    fn collect_headers<'a>(&mut self, buf: &'a [u8], mut req: Request<'a>) -> Result<Option<(Request<'a>, usize)>, ParseError> {
        let start = self.index;
        let slice = &buf[start..];
        if let Some(end_pos) = find_double_crlf(slice) {
            let headers_block = &slice[..end_pos];
            for line in headers_block.split(|&b| b == b'\n') {
                let line = trim_cr(line);
                if line.is_empty() { continue; }
                let bytes = line.as_bytes();
                if let Some(col) = memchr::memchr(b':', bytes) {
                    let name = &line[..col];
                    let value = &line[col+1..];
                    req.headers.push((name.trim(), value.trim()));
                } else { return Err(ParseError::Invalid); }
            }
            let mut consumed = start + end_pos + 4;

            // Determine body length
            let mut content_length: Option<usize> = None;
            let mut chunked = false;
            for (name, val) in &req.headers {
                if name.eq_ignore_ascii_case("content-length") {
                    if let Ok(len) = val.parse::<usize>() {
                        content_length = Some(len);
                    }
                } else if name.eq_ignore_ascii_case("transfer-encoding") && val.trim().eq_ignore_ascii_case("chunked") {
                    chunked = true;
                }
            }

            if let Some(len) = content_length {
                // Ensure buffer has len bytes after headers
                if buf.len() < consumed + len {
                    // Need more data
                    return Ok(None);
                }
                req.body = &buf[consumed .. consumed + len];
                consumed += len;
            } else if chunked {
                match parse_chunked_body(&buf[consumed..]) {
                    Some((body_slice, consumed_extra)) => {
                        req.body = body_slice;
                        consumed += consumed_extra;
                    }
                    None => return Ok(None),
                }
            }

            self.state = ParseState::Done;
            self.index = consumed;
            Ok(Some((req, consumed)))
        } else {
            Ok(None)
        }
    }
}

fn trim_cr(line: &[u8]) -> &str {
    let mut end = line.len();
    if end > 0 && line[end-1] == b'\r' { end -=1; }
    unsafe { str::from_utf8_unchecked(&line[..end]) }
}

fn split_ws<'a>(s: &'a str) -> impl Iterator<Item=&'a str> {
    s.split(|c: char| c.is_ascii_whitespace()).filter(|v| !v.is_empty())
}

mod memchr { #[inline] pub fn memchr(byte: u8, hay: &[u8]) -> Option<usize> { hay.iter().position(|&b| b==byte) } }

impl fmt::Debug for Parser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parser")
            .field("state", &self.state)
            .field("index", &self.index)
            .finish()
    }
}

// Parse chunked transfer encoding. Returns body slice within `input` and total bytes consumed from input (body+terminators).
fn parse_chunked_body(input: &[u8]) -> Option<(&[u8], usize)> {
    let mut pos = 0;
    let mut body_start = 0;
    loop {
        // Find line ending for size
        if let Some(line_end) = memchr::memchr(b'\n', &input[pos..]).map(|i| pos + i) {
            let line = trim_cr(&input[pos..line_end]);
            let size = usize::from_str_radix(line.trim(), 16).ok()?;
            pos = line_end + 1;
            if size == 0 {
                // Expect CRLF after last chunk
                if input.len() < pos + 2 { return None; }
                return Some((&input[body_start .. pos- (line.len()+1)], pos + 2));
            }
            // Ensure enough data
            if input.len() < pos + size + 2 { return None; }
            pos += size + 2; // skip chunk and trailing CRLF
            if body_start == 0 { body_start = line_end + 1; }
        } else { return None; }
    }
} 