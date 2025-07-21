//! 共通型定義 (OS 依存層で共有)

/// EventLoop 登録時・poll 時に用いる識別子
pub type Token = usize;

/// 監視対象の関心事
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interest {
    Readable,
    Writable,
    ReadWrite,
}

/// poll 結果イベント
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub token: Token,
    pub readable: bool,
    pub writable: bool,
} 