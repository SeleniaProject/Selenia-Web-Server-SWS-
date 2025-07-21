# Selenia Web Server – Pending Task Board

---

### Legend
- ✅ / `[x]` : 実装完了・テスト済み
- ⬜️ / `[ ]`

## 未実装タスク一覧

### 1. Core / OS 抽象層
- [x] kqueue ポーラ実装 (macOS / *BSD)
- [x] IOCP ポーラ実装 (Windows)
- [x] timerfd / EVFILT_TIMER / WaitableTimer を統一するクロスプラットフォームタイマ抽象
- [x] NUMA ピン止め対応マルチスレッド EventLoop への統合
- [x] Accept スレッド & SO_REUSEPORT 分散アルゴリズム
- [x] Lock-Free Skiplist を用いた非同期 DNS キャッシュ

### 2. HTTP スタック
#### 2.1 HTTP/1.x
- [x] ボディパーサ (chunked, Content-Length)
- [x] エラーハンドリング & ステータスマッピング
- [x] Keep-Alive 接続プール自動チューニング
- [x] `cargo fuzz` 対応 HTTP/1 パーザハーネス
- [x] wrk2 ベンチシナリオ統合

#### 2.2 HTTP/2
- [x] フレームパーサ / シリアライザ完全実装
- [x] ストリーム状態遷移管理 (HEADERS, DATA, RST など)
- [x] SETTINGS / ACK 交渉処理
- [x] ウィンドウフロー制御の本実装
- [x] HPACK とストリームの結線
- [x] GOAWAY / graceful shutdown 対応

#### 2.3 HTTP/3 (QUIC)
- [x] QUIC Transport ハンドシェイク & パケット化
- [x] ストリームスケジューラ & フロー制御
- [x] QPACK エンコーダ / デコーダ統合
- [x] 0-RTT / Retry / Datagram Extension 対応

### 3. TLS / Crypto
- [x] TLS 1.3 ハンドシェイクステートマシン
- [x] レコードレイヤ (ChaCha20-Poly1305, AES-GCM) 実装
- [x] セッションチケット & 再開機構
- [x] OCSP Stapling 自動化

### 4. ルーティング / セキュリティ
- [x] Radix ツリー Router (rewrite, ワイルドカード対応)
- [x] JWT ベース RBAC ミドルウェア
- [x] WAF ルールエンジン実装
- [x] eBPF インラインルール評価器
- [x] トークンバケット Rate Limit ミドルウェア

### 5. プラグイン & サンドボックス
- [x] C ABI プラグインローダ (`cdylib`) バージョン検査付き
- [x] WASM Edge Function サンドボックス (WASI Snapshot)
- [x] Capability および seccomp 制限統合

### 6. 観測性
- [x] 構造化 JSON ロガー (動的レベルリロード対応)
- [x] Prometheus `/metrics` エクスポータ
- [x] ヒストグラム / サマリーメトリクス
- [x] OpenTelemetry Trace エクスポータ (OTLP gRPC)
- [x] `traceparent` 自動伝播

### 7. CLI & プロセスモデル
- [x] `start|stop|reload|benchmark|plugin|locale` 各サブコマンド実装
- [x] マスター / ワーカープロセス管理と graceful reload
- [x] Zero-Downtime Reload ワークフロー & メトリクス

### 8. デプロイ / CI & 品質ゲート
- [ ] GitHub Actions マトリックス構築 (build, test, fuzz, bench)
- [ ] `cargo clippy` / `cargo fmt` 自動ゲート
- [ ] `llvm-cov` カバレッジレポート統合
- [ ] FUZZ ターゲット 24h CI
- [ ] SBOM 生成 & cosign 署名

### 9. ベンチマーク自動化
- [ ] wrk2 シナリオ自動実行
- [ ] h2load シナリオ自動実行
- [ ] quicperf シナリオ自動実行