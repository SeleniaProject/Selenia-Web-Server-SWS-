# Selenia Web Server – Pending Task Board

> 現在のコードベースで未実装または不完全と判定されたタスク一覧。完了した項目は `[x]` に変更して進捗を更新してください。

---

## 1. Core / OS 抽象層
- [x] kqueue ポーラ実装 (macOS / *BSD)
- [x] IOCP ポーラ実装 (Windows)
- [x] timerfd / EVFILT_TIMER / WaitableTimer を統一するクロスプラットフォームタイマ抽象
- [x] NUMA ピン止め対応マルチスレッド EventLoop への統合
- [x] Accept スレッド & SO_REUSEPORT 分散アルゴリズム
- [x] Lock-Free Skiplist を用いた非同期 DNS キャッシュ

## 2. HTTP スタック
### 2.1 HTTP/1.x
- [x] ボディパーサ (chunked, Content-Length)
- [x] エラーハンドリング & ステータスマッピング
- [x] Keep-Alive 接続プール自動チューニング
- [x] `cargo fuzz` 対応 HTTP/1 パーザハーネス
- [x] wrk2 ベンチシナリオ統合

### 2.2 HTTP/2
- [x] フレームパーサ / シリアライザ完全実装
- [x] ストリーム状態遷移管理 (HEADERS, DATA, RST など)
- [x] SETTINGS / ACK 交渉処理
- [x] ウィンドウフロー制御の本実装
- [ ] HPACK とストリームの結線
- [ ] GOAWAY / graceful shutdown 対応

### 2.3 HTTP/3 (QUIC)
- [ ] QUIC Transport ハンドシェイク & パケット化
- [ ] ストリームスケジューラ & フロー制御
- [ ] QPACK エンコーダ / デコーダ統合
- [ ] 0-RTT / Retry / Datagram Extension 対応

## 3. TLS / Crypto
- [ ] TLS 1.3 ハンドシェイクステートマシン
- [ ] レコードレイヤ (ChaCha20-Poly1305, AES-GCM) 実装
- [ ] セッションチケット & 再開機構
- [ ] OCSP Stapling 自動化

## 4. ルーティング / セキュリティ
- [ ] Radix ツリー Router (rewrite, ワイルドカード対応)
- [ ] JWT ベース RBAC ミドルウェア
- [ ] WAF ルールエンジン実装
- [ ] eBPF インラインルール評価器
- [ ] トークンバケット Rate Limit ミドルウェア

## 5. プラグイン & サンドボックス
- [ ] C ABI プラグインローダ (`cdylib`) バージョン検査付き
- [ ] WASM Edge Function サンドボックス (WASI Snapshot)
- [ ] Capability および seccomp 制限統合

## 6. 観測性
- [ ] 構造化 JSON ロガー (動的レベルリロード対応)
- [ ] Prometheus `/metrics` エクスポータ
- [ ] ヒストグラム / サマリーメトリクス
- [ ] OpenTelemetry Trace エクスポータ (OTLP gRPC)
- [ ] `traceparent` 自動伝播

## 7. CLI & プロセスモデル
- [ ] `start|stop|reload|benchmark|plugin|locale` 各サブコマンド実装
- [ ] マスター / ワーカープロセス管理と graceful reload
- [ ] Zero-Downtime Reload ワークフロー & メトリクス

## 8. デプロイ / CI & 品質ゲート
- [ ] GitHub Actions マトリックス構築 (build, test, fuzz, bench)
- [ ] `cargo clippy` / `cargo fmt` 自動ゲート
- [ ] `llvm-cov` カバレッジレポート統合
- [ ] FUZZ ターゲット 24h CI
- [ ] SBOM 生成 & cosign 署名

## 9. ベンチマーク自動化
- [ ] wrk2 シナリオ自動実行
- [ ] h2load シナリオ自動実行
- [ ] quicperf シナリオ自動実行

---

### Legend
- ✅ / `[x]` : 実装完了・テスト済み
- ⬜️ / `[ ]` : 未実装 / 進行中 