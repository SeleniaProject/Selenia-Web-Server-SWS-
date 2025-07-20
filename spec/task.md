# Selenia Web Server – Task Board

> このドキュメントは `spec/SPECIFICATION.md` と `spec/DESIGN.md` に基づき、実装すべき全項目を洗い出した開発タスク一覧である。チェック済み (`[x]`) は現時点で既に実装・コミットされている部分を示す。未チェック (`[ ]`) は今後実装が必要な項目を示す。タスク完了後はプルリクエストにて本ファイルを更新すること。

---

## 1. Core / OS 抽象層
- [x] Poller 抽象トレイト実装 (`epoll`, `kqueue`, `IOCP`, `Stub`)
- [x] Non-blocking EventLoop (`event_loop.rs`)
- [x] Multi-poller auto-selection & runtime fallback
- [x] Async DNS キャッシュ (skiplist + TTL eviction)
- [x] Hot-Reload マスター/ワーカープロセス制御

## 2. Crypto Subsystem
- [x] ChaCha20 (RFC8439) 実装
- [x] Poly1305 (RFC8439) 実装
- [x] SHA-256 / HMAC / HKDF
- [x] AES-GCM (software fallback + AES-NI)
- [x] TLS 1.3 握手 & レコードレイヤ
- [x] OCSP Stapling / HSTS 自動付与

## 3. HTTP Stack
### 3.1 HTTP/1.x
- [x] 手書き 0-alloc パーサ (`parser.rs`)
- [x] 静的ファイル送出 (sendfile / TransmitFile)
- [x] Keep-Alive connection pool auto-tune

### 3.2 HTTP/2
- [x] HPACK 圧縮/展開完全実装
- [x] ストリーム優先度ツリー & フロー制御

### 3.3 HTTP/3 (QUIC)
- [x] QUIC Transport ハンドシェイク
- [x] QPACK 圧縮/展開
- [x] 0-RTT / Retry / Datagram Extension

### 3.4 共通
- [x] Range / Conditional / ETag 処理
- [x] Gzip / Deflate 圧縮
- [x] Brotli / Zstd 実装完了

## 4. Plugin & Sandbox
- [x] C ABI Plugin Loader (`cdylib`)
- [x] WASM Edge Function (WASI Snapshot)
- [x] Capability / seccomp 制限

## 5. Routing / RBAC / WAF
- [x] Radix ツリー Router (rewrite, redirect, proxy)
- [x] YAML ベース設定ローダ (`config.rs`)
- [x] locale / i18n 骨格 (`locale.rs`)
- [x] JWT RBAC ミドルウェア
- [x] WAF Skeleton (`waf.rs`)
- [x] eBPF inline rule evaluator
- [ ] Token bucket Rate-Limit

## 6. Observability
- [x] 構造化 JSON ロガー (`logger.rs`)
- [ ] Log rotation & level reload via SIGHUP
- [x] Metrics カウンタ / ヒストグラム (`metrics.rs`)
- [ ] Prometheus `/metrics` HTTP エンドポイント
- [ ] OpenTelemetry Trace exporter (OTLP gRPC)

## 7. Operations / CLI
- [x] ベンチマークツール (`tools/bench.rs`)
- [ ] `sws start|stop|reload|benchmark|plugin|locale` CLI サブコマンド実装
- [ ] `sws plugin install/validate` flow
- [ ] Zero-Downtime Reload ワークフロー

## 8. CI/CD & Quality Gate
- [ ] GitHub Actions Matrix (build, test, fuzz, bench)
- [ ] `cargo llvm-cov` 100% 取得
- [ ] Fuzz ハーネス (`cargo fuzz`) for parser, HPACK, QUIC
- [ ] SBOM 自動生成 & cosign 署名

## 9. Security & Hardening
- [ ] memfd_secret TLS key loader
- [ ] Live-Patch 差分適用エンジン
- [ ] seccomp-BPF allowlist 自動生成
- [ ] supply-chain SBOM / CVE bot integration

## 10. Deployment / Packaging
- [ ] Single static binary (`cargo strip`, `upx`)
- [ ] Multi-arch Docker build (`scratch` 6 MB)
- [ ] Helm / K8s Manifests with readiness & liveness probes

## 11. Performance Benchmarks
- [ ] wrk2 シナリオ (HTTP/1) 260 Gbps 達成
- [ ] h2load シナリオ (HTTP/2) 220 Gbps 達成
- [ ] quicperf シナリオ (HTTP/3) 240 Gbps 達成

## 12. Documentation & Spec Compliance
- [x] SPECIFICATION.md 完成
- [x] DESIGN.md 完成
- [ ] Rustdoc 100% 公開 API カバレッジ
- [ ] man page / HTML ドキュメント自動生成

---

### Legend
- ✅ / `[x]` : 実装完了・テスト済み
- ⬜️ / `[ ]` : 未実装 / 進行中

進捗更新の際はコミットメッセージに `task: update` を含め、本ファイルを忘れずに編集して下さい。 