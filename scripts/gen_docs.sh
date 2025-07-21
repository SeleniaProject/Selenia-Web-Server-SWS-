#!/usr/bin/env bash
set -euo pipefail
# Build docs
cargo doc --workspace --no-deps
# Generate man page via help2man if available
BIN=target/release/selenia_server
if [ ! -f "$BIN" ]; then
  cargo build --release --bin selenia_server
fi
mkdir -p docs
if command -v help2man >/dev/null 2>&1; then
  help2man -N "$BIN" -o docs/sws.1 --no-discard-stderr || true
  # Convert to HTML for GitHub Pages if man2html exists
  if command -v man2html >/dev/null 2>&1; then
    man2html docs/sws.1 > docs/sws.html || true
  fi
fi
printf "Docs generated under target/doc and docs/\n" 