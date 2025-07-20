#!/usr/bin/env bash
set -euo pipefail
TARGET="x86_64-unknown-linux-musl"
rustup target add ${TARGET} || true
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target ${TARGET}
strip target/${TARGET}/release/selenia_server
if command -v upx >/dev/null 2>&1; then
  upx --lzma --best target/${TARGET}/release/selenia_server
fi
echo "Static binary available at target/${TARGET}/release/selenia_server" 