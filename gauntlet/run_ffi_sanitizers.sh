#!/usr/bin/env bash
# Run on a supported Linux host. Keep leak detection enabled and preserve failures.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REC="${GAUNTLET_RECEIPTS:-$HERE/receipts}"
mkdir -p "$REC"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/ffi-asan}"
export RUSTFLAGS="-Zsanitizer=address"
# Do not inherit leak suppression settings from the caller.
export ASAN_OPTIONS="detect_leaks=1"
export LSAN_OPTIONS="exitcode=23"
cargo +nightly test --locked -p citadel-ffi --lib -Zbuild-std \
  --target x86_64-unknown-linux-gnu -- --test-threads=1 \
  2>&1 | tee "$REC/ffi-sanitizers.txt"
