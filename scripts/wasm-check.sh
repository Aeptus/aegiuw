#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# scripts/wasm-check.sh — confirm aegiuw-core compiles to wasm32-unknown-unknown.
#
# Per DECISIONS.N76 (compile aegiuw-core to WASM for use inside the Cloudflare
# Worker — single source of truth, no Rust/TS schema drift) and SNI backlog I3
# (confirm the build still works after `tracing` landed in O1).
#
# The Worker config is `--no-default-features` (core + alloc only, no std) per
# P6, so that's the build that must succeed. We also smoke the std and
# unstable_extensions configs.
#
# Usage:
#   scripts/wasm-check.sh

set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown

# Install the target on demand. Idempotent.
if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
  echo "→ installing ${TARGET} target …"
  rustup target add "${TARGET}"
fi

echo "→ aegiuw-core → ${TARGET} (Worker config: --no-default-features)"
cargo build -p aegiuw-core --target "${TARGET}" --no-default-features

echo "→ aegiuw-core → ${TARGET} (default features / std)"
cargo build -p aegiuw-core --target "${TARGET}"

echo "→ aegiuw-core → ${TARGET} (--no-default-features --features unstable_extensions)"
cargo build -p aegiuw-core --target "${TARGET}" --no-default-features --features unstable_extensions

echo "✓ aegiuw-core compiles to ${TARGET} in all three configs"
