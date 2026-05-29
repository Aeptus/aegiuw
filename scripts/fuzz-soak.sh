#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# scripts/fuzz-soak.sh — periodic fuzzing protocol per SNI backlog S6.
#
# We don't have GitHub Actions CI (Aeptus org policy, see DECISIONS.N81), so
# continuous fuzzing is a manual cadence: run this script before a release,
# after any SNI-parser refactor, or on a weekly cron. Each of the three fuzz
# targets gets `$TIMEOUT` seconds of dedicated runtime; libFuzzer writes
# any crashes to `crates/aegiuw-core/fuzz/artifacts/<target>/crash-<hex>`.
#
# Usage:
#   scripts/fuzz-soak.sh            # default 5 minutes per target (15m total)
#   scripts/fuzz-soak.sh 600        # 10 minutes per target (30m total)
#   scripts/fuzz-soak.sh 3600       # 1 hour per target (3h total)
#
# Requires: nightly Rust toolchain + cargo-fuzz (`cargo install cargo-fuzz`).

set -euo pipefail

TIMEOUT=${1:-300}
TARGETS=(extract_sni reassemble_handshake parse_handshake_message)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$REPO_ROOT/crates/aegiuw-core/fuzz"

for target in "${TARGETS[@]}"; do
  echo
  echo "═══ fuzz: $target ($(date +%H:%M:%S), running ${TIMEOUT}s) ═══"
  cargo +nightly fuzz run "$target" -- \
    -max_total_time="$TIMEOUT" \
    -timeout=1 \
    -print_final_stats=1
done

echo
echo "═══ soak complete ═══"
if [ -d artifacts ] && [ -n "$(find artifacts -type f -name 'crash-*' 2>/dev/null)" ]; then
  echo "✗ crashes found — see crates/aegiuw-core/fuzz/artifacts/"
  find artifacts -type f -name 'crash-*'
  exit 1
else
  echo "✓ no crashes across $((TIMEOUT * 3))s of fuzzing"
fi
