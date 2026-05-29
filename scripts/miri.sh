#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# scripts/miri.sh — run MIRI on aegiuw-core to catch undefined behavior.
#
# `aegiuw-core` already enforces `unsafe_code = "forbid"`, so MIRI should find
# nothing — this script is the *proof* of that. Per SNI backlog S9 (P3).
#
# Usage:
#   scripts/miri.sh                  # run MIRI on the full test suite
#   scripts/miri.sh sni              # filter to SNI tests only
#
# Caveats:
#   - MIRI is 100×+ slower than native execution. The full suite under MIRI
#     can take 10–30 minutes locally.
#   - Proptest properties run their default 256 cases per property under
#     MIRI — slow. Set `PROPTEST_CASES=8 scripts/miri.sh` to reduce.

set -euo pipefail

# Install MIRI components on demand. Idempotent.
if ! rustup +nightly component list --installed 2>/dev/null | grep -q '^miri'; then
  echo "→ installing miri component …"
  rustup +nightly component add miri
fi
if ! rustup +nightly component list --installed 2>/dev/null | grep -q '^rust-src'; then
  echo "→ installing rust-src component …"
  rustup +nightly component add rust-src
fi

cd "$(dirname "$0")/.."

FILTER=${1:-}
echo "→ cargo +nightly miri test -p aegiuw-core ${FILTER}"
cargo +nightly miri test -p aegiuw-core -- "$FILTER"
