#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# scripts/mutants.sh — run cargo-mutants on aegiuw-core to check the SNI
# parser's test coverage quality. Per SNI backlog S10 (P3).
#
# cargo-mutants modifies the source (flips comparisons, replaces returns,
# etc.) and runs tests. A *surviving* mutant means the test suite didn't
# notice — that line is uncovered or the assertions are too loose.
#
# Usage:
#   scripts/mutants.sh                          # full run on aegiuw-core
#   scripts/mutants.sh --file src/sni.rs        # SNI parser only
#   scripts/mutants.sh --no-shuffle             # deterministic order
#
# Expect a long run: each mutant requires a full test build + run. Budget
# 15–60 minutes depending on host.

set -euo pipefail

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "→ installing cargo-mutants …"
  cargo install cargo-mutants
fi

cd "$(dirname "$0")/.."
cargo mutants -p aegiuw-core "$@"
