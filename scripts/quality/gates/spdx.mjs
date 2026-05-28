// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Verify every Rust source file and every Worker TypeScript source file
 * begins with an `SPDX-License-Identifier: AGPL-3.0-or-later` declaration
 * (per `DECISIONS.N75` — AGPL-3.0-or-later applies to the OSS core).
 */

import { readFileSync } from 'node:fs';
import { gitListFiles } from '../git.mjs';

const HEADER_RE = /SPDX-License-Identifier:\s*AGPL-3\.0-or-later/;
const RUST_RE = /\.rs$/;
const TS_WORKER_RE = /^workers\/aegiuw-router\/src\/.*\.ts$/;

function shouldCheck(path) {
  return RUST_RE.test(path) || TS_WORKER_RE.test(path);
}

/**
 * Allow the SPDX header anywhere in the first 5 lines so it can sit after
 * an optional shebang or `#![…]` inner attribute on Rust binaries.
 */
function hasSpdxHeader(content) {
  const head = content.split('\n', 5).join('\n');
  return HEADER_RE.test(head);
}

export async function checkSpdx(ctx) {
  const start = Date.now();
  let targets;
  if (ctx.mode === 'prepush-full' || ctx.mode === 'local') {
    targets = gitListFiles('.').filter(shouldCheck);
  } else {
    targets = ctx.relevantFiles.filter(shouldCheck);
  }

  const missing = [];
  for (const f of targets) {
    try {
      const c = readFileSync(f, 'utf8');
      if (!hasSpdxHeader(c)) missing.push(f);
    } catch {
      missing.push(`${f} (unreadable)`);
    }
  }

  const passed = missing.length === 0;
  return {
    passed,
    durationMs: Date.now() - start,
    output: missing.map((f) => `  missing SPDX header: ${f}`).join('\n'),
    reason: passed
      ? ''
      : `${missing.length} file(s) missing 'SPDX-License-Identifier: AGPL-3.0-or-later'`,
  };
}
