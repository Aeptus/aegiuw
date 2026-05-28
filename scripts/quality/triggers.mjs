// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Force-full-suite rules: pre-push escalates to prepush-full when the
 * change set touches anything that invalidates scoped reasoning.
 *
 * Adapted to aegiuw's actual surface (Rust workspace + one Worker + docs
 * + hooks). Trimmed from the spec's polyglot list, but the principle is
 * preserved: if the change alters the graph, the validator, or shared
 * contracts, do not trust a narrow run.
 */

const FULL_TRIGGER_PATHS = [
  // Hook + runner infrastructure
  /^hooks\//,
  /^scripts\/quality\//,

  // Cargo workspace surface
  /^Cargo\.toml$/,
  /^Cargo\.lock$/,
  /^rust-toolchain\.toml$/,
  /^crates\/[^/]+\/Cargo\.toml$/,

  // Worker config
  /^workers\/aegiuw-router\/(package(-lock)?\.json|tsconfig\.json|wrangler\.jsonc)$/,

  // Root config
  /^package(-lock)?\.json$/,
  /^\.gitignore$/,
];

/**
 * Decide whether a pre-push run must escalate to prepush-full.
 *
 * @param {{ mode: string, forceFull: boolean, changedFiles: string[] }} ctx
 * @returns {{ full: boolean, reason: string }}
 */
export function shouldRunFullSuite(ctx) {
  if (ctx.mode === 'prepush-full') return { full: true, reason: 'explicit mode' };
  if (ctx.forceFull) return { full: true, reason: '--full flag' };
  if (!ctx.changedFiles || ctx.changedFiles.length === 0) {
    return { full: true, reason: 'no changed files resolved (cannot scope safely)' };
  }
  for (const f of ctx.changedFiles) {
    for (const re of FULL_TRIGGER_PATHS) {
      if (re.test(f)) {
        return { full: true, reason: `high-impact file changed: ${f}` };
      }
    }
  }
  return { full: false, reason: 'scoped run is safe' };
}

export const _internal = { FULL_TRIGGER_PATHS };
