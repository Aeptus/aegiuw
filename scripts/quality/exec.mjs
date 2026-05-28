// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Subprocess execution helper used by gates.
 *
 * Returns a uniform `{ passed, durationMs, output, reason }` shape so the
 * runner can format output identically regardless of which tool ran.
 */

import { spawn } from 'node:child_process';

export async function runCmd(cmd, args, opts = {}) {
  const timeout = opts.timeoutMs ?? 60_000;
  const cwd = opts.cwd ?? process.cwd();
  const env = opts.env ?? process.env;
  const start = Date.now();

  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let killed = false;

    proc.stdout?.on('data', (d) => {
      stdout += d.toString('utf8');
    });
    proc.stderr?.on('data', (d) => {
      stderr += d.toString('utf8');
    });

    const timer = setTimeout(() => {
      killed = true;
      proc.kill('SIGKILL');
    }, timeout);

    proc.on('close', (code) => {
      clearTimeout(timer);
      const durationMs = Date.now() - start;
      if (killed) {
        resolve({
          passed: false,
          durationMs,
          output: stdout + stderr,
          reason: `timeout after ${timeout}ms`,
        });
        return;
      }
      const passed = code === 0;
      resolve({
        passed,
        durationMs,
        output: stdout + stderr,
        reason: passed ? '' : `${cmd} ${args.join(' ')} exited ${code}`,
      });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        passed: false,
        durationMs: Date.now() - start,
        output: String(err),
        reason: err.message,
      });
    });
  });
}
