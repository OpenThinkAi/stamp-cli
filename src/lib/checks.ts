import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import type { CheckDef } from "./config.js";

export interface CheckResult {
  name: string;
  command: string;
  exit_code: number;
  /** sha256 of concatenated stdout+stderr, hex. Ties the attestation to
   * the output the signer actually saw. */
  output_sha: string;
  /** Truncated stdout/stderr for on-terminal debugging. Not included in the
   * signed payload — just for the prose report the caller prints. */
  tail: string;
  duration_ms: number;
}

/**
 * Run each check command in sequence. Returns one result per check.
 * Does not throw on non-zero exits — the caller inspects `exit_code`.
 *
 * Commands run via the shell so `npm run build` / chained commands work
 * as authors write them in config.yml. Inherits the current environment
 * (including PATH, so `npm`, `npx`, etc. resolve the way the operator expects).
 */
export function runChecks(
  checks: CheckDef[],
  cwd: string,
): CheckResult[] {
  const results: CheckResult[] = [];
  for (const check of checks) {
    const start = Date.now();
    const proc = spawnSync(check.run, {
      cwd,
      shell: true,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    const duration_ms = Date.now() - start;

    const stdout = proc.stdout ?? "";
    const stderr = proc.stderr ?? "";
    const combined = stdout + stderr;
    const output_sha = createHash("sha256").update(combined, "utf8").digest("hex");

    // Keep last ~800 chars for the printed tail (whichever surface is noisier
    // — prefer stderr if present, since test runners often report failures there).
    const noisy = stderr.trim() ? stderr : stdout;
    const tail = noisy.length > 800 ? "…" + noisy.slice(-800) : noisy;

    results.push({
      name: check.name,
      command: check.run,
      exit_code: proc.status ?? (proc.signal ? 128 : 1),
      output_sha,
      tail,
      duration_ms,
    });
  }
  return results;
}

export function allPassed(results: CheckResult[]): boolean {
  return results.every((r) => r.exit_code === 0);
}
