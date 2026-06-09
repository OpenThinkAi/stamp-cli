import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import type { CheckDef, QuarantineEntry } from "./config.js";

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
  /**
   * Operator-declared flake-quarantine list copied from `CheckDef.quarantine`,
   * forwarded onto the result so the merge code can fold it into the
   * signed attestation alongside the check's verdict. Undefined when the
   * check has no quarantine (preserves byte-identity for envelopes from
   * repos that don't use the feature).
   */
  quarantine?: QuarantineEntry[];
}

/** Env var the check's shell command receives when a quarantine list is
 *  active for that check. Comma-joined `test` IDs from `QuarantineEntry`.
 *  Stamp does not interpret the IDs — the operator's command consumes
 *  them in whatever shape its test runner expects. */
export const QUARANTINE_ENV_VAR = "STAMP_QUARANTINE_TESTS";

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
    // Quarantine env-var pass-through (AGT-476). When the check has a
    // non-empty quarantine list, export comma-joined `test` IDs via
    // STAMP_QUARANTINE_TESTS so the operator's command can opt to skip
    // them. We never strip the check itself — the operator's runner
    // does the actual skipping. The signed list on the result side is
    // what gets folded into the attestation, so a verifier can audit
    // which gates were declared not-enforced for this merge.
    const env =
      check.quarantine && check.quarantine.length > 0
        ? {
            ...process.env,
            [QUARANTINE_ENV_VAR]: check.quarantine.map((q) => q.test).join(","),
          }
        : process.env;

    const start = Date.now();
    const proc = spawnSync(check.run, {
      cwd,
      shell: true,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      env,
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
      ...(check.quarantine && check.quarantine.length > 0
        ? { quarantine: check.quarantine }
        : {}),
    });
  }
  return results;
}

export function allPassed(results: CheckResult[]): boolean {
  return results.every((r) => r.exit_code === 0);
}

/**
 * Canonical signature emitted by vitest's fork-pool when a worker process
 * fails to start within the startup timeout. On macOS this is most often
 * caused by `syspolicyd`'s ExecPolicy DB bloating under heavy subagent
 * churn (every short-lived binary launch goes through ExecPolicy), which
 * slows process spawn enough that vitest's fork worker exceeds its
 * startup deadline. The failure is indistinguishable from a real test
 * failure at the exit-code level, so the diagnostic below surfaces the
 * suspected cause and recovery path.
 *
 * Kept as a single regex so future vitest wording shifts are a one-line fix.
 */
const VITEST_FORK_POOL_FLAKE_RE = /Failed to start forks worker/;

/**
 * Returns true when the captured check output bears the vitest fork-pool
 * worker-startup-timeout signature. Pure — caller is responsible for
 * formatting and printing the diagnostic message.
 */
export function detectVitestForkPoolFlake(output: string): boolean {
  if (!output) return false;
  return VITEST_FORK_POOL_FLAKE_RE.test(output);
}

/**
 * The diagnostic line(s) to print when `detectVitestForkPoolFlake` matches.
 * Identifies the suspected root cause (macOS syspolicyd ExecPolicy DB bloat
 * from heavy subagent churn) and points at the recovery path so the operator
 * doesn't burn time debugging a flake as a real test failure.
 */
export const VITEST_FORK_POOL_FLAKE_DIAGNOSTIC = [
  "This looks like a vitest fork-pool worker-startup timeout, NOT a real",
  "test failure. On macOS this is typically caused by syspolicyd's",
  "ExecPolicy DB bloating under heavy subagent churn — every short-lived",
  "binary launch goes through ExecPolicy, slowing process spawn enough",
  "that vitest's fork worker exceeds its startup deadline.",
  "",
  "Recovery: reboot the machine (clears the in-memory backlog). If it",
  "recurs immediately after reboot, reset the ExecPolicy DB:",
  "  sudo mv /var/db/SystemPolicyConfiguration/ExecPolicy{,.bak.$(date +%s)}",
  "  sudo reboot",
  "Then re-run `stamp merge`. If the same check fails with a different",
  "signature, treat it as a real test failure.",
].join("\n");
