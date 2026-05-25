/**
 * AGT-112 — post-review retention advisory for `stamp review`.
 *
 * After a `stamp review` run completes (both local and server-attested paths),
 * this module checks whether any rows in `state.db` or spool files are older
 * than the operator-configured `retention:` thresholds in `.stamp/config.yml`
 * and either:
 *
 *   - Emits an advisory line to stderr: "note: state.db has N reviews older
 *     than 90d; run `stamp prune --older-than 90d` to clean up." (default)
 *   - OR auto-prunes via `runPrune` when `retention.auto_prune: true` is set.
 *
 * The advisory is suppressed by `STAMP_SUPPRESS_LLM_NOTICE=1`, matching the
 * convention used by dataFlow.ts and llmNotice.ts. Auto-prune is NOT
 * suppressible — the operator explicitly opted in.
 *
 * Both the local-LLM path and the server-attested path in `commands/review.ts`
 * wire a single call to `printRetentionAdvisory` as a shared tail helper so
 * neither path drifts from the other (per the approved plan decision).
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";

import { peekSpools, runPrune } from "../commands/prune.js";
import type { RetentionConfig } from "./config.js";
import { parseRetentionDuration } from "./duration.js";
import { gitCommonDir } from "./paths.js";
import { peekPrunable } from "./db.js";

const SUPPRESS_ENV = "STAMP_SUPPRESS_LLM_NOTICE";

function noticesSuppressed(): boolean {
  return process.env[SUPPRESS_ENV] === "1";
}

/**
 * Pure formatter — returns advisory line(s) for a given count, label, and
 * duration. Returns an empty array when count is 0 or duration is unset.
 * Separated from the printing/prune logic for deterministic unit testing.
 *
 * @param count  Number of overdue items (rows or spool files).
 * @param kind   "reviews" or "spools" — used in the advisory prose.
 * @param humanLabel  Human-readable duration string (e.g. "90d").
 */
export function formatRetentionAdvisory(
  count: number,
  kind: "reviews" | "spools",
  humanLabel: string,
): string[] {
  if (count === 0) return [];
  const item = kind === "reviews" ? "review" : "spool file";
  const items = kind === "reviews" ? "reviews" : "spool files";
  const noun = count === 1 ? item : items;
  return [
    `note: state.db has ${count} ${noun} older than ${humanLabel}; run \`stamp prune --older-than ${humanLabel}\` to clean up`,
  ];
}

/**
 * The shared tail helper wired into BOTH review paths in `commands/review.ts`.
 *
 * Checks the open `db` against `retention.reviews` and counts overdue spool
 * files against `retention.spools`. When `auto_prune: true`, calls `runPrune`
 * instead of advising; otherwise prints advisory line(s) to stderr.
 *
 * Safe to call when `retention` is undefined — no-ops cleanly. Also no-ops
 * when `db` is null (no state.db exists yet) for the reviews pass, and
 * when the spool dirs don't exist for the spools pass.
 *
 * @param db        Open DatabaseSync handle (caller owns close). May be null
 *                  when state.db didn't exist before the review run.
 * @param repoRoot  Absolute repo root, used to locate spool dirs.
 * @param retention Parsed retention config from `.stamp/config.yml`, or
 *                  undefined when the field is absent.
 */
export function printRetentionAdvisory(
  db: DatabaseSync | null,
  repoRoot: string,
  retention: RetentionConfig | undefined,
): void {
  if (!retention) return;
  if (!retention.reviews && !retention.spools) return;

  const auto = retention.auto_prune === true;

  if (auto) {
    // Auto-prune: call runPrune for whichever thresholds are configured.
    // runPrune internally re-finds the repo root, so we only need to chdir
    // or pass the relevant opts. Since runPrune calls findRepoRoot() itself,
    // and review.ts already has the repo root resolved, we call it with the
    // first configured threshold — reviews takes precedence when both are set
    // (they share the same underlying prune command and duration). In practice
    // an operator sets both to the same value; if they differ, the reviews
    // threshold drives the prune (spools are also pruned at that duration).
    //
    // NOTE: auto_prune always uses the reviews duration when set, falling back
    // to spools duration. Both thresholds are enforced by a single runPrune
    // call since runPrune sweeps both the DB rows and the spool dirs.
    const olderThan = retention.reviews ?? retention.spools!;
    try {
      runPrune({ olderThan });
    } catch (err) {
      // Surface the error as a stderr warning rather than aborting — the
      // review itself succeeded; a prune failure is advisory, not fatal.
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(
        `warning: retention.auto_prune failed (${message}); run \`stamp prune --older-than ${olderThan}\` manually\n`,
      );
    }
    return;
  }

  // Advisory-only path: count overdue items and print the advisory line(s).
  if (noticesSuppressed()) return;

  // Reviews pass
  if (retention.reviews && db !== null) {
    try {
      const { sqliteModifier, humanLabel } = parseRetentionDuration(retention.reviews);
      const peek = peekPrunable(db, sqliteModifier);
      for (const line of formatRetentionAdvisory(peek.total, "reviews", humanLabel)) {
        process.stderr.write(`${line}\n`);
      }
    } catch {
      // Defensive: parseRetentionDuration already validated at config-load
      // time, so this shouldn't throw. Silently skip rather than aborting
      // a completed review.
    }
  }

  // Spools pass
  if (retention.spools) {
    try {
      const { durationMs, humanLabel } = parseRetentionDuration(retention.spools);
      const cutoffMs = Date.now() - durationMs;
      const commonDir = gitCommonDir(repoRoot);
      const parsesDir = join(commonDir, "stamp", "failed-parses");
      const runsDir = join(commonDir, "stamp", "failed-runs");
      let spoolCount = 0;
      if (existsSync(parsesDir)) spoolCount += peekSpools(parsesDir, cutoffMs).length;
      if (existsSync(runsDir)) spoolCount += peekSpools(runsDir, cutoffMs).length;
      for (const line of formatRetentionAdvisory(spoolCount, "spools", humanLabel)) {
        process.stderr.write(`${line}\n`);
      }
    } catch {
      // Defensive: same rationale as reviews pass above.
    }
  }
}
