import { readSync } from "node:fs";
import type { BranchRule } from "./config.js";

/**
 * Audit H1 — residual-risk reframing of "LLM verdict directly authorizes
 * signed merges to protected branches." Mitigations against prompt
 * injection are state-of-the-art (random hex fence, structured tool
 * channel, last-line VERDICT regex, MCP allowlist, WebFetch path pinning),
 * but the auditor explicitly notes the residual stays high because the
 * sink is signed merge to main.
 *
 * The defense added here is operator awareness: by default `stamp merge`
 * pauses for an interactive y/N before signing the merge commit. The
 * operator sees what's about to land — base→head SHAs, the source branch,
 * the target — and confirms (or aborts) before any history change.
 *
 * Three opt-outs, all explicit:
 *   1. CLI flag      `stamp merge … --yes`     (per-invocation, the
 *                                              "I'm about to do a batch
 *                                              of these" path)
 *   2. Env var       `STAMP_REQUIRE_HUMAN_MERGE=0`  (per-shell, agent loop)
 *   3. Repo config   `branches.<name>.require_human_merge: false`
 *                                              (per-branch, only the
 *                                              repo's own reviewers can
 *                                              add this — it goes
 *                                              through stamp review like
 *                                              any other config change)
 *
 * Non-interactive without an opt-out is a hard fail: a stamp client
 * running under a CI shell or an agent harness with no stdin TTY MUST
 * declare its intent to bypass the human gate. Silent fall-through to
 * "merge unattended" defeats the entire point of this finding.
 */
export interface RequireHumanMergeArgs {
  /** Target branch (the protected one — e.g. "main"). */
  target: string;
  /** Source branch being merged in. */
  source: string;
  /** Merge-base SHA of source and target (the diff's base). Shown in the
   *  prompt so the operator sees what's actually about to be signed. */
  base_sha: string;
  /** Tip SHA of the source branch (the diff's head). The most useful
   *  thing to display — catches a stale or attacker-shifted source. */
  head_sha: string;
  /** Resolved branch rule from .stamp/config.yml. */
  branchRule: BranchRule;
  /** Whether the operator passed --yes on the command line. */
  yes: boolean;
  /**
   * Output of `git diff --stat <base>..<head>` for the merge. When
   * present, printed above the confirmation prompt so the operator sees
   * diff-shaped content (filenames + churn counts, not raw diff text)
   * before confirming. Injected by the merge caller (which has repoRoot
   * and can run git) so this function stays unit-testable without a
   * live git repo.
   *
   * AC#2 (audit H1 residual hardening).
   */
  diffStat?: string;
  /**
   * Test seam: inject a line-reader so tests can exercise the prompt path
   * in-process without spawning a subprocess or attaching a real TTY.
   * Production callers omit this; it defaults to `readLineSync`.
   */
  _readLine?: () => string;
}

export function requireHumanMerge(args: RequireHumanMergeArgs): void {
  // Any of these three opts out; check order is incidental — all three
  // are operator-declared intent and return silently.
  // IMPORTANT: use strict equality (=== false, not falsy) so that the
  // string value "strict" is never truthy-coerced into bypassing the gate.
  if (args.branchRule.require_human_merge === false) return;
  if (args.yes) return;
  if (process.env.STAMP_REQUIRE_HUMAN_MERGE === "0") return;

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error(
      `confirmation required: stamp merge needs interactive confirmation ` +
        `for protected branch "${args.target}", but no TTY is attached.\n\n` +
        `Opt out explicitly — pick one:\n` +
        `  - per-invocation:  stamp merge ${args.source} --into ${args.target} --yes\n` +
        `  - per-shell:       STAMP_REQUIRE_HUMAN_MERGE=0 stamp merge ...\n` +
        `  - per-branch:      add 'require_human_merge: false' under ` +
        `branches.${args.target} in .stamp/config.yml (and merge that change ` +
        `through the normal review flow)\n\n` +
        `Background: stamp's threat model treats LLM-verdict-as-merge-` +
        `authorization as residual HIGH (audit H1). The default forces ` +
        `operator awareness; the env var / flag / config field are how ` +
        `you declare automated intent.`,
    );
  }

  const readLine = args._readLine ?? readLineSync;

  // AC#2: Show git diff --stat above the prompt when available.
  // Filenames + churn counts, not raw diff text — low injection risk;
  // still printed as plain text, never interpolated into a shell.
  if (args.diffStat && args.diffStat.trim()) {
    process.stdout.write(args.diffStat.trimEnd() + "\n");
  }

  // AC#3: strict mode — require the operator to type the exact phrase
  // `merge <source> -> <target>` rather than a bare y/N.
  if (args.branchRule.require_human_merge === "strict") {
    const expectedPhrase = `merge ${args.source} -> ${args.target}`;
    const prompt =
      `Sign + merge '${args.source}' (${args.head_sha.slice(0, 8)}) ` +
      `→ '${args.target}' (base ${args.base_sha.slice(0, 8)})?\n` +
      `Type "${expectedPhrase}" to confirm: `;
    process.stdout.write(prompt);
    const answer = readLine().trim();
    if (answer !== expectedPhrase) {
      throw new Error(
        `merge cancelled: strict confirmation required — expected ` +
          `"${expectedPhrase}" but got '${answer || "<empty>"}'. ` +
          `Merge ${args.source} → ${args.target} aborted.`,
      );
    }
    return;
  }

  // Standard y/N confirmation.
  // Show base→head SHAs so the operator confirms what's actually about
  // to be signed. The head_sha is the load-bearing one — a stale or
  // attacker-shifted source ref shows up here as a SHA the operator
  // doesn't recognise.
  const prompt =
    `Sign + merge '${args.source}' (${args.head_sha.slice(0, 8)}) ` +
    `→ '${args.target}' (base ${args.base_sha.slice(0, 8)})? [y/N] `;
  process.stdout.write(prompt);
  const answer = readLine().trim().toLowerCase();
  if (answer !== "y" && answer !== "yes") {
    throw new Error(
      `merge cancelled: operator answered '${answer || "<empty>"}' to the ` +
        `confirmation prompt for ${args.source} → ${args.target}.`,
    );
  }
}

/**
 * Read one line from stdin synchronously, byte-at-a-time until LF.
 * Synchronous because stamp merge's flow is otherwise sync; promoting
 * the whole call chain to async to use readline would touch every
 * caller for one prompt. The byte-loop is fine: human typing speed is
 * the bottleneck, not the syscall rate.
 *
 * Stops on LF, EOF, or read error. Trailing CR is stripped (Windows
 * line endings on a TTY) so callers see plain "y" / "yes" / "" rather
 * than "y\r" / "yes\r" / "\r".
 */
export function readLineSync(): string {
  const buf = Buffer.alloc(1);
  let out = "";
  const fd = 0;
  for (;;) {
    let n: number;
    try {
      n = readSync(fd, buf, 0, 1, null);
    } catch {
      break;
    }
    if (n === 0) break;
    const ch = buf.toString("utf8", 0, 1);
    if (ch === "\n") break;
    out += ch;
  }
  if (out.endsWith("\r")) out = out.slice(0, -1);
  return out;
}
