import { existsSync } from "node:fs";
import {
  parseCommitAttestation,
  type AttestationPayload,
} from "../lib/attestation.js";
import { loadConfig } from "../lib/config.js";
import {
  latestReviews,
  openDb,
  reviewHistory,
  type ReviewRow,
} from "../lib/db.js";
import {
  commitMessage,
  currentBranch,
  firstParentCommits,
  resolveDiff,
  type CommitSummary,
} from "../lib/git.js";
import { findTrustedKey } from "../lib/keys.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";
import { verifyBytes } from "../lib/signing.js";

export interface LogOptions {
  limit: number;
  /** Show raw review DB rows instead of commits (legacy / deep-debug view). */
  reviews: boolean;
  /** Branch or ref to view; defaults to current branch. */
  branch?: string;
  /** If set, filter DB-reviews view to a specific diff. Ignored outside --reviews. */
  diff?: string;
  /** If set, show one-commit detail instead of the list. Positional arg. */
  sha?: string;
}

/**
 * stamp log
 *
 * Default: a summary of merges on the current branch's first-parent history,
 * each line showing the attestation state (signer, reviewers, checks).
 *
 * `<sha>`: full drill-down on one commit — decoded attestation, review
 * prose from DB if available, signature status.
 *
 * `--reviews`: legacy view — every row in the reviews table, chronological.
 *   Useful when you want to see review iterations that never made it to a
 *   merge, or to debug the DB directly.
 */
export function runLog(opts: LogOptions): void {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  if (!existsSync(configPath)) {
    throw new Error(
      `no .stamp/config.yml at ${configPath}. Run \`stamp init\` first.`,
    );
  }

  if (opts.sha) {
    printCommitDetail(opts.sha, repoRoot);
    return;
  }

  if (opts.reviews) {
    printReviewHistory(repoRoot, opts.limit, opts.diff);
    return;
  }

  const branch = opts.branch ?? currentBranch(repoRoot);
  printCommitList(repoRoot, branch, opts.limit);
}

// ---------- default: commit list with attestation summaries ----------

function printCommitList(
  repoRoot: string,
  branch: string,
  limit: number,
): void {
  const commits = firstParentCommits(branch, limit, repoRoot);
  if (commits.length === 0) {
    console.log(`no commits on ${branch}`);
    return;
  }

  const bar = "─".repeat(78);
  console.log(bar);
  console.log(`commits on ${branch} (first-parent, last ${commits.length})`);
  console.log(bar);

  for (const c of commits) {
    const parsed = parseCommitAttestation(c.body);
    const shortSha = c.sha.slice(0, 10);
    if (!parsed) {
      console.log(`  ${shortSha}  [unstamped]  ${c.title}`);
      continue;
    }
    const { payload } = parsed;
    const signer = payload.signer_key_id.replace(/^sha256:/, "").slice(0, 8);
    const approvals = payload.approvals.map((a) => {
      const mark = a.verdict === "approved" ? "✓" : "✗";
      return `${mark}${a.reviewer}`;
    }).join(" ");
    const checks = (payload.checks ?? []).map((c) => {
      const mark = c.exit_code === 0 ? "✓" : "✗";
      return `${mark}${c.name}`;
    }).join(" ");
    const checksLabel = checks ? `  checks[${checks}]` : "";
    console.log(
      `  ${shortSha}  signer=${signer}  reviewers[${approvals}]${checksLabel}`,
    );
    console.log(`             ${c.title}`);
  }
  console.log(bar);
  console.log(
    `tip: \`stamp log <sha>\` for full detail on one commit; \`stamp log --reviews\` for the DB review history.`,
  );
}

// ---------- single-commit detail ----------

function printCommitDetail(sha: string, repoRoot: string): void {
  const message = commitMessage(sha, repoRoot);
  const firstLine = message.split("\n")[0] ?? "";
  const parsed = parseCommitAttestation(message);

  const bar = "─".repeat(78);
  console.log(bar);
  console.log(`commit: ${sha}`);
  console.log(`title:  ${firstLine}`);
  console.log(bar);

  if (!parsed) {
    console.log("\n(no Stamp-Payload trailer — commit is unstamped)\n");
    return;
  }

  const { payload, payloadBytes, signatureBase64 } = parsed;

  console.log(`target branch:  ${payload.target_branch}`);
  console.log(`base → head:    ${payload.base_sha.slice(0, 12)} → ${payload.head_sha.slice(0, 12)}`);
  console.log(`signer:         ${payload.signer_key_id}`);

  // Signature + trust check
  const trustedPem = findTrustedKey(repoRoot, payload.signer_key_id);
  if (!trustedPem) {
    console.log(`signature:      ✗ signer key not in .stamp/trusted-keys/`);
  } else {
    let valid = false;
    try {
      valid = verifyBytes(trustedPem, payloadBytes, signatureBase64);
    } catch {
      valid = false;
    }
    console.log(`signature:      ${valid ? "✓ valid" : "✗ INVALID"}`);
  }

  console.log(bar);
  console.log("approvals:");
  for (const a of payload.approvals) {
    const mark = a.verdict === "approved" ? "✓" : "✗";
    console.log(`  ${mark} ${a.reviewer.padEnd(16)} ${a.verdict}`);
  }

  if (payload.checks && payload.checks.length > 0) {
    console.log(bar);
    console.log("checks:");
    for (const c of payload.checks) {
      const mark = c.exit_code === 0 ? "✓" : "✗";
      console.log(
        `  ${mark} ${c.name.padEnd(16)} \`${c.command}\`   exit=${c.exit_code}`,
      );
    }
  }

  // Review prose from DB, if available
  const prose = collectReviewProse(repoRoot, payload);
  if (prose.length > 0) {
    for (const p of prose) {
      console.log(bar);
      console.log(`review — ${p.reviewer}  (${p.verdict})`);
      console.log(bar);
      console.log(p.issues ?? "(no prose recorded)");
    }
  } else {
    console.log(bar);
    console.log(
      "(no matching review rows in local DB — prose unavailable. Reviews " +
        "live in .git/stamp/state.db per-machine; prose for commits made on " +
        "a different machine won't be here.)",
    );
  }

  console.log(bar);
}

function collectReviewProse(
  repoRoot: string,
  payload: AttestationPayload,
): ReviewRow[] {
  const dbPath = stampStateDbPath(repoRoot);
  if (!existsSync(dbPath)) return [];
  const db = openDb(dbPath);
  try {
    const rows = latestReviews(db, payload.base_sha, payload.head_sha);
    // Only return rows whose reviewer matches one in the attestation.
    const approvedReviewers = new Set(payload.approvals.map((a) => a.reviewer));
    return rows.filter((r) => approvedReviewers.has(r.reviewer)) as ReviewRow[];
  } finally {
    db.close();
  }
}


// ---------- legacy --reviews view: raw DB rows ----------

function printReviewHistory(
  repoRoot: string,
  limit: number,
  diff?: string,
): void {
  const configPath = stampConfigFile(repoRoot);
  // loadConfig isn't strictly needed here but kept for the side effect of
  // surfacing a helpful "run stamp init" error.
  loadConfig(configPath);

  const dbPath = stampStateDbPath(repoRoot);
  if (!existsSync(dbPath)) {
    console.log("No reviews recorded yet.");
    return;
  }

  const db = openDb(dbPath);
  let rows: ReviewRow[];
  try {
    if (diff) {
      const resolved = resolveDiff(diff, repoRoot);
      rows = reviewHistory(db, { limit }).filter(
        (r) =>
          r.base_sha === resolved.base_sha && r.head_sha === resolved.head_sha,
      );
    } else {
      rows = reviewHistory(db, { limit });
    }
  } finally {
    db.close();
  }

  if (rows.length === 0) {
    console.log(diff ? `No reviews for ${diff}.` : "No reviews yet.");
    return;
  }

  const bar = "─".repeat(78);
  for (const row of rows) {
    const mark =
      row.verdict === "approved"
        ? "✓"
        : row.verdict === "changes_requested"
          ? "⟳"
          : "✗";
    console.log(bar);
    console.log(
      `#${row.id}  ${mark} ${row.reviewer.padEnd(16)} ${row.verdict.padEnd(18)} ` +
        `${row.base_sha.slice(0, 8)} → ${row.head_sha.slice(0, 8)}   ${row.created_at}`,
    );
    if (row.issues) {
      console.log(bar);
      console.log(row.issues);
    }
  }
  console.log(bar);
  console.log(
    `${rows.length} review${rows.length === 1 ? "" : "s"} shown` +
      (diff ? ` for ${diff}` : ""),
  );
}

// Ensure commits whose title is visibly different from body doesn't cause
// the formatter to produce redundant lines. Intentionally unused helper.
export function _normalizeTitle(c: CommitSummary): string {
  return c.title;
}
