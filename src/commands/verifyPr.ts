/**
 * `stamp verify-pr <head> --base <base> --into <branch>`
 *
 * Consumer side of PR-check mode. Verifies that the diff `base..head` has
 * a valid stamp attestation under `refs/stamp/attestations/<patch-id>`.
 * Wraps the same primitives that `stamp/verify-attestation@v1` (the GH
 * Action) calls into, so operators can run the exact verification path
 * locally as `stamp/verify-attestation` would on a PR.
 *
 * Verification steps (in this order — signature first so payload
 * fields are only acted on after the crypto says "trust this"):
 *   1. Resolve <head> + <base> to SHAs.
 *   2. Compute patch-id of base..head.
 *   3. Read refs/stamp/attestations/<patch-id> — fail if missing.
 *   4. Validate envelope shape (parser already bounded by 64 KiB cap).
 *   5. Read .stamp/trusted-keys/ at base; find the .pub whose
 *      fingerprint matches attestation.signer_key_id.
 *   6. Verify Ed25519 signature over serializePayload(payload). After
 *      this point all payload fields are trusted (signature covers
 *      the canonical JSON, including target_branch and approvals).
 *   7. Check attestation.target_branch equals the operator-supplied
 *      --into. The signature already guarantees the field wasn't
 *      tampered with; this check defends against re-using an
 *      attestation signed for a relaxed branch rule against a
 *      stricter branch.
 *   8. Read .stamp/config.yml at base; find branch rule for --into.
 *   9. Check every rule.required reviewer has an "approved" entry in
 *      attestation.approvals.
 *  10. If rule.strict_base is true: attestation.target_branch_tip_sha
 *      must equal the current tip of --into (resolved live via
 *      `git rev-parse <branch>`, NOT --base). Default (undefined/false)
 *      is loose — patch-id match alone is sufficient regardless of how
 *      far main has advanced since the reviewer signed.
 *
 * Exits 0 on success, 1 on any verification failure. Prints a
 * structured summary either way; a CI consumer can fail the check
 * purely on exit code without parsing prose.
 */

import { spawnSync } from "node:child_process";
import { findBranchRule, parseConfigFromYaml } from "../lib/config.js";
import { resolveDiff, runGit, showAtRef } from "../lib/git.js";
import { fingerprintFromPem } from "../lib/keys.js";
import { findRepoRoot } from "../lib/paths.js";
import { patchIdForSpan } from "../lib/patchId.js";
import {
  readAttestationRef,
  serializePayload,
} from "../lib/prAttestation.js";
import { verifyBytes } from "../lib/signing.js";

export interface VerifyPrOptions {
  /** Head ref (commit SHA, branch name, or any rev-parse-able value). */
  head: string;
  /** Base ref. Same shape as head. */
  base: string;
  /** Branch the PR will merge into. The attestation's recorded
   *  `target_branch` must equal this — guards against an attestation
   *  signed for a relaxed branch rule being verified against a stricter
   *  branch's rules. Named `into` to match `stamp merge --into` and
   *  `stamp attest --into`. */
  into: string;
  /** Repo root override; defaults to cwd. */
  repoPath?: string;
}

export function runVerifyPr(opts: VerifyPrOptions): void {
  const repoRoot = opts.repoPath ?? findRepoRoot();

  // resolveDiff insists on a "<base>..<head>" form, which we reconstruct.
  const resolved = resolveDiff(`${opts.base}..${opts.head}`, repoRoot);
  const patch_id = patchIdForSpan(resolved.base_sha, resolved.head_sha, repoRoot);

  const envelope = readAttestationRef(patch_id, repoRoot);
  if (!envelope) {
    fail(
      `no attestation found at refs/stamp/attestations/${patch_id} ` +
        `(diff ${resolved.base_sha.slice(0, 8)}..${resolved.head_sha.slice(0, 8)}). ` +
        `Operator must run \`stamp attest --into ${opts.into}\` and push the ` +
        `attestation ref to this remote.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  const { payload, signature } = envelope;

  // Source the trust set from the BASE tree, never HEAD. Same v3
  // boundary as stamp merge / stamp attest: a feature branch cannot
  // edit its own trusted-keys and have those edits affect its own
  // verification. The signer_key_id field is used as a hint to pick
  // which trusted key to try; even if forged, a wrong-key attempt
  // fails the signature step below — the field is not load-bearing
  // for trust, just for routing.
  const trustedKey = findTrustedKeyAtBase(
    resolved.base_sha,
    payload.signer_key_id,
    repoRoot,
  );
  if (!trustedKey) {
    fail(
      `signer_key_id ${payload.signer_key_id} is not in .stamp/trusted-keys/ ` +
        `at base ${resolved.base_sha.slice(0, 8)}. The reviewer's signing key ` +
        `must be added to this repo's trust set via \`stamp trust grant\` and ` +
        `landed through the standard stamp gate before their attestations verify.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Verify the signature BEFORE acting on any payload field. Crypto
  // first, then trust the contents. The signature covers the canonical
  // JSON of payload (which includes target_branch and approvals), so
  // any tampering with those fields after signing fails this check.
  const sigOk = verifyBytes(
    trustedKey.pem,
    serializePayload(payload),
    signature,
  );
  if (!sigOk) {
    fail(
      `signature verification failed against ${trustedKey.filename} ` +
        `(${payload.signer_key_id}). Either the attestation has been tampered ` +
        `with after signing, or the trusted-keys entry doesn't match the key ` +
        `that signed.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // From here on the payload is trusted. Check target_branch matches
  // the verifier's --into so an attestation signed for a relaxed
  // branch rule can't be used to merge into a stricter branch.
  if (payload.target_branch !== opts.into) {
    fail(
      `attestation target_branch="${payload.target_branch}" does not match ` +
        `verifier --into="${opts.into}". The reviewer signed an attestation ` +
        `for a different merge destination — re-attest with --into ${opts.into}.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  let configYaml: string;
  try {
    configYaml = showAtRef(resolved.base_sha, ".stamp/config.yml", repoRoot);
  } catch (e) {
    fail(
      `could not read .stamp/config.yml at base ${resolved.base_sha.slice(0, 8)}: ` +
        `${(e as Error).message}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const config = parseConfigFromYaml(configYaml);
  const rule = findBranchRule(config.branches, opts.into);
  if (!rule) {
    fail(
      `no branch rule for "${opts.into}" in .stamp/config.yml at base ` +
        `${resolved.base_sha.slice(0, 8)}. Configured branches: ` +
        `${Object.keys(config.branches).join(", ") || "(none)"}.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Gate check: every required reviewer must have an `approved` entry.
  const approvalByReviewer = new Map(
    payload.approvals.map((a) => [a.reviewer, a.verdict]),
  );
  const missing: string[] = [];
  for (const r of rule.required) {
    if (approvalByReviewer.get(r) !== "approved") missing.push(r);
  }
  if (missing.length > 0) {
    fail(
      `gate CLOSED: missing approved verdicts for: ${missing.join(", ")}. ` +
        `Attestation has approvals for: ` +
        `${payload.approvals.map((a) => `${a.reviewer}=${a.verdict}`).join(", ")}.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Strict-base check (opt-in). When the rule sets strict_base:true,
  // the TIP of the target branch must be the same as it was at attest
  // time. Any advancement of main between attest and verify invalidates,
  // even when the cumulative diff content is unchanged (in which case
  // patch-id and merge-base both still agree, so loose mode would
  // accept). Comparing tips (`target_branch_tip_sha`) — not
  // merge-bases (`base_sha`) — is what catches "main moved with
  // unrelated commits."
  if (rule.strict_base) {
    if (!payload.target_branch_tip_sha) {
      // v1 envelope: doesn't carry the tip SHA, can't verify strict_base.
      // Don't silently accept (would be a strict-mode bypass); don't
      // silently fail with "no attestation found" prose (confusing).
      // Refuse with a specific schema-error so the operator knows to
      // re-attest with a newer stamp release.
      fail(
        `strict_base check failed: attestation schema v${payload.schema_version} ` +
          `predates target_branch_tip_sha (v2+). Re-attest with stamp ≥ 1.6.0 ` +
          `to verify under strict_base; or relax the branch rule.`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
    // Resolve the LIVE tip of the target branch (opts.into), not
    // opts.base. They coincide in the GH Action where opts.base ==
    // current tip of opts.into at event-fire time, but diverge when
    // a local caller passes a non-tip SHA as --base. Using opts.into
    // makes the "did main advance since attest?" check semantically
    // correct in both contexts.
    const currentTip = runGit(
      ["rev-parse", `${opts.into}^{commit}`],
      repoRoot,
    ).trim();
    if (payload.target_branch_tip_sha !== currentTip) {
      fail(
        `strict_base check failed: attestation was signed when ${opts.into} ` +
          `was at ${payload.target_branch_tip_sha.slice(0, 8)}, but ${opts.into} ` +
          `is now at ${currentTip.slice(0, 8)}. Re-attest with the current tip.`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
  }

  printSuccess({
    patch_id,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    target_branch: opts.into,
    signer_key_id: payload.signer_key_id,
    trusted_key_filename: trustedKey.filename,
    approvals: payload.approvals.map((a) => ({
      reviewer: a.reviewer,
      verdict: a.verdict,
    })),
    strict_base: rule.strict_base ?? false,
  });
}

interface TrustedKeyHit {
  filename: string;
  pem: string;
}

/**
 * Walk `.stamp/trusted-keys/*.pub` at the given base SHA via git
 * (no filesystem access — the verifier runs in a CI checkout where
 * the working tree may not be the base ref) and return the .pub whose
 * Ed25519 fingerprint matches `signer_key_id`. Returns null when no
 * file in the directory matches; callers convert that to a verdict.
 */
function findTrustedKeyAtBase(
  base_sha: string,
  signer_key_id: string,
  repoRoot: string,
): TrustedKeyHit | null {
  // ls-tree to enumerate the directory at this revision. Output format
  // is "<mode> <type> <object> <path>" tab-separated; we only need the
  // path. -r recurses; --name-only returns just the path.
  const lsTree = spawnSync(
    "git",
    [
      "ls-tree",
      "--name-only",
      "-r",
      base_sha,
      ".stamp/trusted-keys/",
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (lsTree.status !== 0) {
    // Directory genuinely missing or some other ls-tree error — treat
    // as "no trust set at this base." Caller will fail with a clear
    // error attributing it to the trust set, not git plumbing.
    return null;
  }
  const files = (lsTree.stdout ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.endsWith(".pub"));

  for (const file of files) {
    let pem: string;
    try {
      pem = runGit(["show", `${base_sha}:${file}`], repoRoot);
    } catch {
      continue;
    }
    let fp: string;
    try {
      fp = fingerprintFromPem(pem);
    } catch {
      continue;
    }
    if (fp === signer_key_id) {
      return { filename: file.replace(/^\.stamp\/trusted-keys\//, ""), pem };
    }
  }
  return null;
}

interface SuccessSummary {
  patch_id: string;
  base_sha: string;
  head_sha: string;
  target_branch: string;
  signer_key_id: string;
  trusted_key_filename: string;
  approvals: Array<{ reviewer: string; verdict: string }>;
  strict_base: boolean;
}

function printSuccess(s: SuccessSummary): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(
    `target: ${s.target_branch}   base: ${s.base_sha.slice(0, 8)} → head: ${s.head_sha.slice(0, 8)}`,
  );
  console.log(bar);
  console.log(`  patch-id:        ${s.patch_id}`);
  console.log(`  signer:          ${s.signer_key_id}`);
  console.log(`  trusted-key:     .stamp/trusted-keys/${s.trusted_key_filename}`);
  console.log(`  base mode:       ${s.strict_base ? "strict" : "loose"}`);
  for (const a of s.approvals) {
    const mark = a.verdict === "approved" ? "✓" : "✗";
    console.log(`  ${mark}  ${a.reviewer.padEnd(16)} ${a.verdict}`);
  }
  console.log(bar);
  console.log("result: VERIFIED");
  console.log(bar);
}

/**
 * Print a structured failure summary and exit 1. CI consumers can rely
 * on the exit code; the prose is for the operator looking at the
 * action's logs. The `error:` prefix on the cause line matches the
 * stderr-prefix convention used elsewhere in the CLI; agents that
 * grep stderr for `^error:` get the failure cause cleanly.
 */
function fail(
  reason: string,
  patch_id: string,
  base_sha: string,
  head_sha: string,
): never {
  const bar = "─".repeat(72);
  console.error(bar);
  console.error(`base: ${base_sha.slice(0, 8)} → head: ${head_sha.slice(0, 8)}`);
  console.error(`patch-id: ${patch_id}`);
  console.error(bar);
  console.error(`error: ${reason}`);
  console.error("result: FAILED");
  console.error(bar);
  process.exit(1);
}
