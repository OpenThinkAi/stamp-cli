/**
 * `stamp admin sign --pending [<sha>]` — trust-anchor multi-sig
 * collection flow (AGT-337).
 *
 * Two modes, dispatched on whether a SHA is provided:
 *
 *   - **List mode** (`stamp admin sign --pending`): enumerate recent
 *     commits that touch `.stamp/**`, show each one's sig count vs.
 *     the path-rule's `minimum_signatures`, and point operators at
 *     the sign-mode invocation. Bounded by `LIST_MODE_HORIZON` (last
 *     N first-parent commits ahead of `origin/<target>` if available,
 *     else last N commits on HEAD).
 *
 *   - **Sign mode** (`stamp admin sign --pending <sha>`): validate
 *     that the commit (a) touches a `.stamp/**` path matched by some
 *     `path_rules` entry, (b) hasn't already been signed by the caller,
 *     (c) caller's local stamp key has `admin` capability per the
 *     manifest at the commit's base. Build the v4 trust-anchor signing
 *     target (shared with `stamp merge` via
 *     `src/lib/trustAnchorPayload.ts`), sign over its canonical bytes,
 *     append to the notes-ref keyed by the commit SHA.
 *
 * Storage and signing-target rationale lives in
 * `src/lib/trustAnchorNotes.ts` and `src/lib/trustAnchorPayload.ts` —
 * read those module docstrings before changing anything wire-affecting
 * here.
 */

import { execFileSync, spawnSync } from "node:child_process";
import {
  canonicalSerializeApproval,
  CURRENT_V4_SCHEMA_VERSION,
  type ApprovalEntryV4,
  type ApprovalV4,
} from "../lib/attestationV4.js";
import { findBranchRule, parseConfigFromYaml } from "../lib/config.js";
import { openDb, serverApprovalsFor } from "../lib/db.js";
import {
  listFilesAtRef,
  showAtRef,
} from "../lib/git.js";
import { ensureUserKeypair } from "../lib/keys.js";
import {
  findRepoRoot,
  stampStateDbPath,
} from "../lib/paths.js";
import { parsePathRules } from "../hooks/pre-receive.js";
import { PR_ATTESTATION_SCHEMA_VERSION } from "../lib/prAttestation.js";
import { signBytes, verifyBytes } from "../lib/signing.js";
import { buildPubkeyMap } from "../lib/sshReviewClient.js";
import {
  parseManifest,
  resolveCapability,
  snapshotSha256,
  type TrustedKeysManifest,
} from "../lib/trustedKeysManifest.js";
import {
  diffSha256Hex,
  trustAnchorSigningBytes,
} from "../lib/trustAnchorPayload.js";
import {
  commitExists,
  emptyNote,
  firstParent,
  listChangedFiles,
  noteWithAppendedSignature,
  readNote,
  resolveCommitSha,
  TRUST_ANCHOR_NOTES_REF,
  type TrustAnchorNote,
  writeNote,
} from "../lib/trustAnchorNotes.js";
import { parse as parseYaml } from "yaml";

/** Per-pattern entry needed for sign-time validation. Mirrors the
 *  shape `parsePathRules` produces, kept here local to the command. */
interface PathRuleLite {
  pattern: string;
  require_capability: string;
  minimum_signatures: number;
  bypass_review_cycle: boolean;
}

export interface AdminSignOptions {
  /** Commit to sign (or undefined for list mode). */
  pending?: string;
  /** Override the target branch (defaults to the rule's branch from
   *  config, or `main` when ambiguous). Used only for sign-mode payload
   *  prediction; the verifier reads target_branch from the commit's
   *  v4 envelope at merge time and doesn't consult this. */
  targetBranch?: string;
  /** Override the predicted operator fingerprint (the `signer_key_id`
   *  baked into the signing target). Default = the caller's local
   *  stamp key. In a `minimum_signatures: 2` workflow where one admin
   *  signs but a DIFFERENT admin will run `stamp merge`, the
   *  non-operator admin MUST pass this flag with the eventual
   *  operator's fingerprint — otherwise their signature will sign
   *  bytes that diverge from what `stamp merge` re-derives, and the
   *  gate will fail with "0 verifying signatures" at merge time. This
   *  is the operational coordination point the multi-admin flow turns
   *  on; surface it loudly. */
  signerKeyId?: string;
  /** Envelope mode the produced signature must satisfy. `auto`
   *  (default) inspects `.stamp/config.yml` at base_sha and picks `pr`
   *  iff the matching branch rule has `review_server` set, otherwise
   *  `v4`. Explicit `pr` / `v4` force the choice for debugging or
   *  staged migrations. The PR (`schema_version: 3`) and v4 trailer
   *  (`schema_version: 5`) verifiers reconstruct the admin-signing
   *  target with their OWN envelope's `schema_version` baked in, so an
   *  admin signature produced for one mode will not verify in the
   *  other — getting this right at producer-time is required for the
   *  Shape 4 (PR-mode) flow. See `src/lib/trustAnchorPayload.ts`'s
   *  `schemaVersion` field for the two-axes rationale. */
  mode?: "auto" | "pr" | "v4";
  /** When true, list mode emits machine-readable JSON instead of the
   *  human table. */
  json?: boolean;
}

/** Resolved envelope-mode value: the wire-format the admin signature
 *  will be verified against. Single integer space (`pr` ↔ schema 3,
 *  `v4` ↔ schema 5) per `trustAnchorPayload.ts`. */
type ResolvedMode = "pr" | "v4";

/** Default horizon for list mode. Bounded so a repo with millions of
 *  commits doesn't pay an unbounded `git log` cost. 100 is comfortable
 *  for any realistic in-flight admin-change set; the operator can
 *  always sign a specific SHA outside the horizon explicitly. */
const LIST_MODE_HORIZON = 100;

/** Path-glob → regex (same semantics as the verifier's
 *  `pathGlobToRegex`). Local copy: the verifier's helper is private to
 *  `src/hooks/pre-receive.ts` and we don't want to leak it from there;
 *  duplicating the small function is cheaper than restructuring the
 *  hook for export when the surface might shift in M4 follow-ups. */
function pathGlobToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const DOUBLE = "\x00DOUBLESTAR\x00";
  const SINGLE = "\x00SINGLESTAR\x00";
  const QMARK = "\x00QMARK\x00";
  const translated = escaped
    .replace(/\*\*/g, DOUBLE)
    .replace(/\*/g, SINGLE)
    .replace(/\?/g, QMARK)
    .replace(new RegExp(DOUBLE, "g"), ".*")
    .replace(new RegExp(SINGLE, "g"), "[^/]*")
    .replace(new RegExp(QMARK, "g"), "[^/]");
  return new RegExp(`^${translated}$`);
}

function pathMatchesAny(filePath: string, patterns: string[]): boolean {
  for (const p of patterns) {
    if (pathGlobToRegex(p).test(filePath)) return true;
  }
  return false;
}

/** Entry point used by `src/index.ts`. Dispatches on `pending`. */
export function runAdminSign(opts: AdminSignOptions): void {
  const repoRoot = findRepoRoot();
  if (opts.pending === undefined || opts.pending === "") {
    listPending(repoRoot, opts);
    return;
  }
  signPending(repoRoot, opts.pending, opts);
}

// ─── List mode ─────────────────────────────────────────────────────

interface PendingRow {
  sha: string;
  short_sha: string;
  base_sha: string;
  subject: string;
  touched_paths: string[];
  /** Path-rules patterns the diff matches. Empty when the commit
   *  doesn't actually need any admin sigs (the operator might be on a
   *  pre-path_rules repo or have signed something that doesn't touch
   *  a gated path). */
  matched_rules: PathRuleLite[];
  signatures_present: number;
  /** Maximum `minimum_signatures` across matched rules. The gate is
   *  per-rule but UX summarizes to the binding count. */
  signatures_required: number;
  /** True when at least one matched rule still needs more sigs. */
  awaiting: boolean;
}

function listPending(repoRoot: string, opts: AdminSignOptions): void {
  const candidates = recentCommitsToScan(repoRoot, opts.targetBranch);
  const rows: PendingRow[] = [];

  for (const c of candidates) {
    const baseSha = firstParent(repoRoot, c.sha);
    if (!baseSha) continue; // root commit; can't compute a base diff
    const changed = listChangedFiles(repoRoot, baseSha, c.sha) ?? [];
    if (changed.length === 0) continue;

    const rules = readPathRulesAtRef(repoRoot, baseSha);
    if (rules.length === 0) continue;

    const matched: PathRuleLite[] = [];
    const touched = new Set<string>();
    for (const rule of rules) {
      const hits = changed.filter((f) => pathMatchesAny(f, [rule.pattern]));
      if (hits.length === 0) continue;
      matched.push(rule);
      for (const h of hits) touched.add(h);
    }
    if (matched.length === 0) continue;

    const note = readNote(repoRoot, c.sha);
    const present = note?.signatures.length ?? 0;
    const required = matched.reduce(
      (max, r) => Math.max(max, r.minimum_signatures),
      0,
    );

    rows.push({
      sha: c.sha,
      short_sha: c.sha.slice(0, 12),
      base_sha: baseSha,
      subject: c.subject,
      touched_paths: [...touched].sort(),
      matched_rules: matched,
      signatures_present: present,
      signatures_required: required,
      awaiting: present < required,
    });
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
    return;
  }

  if (rows.length === 0) {
    console.log("no pending .stamp/** commits awaiting admin counter-signature.");
    console.log(`scanned the last ${LIST_MODE_HORIZON} commits on HEAD.`);
    return;
  }

  const awaitingRows = rows.filter((r) => r.awaiting);
  const metRows = rows.filter((r) => !r.awaiting);

  const bar = "─".repeat(72);
  if (awaitingRows.length > 0) {
    console.log(bar);
    console.log(
      `pending .stamp/** commits — ${awaitingRows.length} awaiting counter-signature`,
    );
    console.log(bar);
    for (const r of awaitingRows) {
      console.log(
        `  ${r.short_sha}  ${r.signatures_present}/${r.signatures_required}  ${r.subject}`,
      );
      const sample = r.touched_paths.slice(0, 3).join(", ");
      const more =
        r.touched_paths.length > 3 ? ` (+${r.touched_paths.length - 3} more)` : "";
      console.log(`             ${sample}${more}`);
      console.log(`             stamp admin sign --pending ${r.short_sha}`);
    }
  }
  if (metRows.length > 0) {
    console.log(bar);
    console.log(`signature threshold already met — ${metRows.length} ready to merge`);
    console.log(bar);
    for (const r of metRows) {
      console.log(
        `  ${r.short_sha}  ${r.signatures_present}/${r.signatures_required}  ${r.subject}`,
      );
    }
  }
  if (awaitingRows.length === 0 && metRows.length === 0) {
    console.log("no pending .stamp/** commits found in the last horizon.");
  }
  console.log(bar);
  console.log(
    "tip: push the notes-ref so other admins see your signatures —",
  );
  console.log(`     git push origin ${TRUST_ANCHOR_NOTES_REF}`);
}

interface CandidateCommit {
  sha: string;
  subject: string;
}

/** Walk the last `LIST_MODE_HORIZON` first-parent commits on the
 *  current HEAD (or current branch). Prefers commits ahead of the
 *  configured upstream when one exists — those are the ones actually
 *  awaiting a counter-signature. */
function recentCommitsToScan(
  repoRoot: string,
  targetBranchHint: string | undefined,
): CandidateCommit[] {
  // Build the rev range. Prefer "ahead of upstream" when upstream is
  // configured; otherwise fall back to the last N first-parent commits
  // on HEAD.
  let range: string[];
  const upstream = resolveUpstream(repoRoot, targetBranchHint);
  if (upstream) {
    range = [`${upstream}..HEAD`];
  } else {
    range = [`HEAD`];
  }
  const result = spawnSync(
    "git",
    [
      "log",
      "--first-parent",
      `-${LIST_MODE_HORIZON}`,
      "--format=%H%x09%s",
      ...range,
    ],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 4 * 1024 * 1024 },
  );
  if (result.status !== 0) return [];
  const text = result.stdout?.toString("utf8") ?? "";
  const out: CandidateCommit[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    out.push({ sha: line.slice(0, tab), subject: line.slice(tab + 1) });
  }
  return out;
}

/** Resolve the configured upstream (e.g. `origin/main`) for the given
 *  branch hint, or null if none is configured. */
function resolveUpstream(
  repoRoot: string,
  targetBranchHint: string | undefined,
): string | null {
  const candidate = targetBranchHint ?? "HEAD";
  const result = spawnSync(
    "git",
    ["rev-parse", "--abbrev-ref", "--symbolic-full-name", `${candidate}@{upstream}`],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  if (result.status !== 0) return null;
  const text = result.stdout?.toString("utf8").trim() ?? "";
  return text || null;
}

// ─── Sign mode ─────────────────────────────────────────────────────

function signPending(
  repoRoot: string,
  rawSha: string,
  opts: AdminSignOptions,
): void {
  if (!commitExists(repoRoot, rawSha)) {
    throw new Error(
      `commit ${JSON.stringify(rawSha)} not found in this repo. Fetch from origin or pass a SHA that resolves locally.`,
    );
  }
  const headSha = resolveCommitSha(repoRoot, rawSha);
  const baseSha = firstParent(repoRoot, headSha);
  if (!baseSha) {
    throw new Error(
      `commit ${headSha.slice(0, 8)} has no first parent — admin sign requires a commit with a base to diff against.`,
    );
  }

  // Validate (1): commit touches at least one .stamp/** path matched
  // by a path_rules entry at the base.
  const changed = listChangedFiles(repoRoot, baseSha, headSha) ?? [];
  if (changed.length === 0) {
    throw new Error(
      `commit ${headSha.slice(0, 8)} has no files changed against base ${baseSha.slice(0, 8)} — nothing to gate.`,
    );
  }

  const pathRules = readPathRulesAtRef(repoRoot, baseSha);
  if (pathRules.length === 0) {
    throw new Error(
      `no path_rules configured at base ${baseSha.slice(0, 8)} in .stamp/config.yml. ` +
        `stamp admin sign is only meaningful when path_rules gate trust-anchor changes — ` +
        `nothing to sign here. (If you intend to require multi-sig on .stamp/**, add a path_rules entry first.)`,
    );
  }

  const matchedRule = matchAnyRule(pathRules, changed);
  if (!matchedRule) {
    const samplePaths = changed.slice(0, 5).join(", ");
    const morePaths = changed.length > 5 ? `, +${changed.length - 5} more` : "";
    throw new Error(
      `commit ${headSha.slice(0, 8)} doesn't touch any path matched by path_rules at base ${baseSha.slice(0, 8)}. ` +
        `Changed paths: ${samplePaths}${morePaths}. ` +
        `Configured patterns: ${pathRules.map((r) => `"${r.pattern}"`).join(", ")}. ` +
        `No admin signature is required for this commit — merge through the normal stamp flow.`,
    );
  }

  // Validate (3): caller has the required capability per the manifest
  // at base_sha (decision #5: lenient revocation — admin capability
  // resolved at base_sha, matching the verifier).
  const { keypair } = ensureUserKeypair();
  const callerFingerprint = keypair.fingerprint;

  const manifest = readManifestAtRef(repoRoot, baseSha);
  if (!manifest) {
    throw new Error(
      `no readable .stamp/trusted-keys/manifest.yml at base ${baseSha.slice(0, 8)}. ` +
        `Add the manifest with capabilities for your admin keys before counter-signing.`,
    );
  }
  const callerCaps = resolveCapability(manifest, callerFingerprint);
  if (callerCaps === null) {
    throw new Error(
      `your local stamp key (${callerFingerprint}) isn't listed in .stamp/trusted-keys/manifest.yml at base ${baseSha.slice(0, 8)}. ` +
        `Add your key with capabilities: [${matchedRule.require_capability}] to the manifest and merge that change before counter-signing.`,
    );
  }
  if (!callerCaps.includes(matchedRule.require_capability as (typeof callerCaps)[number])) {
    throw new Error(
      `your local stamp key (${callerFingerprint}) has capabilities [${callerCaps.join(", ")}] at base ${baseSha.slice(0, 8)}, ` +
        `but path_rules["${matchedRule.pattern}"] requires the '${matchedRule.require_capability}' capability. ` +
        `Update the manifest to add the missing capability for this key, or have a different admin sign.`,
    );
  }

  // Validate (2): caller hasn't already signed this commit. (Doing
  // this here AND in the note appender means we surface the no-op as a
  // clean message rather than a confusing "already present" deep in
  // git-notes.)
  const existingNote = readNote(repoRoot, headSha);
  if (existingNote) {
    for (const sig of existingNote.signatures) {
      if (sig.signer_key_id === callerFingerprint) {
        const present = existingNote.signatures.length;
        const required = matchedRule.minimum_signatures;
        console.log(
          `your key (${callerFingerprint.slice(0, 22)}…) has already signed ${headSha.slice(0, 12)}.`,
        );
        console.log(
          `current state: ${present}/${required} signatures (${
            present >= required ? "threshold met — ready to merge" : `still need ${required - present} more`
          }).`,
        );
        if (present < required) {
          console.log(
            "share the notes-ref with another admin:",
          );
          console.log(`  git push origin ${TRUST_ANCHOR_NOTES_REF}`);
        }
        return;
      }
    }
  }

  // Build the diff bytes the same way `stamp merge` does — via `git
  // diff base...head` — so the resulting diff_sha256 matches what
  // `buildV4Trailers` will compute. (We can't import `resolveDiff`
  // because it expects a revspec; reuse the underlying behavior.)
  const diffText = gitDiffBetween(repoRoot, baseSha, headSha);
  const diffSha256 = diffSha256Hex(diffText);

  // Load existing server-signed approvals so the predicted v4 payload
  // matches what merge will produce. If none are present, we sign with
  // `approvals: []` — operator must run `stamp review` between admin
  // signatures landing and `stamp merge`, but the sign-time signature
  // is invalidated by that. Surface this clearly.
  const approvals = loadServerApprovals(repoRoot, baseSha, headSha, manifest);

  if (approvals.length === 0) {
    process.stderr.write(
      `note: no server-signed approvals in the local DB for ${baseSha.slice(
        0,
        8,
      )}…${headSha.slice(0, 8)}. ` +
        `Signing now with approvals: []. If \`stamp review\` runs later, the operator running ` +
        `\`stamp merge\` will need to re-collect admin signatures because the v4 payload ` +
        `bytes will have shifted. Re-run admin sign AFTER \`stamp review\` populates server ` +
        `approvals for a stable signature.\n`,
    );
  }

  const targetBranch = opts.targetBranch ?? guessTargetBranch(repoRoot);

  // Predicted operator fingerprint for the eventual `stamp merge`.
  // Defaults to the caller's own key (the common case: one admin
  // signs and runs merge). For multi-admin workflows where a
  // different admin will run merge, callers MUST pass --signer-key-id
  // explicitly so every admin signs over identical bytes. Validate
  // the override looks like a fingerprint to catch typos before they
  // become merge-time "0 verifying signatures" surprises.
  let predictedSigner = callerFingerprint;
  if (opts.signerKeyId !== undefined) {
    if (!/^sha256:[0-9a-f]{64}$/.test(opts.signerKeyId)) {
      throw new Error(
        `--signer-key-id must be a fingerprint of the form \`sha256:<64-hex>\` (got ${JSON.stringify(opts.signerKeyId)}).`,
      );
    }
    predictedSigner = opts.signerKeyId;
  }

  // AGT-370: admin sigs commit to the manifest_snapshot_sha256 just
  // like the operator's outer signature does. Compute it the same way
  // `stamp merge` will at merge time so all signers produce identical
  // canonical bytes.
  const manifestSnapshotSha256 = snapshotSha256(manifest);

  // Resolve which envelope this signature will be verified against.
  // PR-mode (`schema_version: 3`) and v4 trailer (`schema_version: 5`)
  // sign different bytes for the same diff; the wrong choice surfaces
  // as "0 verifying signatures" at attest/merge time on someone else's
  // machine. `auto` reads the branch rule at base_sha and picks `pr`
  // iff `review_server` is set, mirroring `stamp attest`'s dispatch.
  const requestedMode: "auto" | "pr" | "v4" = opts.mode ?? "auto";
  const resolvedMode: ResolvedMode =
    requestedMode === "auto"
      ? detectEnvelopeModeAtBase(repoRoot, baseSha, targetBranch)
      : requestedMode;
  const schemaVersionForMode =
    resolvedMode === "pr" ? PR_ATTESTATION_SCHEMA_VERSION : undefined;

  const signingBytes = trustAnchorSigningBytes({
    baseSha,
    headSha,
    targetBranch,
    diffSha256,
    manifestSnapshotSha256,
    approvals,
    checks: [], // see trustAnchorPayload.ts "Operational caveat"
    signerKeyId: predictedSigner,
    ...(schemaVersionForMode !== undefined
      ? { schemaVersion: schemaVersionForMode }
      : {}),
  });

  const signatureB64 = signBytes(keypair.privateKeyPem, signingBytes);

  // Self-verify before persisting so a key/serialization bug surfaces
  // here rather than at `stamp merge` time on someone else's machine.
  const selfOk = verifyBytes(keypair.publicKeyPem, signingBytes, signatureB64);
  if (!selfOk) {
    throw new Error(
      `internal error: just-produced trust-anchor signature failed self-verification. ` +
        `Refusing to persist a bad note. File a bug at https://github.com/OpenThinkAi/stamp-cli/issues.`,
    );
  }

  const baseNote: TrustAnchorNote = existingNote ?? emptyNote({
    head_sha: headSha,
    base_sha: baseSha,
    diff_sha256: diffSha256,
    target_branch: targetBranch,
  });

  // If the existing note's bytes-binding metadata drifted from what
  // we just computed, the previous admin signed against a different
  // payload prediction. Surface this rather than silently appending —
  // the resulting note will have mutually-incompatible signatures and
  // merge time will fail without obvious blame.
  if (existingNote) {
    if (
      existingNote.base_sha !== baseSha ||
      existingNote.diff_sha256 !== diffSha256 ||
      existingNote.target_branch !== targetBranch
    ) {
      const fields: string[] = [];
      if (existingNote.base_sha !== baseSha) {
        fields.push(`base_sha (${existingNote.base_sha.slice(0, 8)} vs ${baseSha.slice(0, 8)})`);
      }
      if (existingNote.diff_sha256 !== diffSha256) {
        fields.push(
          `diff_sha256 (${existingNote.diff_sha256.slice(0, 12)}… vs ${diffSha256.slice(0, 12)}…)`,
        );
      }
      if (existingNote.target_branch !== targetBranch) {
        fields.push(`target_branch (${existingNote.target_branch} vs ${targetBranch})`);
      }
      throw new Error(
        `existing notes for ${headSha.slice(0, 8)} differ from this run on: ${fields.join(", ")}. ` +
          `A prior admin signed against a different prediction (likely the operator's identity ` +
          `or target_branch shifted). To proceed, delete the stale note and re-collect: ` +
          `\`git notes --ref=${TRUST_ANCHOR_NOTES_REF} remove ${headSha.slice(0, 8)}\` then re-sign.`,
      );
    }
  }

  const { note: updated, alreadyPresent } = noteWithAppendedSignature(baseNote, {
    signer_key_id: callerFingerprint,
    signature: signatureB64,
  });
  if (alreadyPresent) {
    // Should be unreachable — we checked above. Defense-in-depth.
    console.log(`your signature was already present on ${headSha.slice(0, 8)}; nothing to do.`);
    return;
  }

  writeNote(repoRoot, headSha, updated);

  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`signed pending .stamp/** commit ${headSha.slice(0, 12)}`);
  console.log(bar);
  console.log(`  signer:            ${callerFingerprint}`);
  console.log(`  base:              ${baseSha.slice(0, 12)}`);
  console.log(`  diff_sha256:       ${diffSha256.slice(0, 12)}…`);
  console.log(`  rule:              ${matchedRule.pattern} (require_capability=${matchedRule.require_capability})`);
  const resolvedSchemaVersion =
    resolvedMode === "pr" ? PR_ATTESTATION_SCHEMA_VERSION : CURRENT_V4_SCHEMA_VERSION;
  console.log(
    `  envelope mode:     ${resolvedMode}` +
      (requestedMode === "auto" ? " (auto-detected)" : " (--mode override)") +
      ` — schema_version ${resolvedSchemaVersion}`,
  );
  if (requestedMode === "auto" && resolvedMode === "pr") {
    console.log(
      `  note:              prior to WS1 this command always produced v4 signatures; auto-detect picked PR-mode here because the target branch rule has review_server set. Pass --mode v4 if you intend to use \`stamp merge\` on this repo.`,
    );
  }
  console.log(
    `  signatures:        ${updated.signatures.length}/${matchedRule.minimum_signatures}` +
      (updated.signatures.length >= matchedRule.minimum_signatures ? " — threshold met" : ""),
  );
  console.log(`  notes-ref:         ${TRUST_ANCHOR_NOTES_REF}`);
  console.log(bar);
  if (updated.signatures.length < matchedRule.minimum_signatures) {
    const need = matchedRule.minimum_signatures - updated.signatures.length;
    console.log(`Still need ${need} more admin signature${need === 1 ? "" : "s"}.`);
  } else {
    console.log("Threshold met — ready for `stamp merge`.");
  }
  console.log();
  console.log("Share the notes-ref with the other admin(s):");
  console.log(`  git push origin ${TRUST_ANCHOR_NOTES_REF}`);
}

// ─── Helpers ───────────────────────────────────────────────────────

/** Read path_rules at a given commit ref. Re-uses the verifier's
 *  `parsePathRules` so admin sign and the gate see identical rules. */
function readPathRulesAtRef(repoRoot: string, sha: string): PathRuleLite[] {
  let yaml: string;
  try {
    yaml = showAtRef(sha, ".stamp/config.yml", repoRoot);
  } catch {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(yaml);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];
  const raw = (parsed as { path_rules?: unknown }).path_rules;
  const { rules } = parsePathRules(raw);
  return rules.map((r) => ({
    pattern: r.pattern,
    require_capability: r.require_capability,
    minimum_signatures: r.minimum_signatures,
    bypass_review_cycle: r.bypass_review_cycle,
  }));
}

function matchAnyRule(
  rules: PathRuleLite[],
  changedFiles: string[],
): PathRuleLite | null {
  for (const rule of rules) {
    if (changedFiles.some((f) => pathMatchesAny(f, [rule.pattern]))) {
      return rule;
    }
  }
  return null;
}

function readManifestAtRef(
  repoRoot: string,
  sha: string,
): TrustedKeysManifest | null {
  let yaml: string;
  try {
    yaml = showAtRef(sha, ".stamp/trusted-keys/manifest.yml", repoRoot);
  } catch {
    return null;
  }
  return parseManifest(yaml);
}

/** Load server-signed approvals from the local DB, verify each
 *  Ed25519 signature against the manifest at base_sha, and assemble
 *  the same `ApprovalEntryV4[]` shape `buildV4Trailers` produces. We
 *  re-verify here rather than trusting DB columns alone — DB tampering
 *  could otherwise plant a row whose presence shifts the signed bytes
 *  in a way that makes admin signatures verify against bytes that
 *  later fail the pre-receive verifier. Defense-in-depth.
 *
 *  Returns `[]` when no rows exist OR when any row fails verification
 *  (and surfaces a stderr note in the latter case). Strict refusal is
 *  the alternative; lenient skip + log is the call here because (a) a
 *  partial approval set is still better than nothing for the admin
 *  signing the trust-anchor change, and (b) `stamp merge` will
 *  authoritatively re-check and refuse to merge with any bad rows.
 */
function loadServerApprovals(
  repoRoot: string,
  baseSha: string,
  headSha: string,
  manifest: TrustedKeysManifest,
): ApprovalEntryV4[] {
  const db = openDb(stampStateDbPath(repoRoot));
  try {
    const rows = serverApprovalsFor(db, baseSha, headSha);
    if (rows.length === 0) return [];

    // Build pubkey map at base_sha (same boundary as merge).
    const pubFilenames = listFilesAtRef(baseSha, ".stamp/trusted-keys", repoRoot);
    const pubkeyByFingerprint = buildPubkeyMap(pubFilenames, (relPath) =>
      showAtRef(baseSha, relPath, repoRoot),
    );

    const out: ApprovalEntryV4[] = [];
    for (const row of rows) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(row.approval_json);
      } catch {
        process.stderr.write(
          `note: skipping malformed server approval row for reviewer ${row.reviewer}\n`,
        );
        continue;
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
      const a = parsed as ApprovalV4;
      const pem = pubkeyByFingerprint.get(a.server_key_id);
      if (!pem) continue;
      const caps = resolveCapability(manifest, a.server_key_id);
      if (!caps || !caps.includes("server")) continue;
      let ok = false;
      try {
        ok = verifyBytes(pem, canonicalSerializeApproval(a), row.signature_b64);
      } catch {
        ok = false;
      }
      if (!ok) {
        process.stderr.write(
          `note: skipping unverifiable server approval row for reviewer ${row.reviewer} (run \`stamp review\` to refresh)\n`,
        );
        continue;
      }
      out.push({
        approval: a,
        server_attestation: {
          server_key_id: a.server_key_id,
          signature: row.signature_b64,
        },
      });
    }
    // Keep deterministic order: by reviewer name (matches
    // `serverApprovalsFor`'s ORDER BY reviewer ASC).
    out.sort((x, y) =>
      x.approval.reviewer < y.approval.reviewer
        ? -1
        : x.approval.reviewer > y.approval.reviewer
          ? 1
          : 0,
    );
    return out;
  } finally {
    db.close();
  }
}

/** Best-effort guess at the target branch for sign-time payload
 *  prediction. Reads the current branch name; defaults to `main` when
 *  detached. Admins can override with `--target-branch`. */
function guessTargetBranch(repoRoot: string): string {
  try {
    const out = execFileSync(
      "git",
      ["rev-parse", "--abbrev-ref", "HEAD"],
      { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();
    if (out && out !== "HEAD") {
      // Heuristic: on a feature branch, the operator will merge INTO
      // main (or the upstream). Try upstream first.
      const upstream = resolveUpstream(repoRoot, "HEAD");
      if (upstream) {
        const slash = upstream.lastIndexOf("/");
        if (slash >= 0) return upstream.slice(slash + 1);
      }
      return out;
    }
  } catch {
    /* fall through */
  }
  return "main";
}

function gitDiffBetween(repoRoot: string, base: string, head: string): string {
  return execFileSync("git", ["diff", `${base}...${head}`], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/** Detect which envelope the admin signature is being produced for by
 *  reading `.stamp/config.yml` at base_sha and checking whether the
 *  matching branch rule has `review_server` set. Mirrors `stamp
 *  attest`'s dispatch: `review_server` present → Shape 4 PR-mode (v3
 *  envelope, schema_version 3); absent → v4 commit-trailer envelope
 *  (schema_version 5). Any read/parse failure (no config, no matching
 *  rule, malformed YAML) falls back to `v4` — the safe default that
 *  preserves prior behavior for repos not yet on Shape 4. */
function detectEnvelopeModeAtBase(
  repoRoot: string,
  baseSha: string,
  targetBranch: string,
): ResolvedMode {
  let yaml: string;
  try {
    yaml = showAtRef(baseSha, ".stamp/config.yml", repoRoot);
  } catch {
    return "v4";
  }
  let config: ReturnType<typeof parseConfigFromYaml>;
  try {
    config = parseConfigFromYaml(yaml);
  } catch {
    return "v4";
  }
  let rule: ReturnType<typeof findBranchRule>;
  try {
    rule = findBranchRule(config.branches, targetBranch);
  } catch {
    // Ambiguous glob match — be conservative and fall back to v4
    // rather than guess. The operator can pass --mode explicitly.
    return "v4";
  }
  if (!rule) return "v4";
  return rule.review_server ? "pr" : "v4";
}

