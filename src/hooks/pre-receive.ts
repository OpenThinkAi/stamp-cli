/**
 * stamp-verify pre-receive hook.
 *
 * Install as `hooks/pre-receive` (executable) in a bare git repo. For each
 * ref being pushed, the hook reads the target branch's current config +
 * trusted keys (from the pre-push tree, i.e. `old_sha:.stamp/...`), then
 * verifies every new commit introduced by the push.
 *
 * Rules:
 *   - Non-protected refs (no matching rule in .stamp/config.yml) pass through.
 *   - Creation of protected refs (old_sha=0000...) is rejected — operator
 *     must seed directly, see DESIGN.md "Bootstrap".
 *   - Force-pushes (new_sha not a descendant of old_sha) are rejected.
 *   - Every new commit on a protected branch must be a merge commit with
 *     valid Stamp-Payload + Stamp-Verified trailers, signed by a trusted
 *     key, with SHAs matching the commit's parents, and approvals meeting
 *     the branch's required list.
 *
 * Exits 0 on success, 1 on rejection. Rejection reasons go to stderr —
 * git forwards these to the pushing client.
 *
 * Per-commit verification is structured as a pipeline of named phase
 * functions (see `COMMIT_PHASES`). Each phase is a pure check returning
 * a `PhaseResult`; the orchestrator (`verifyCommit`) invokes them in
 * order and rejects on the first failure. AGT-350 (this refactor) is the
 * precursor for AGT-335, which will append v4 verification phases.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import {
  MIN_ACCEPTED_PAYLOAD_VERSION,
  parseCommitAttestation,
  type AttestationPayload,
} from "../lib/attestation.js";
import {
  MIN_ACCEPTED_V4_SCHEMA_VERSION,
  type AttestationPayloadV4,
} from "../lib/attestationV4.js";
import { fingerprintFromPem } from "../lib/keys.js";
import { globToRegex, isGlobPattern } from "../lib/refPatterns.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
  readReviewersFromYaml,
} from "../lib/reviewerHash.js";
import { verifyBytes } from "../lib/signing.js";
import { parseManifest } from "../lib/trustedKeysManifest.js";
// V4-trust-level verification pipeline lives in src/lib/v4Trust.ts so
// both this hook and the PR-mode verifier (src/commands/verifyPr.ts)
// call into the same phase functions — no logic divergence between
// server-gated and PR-mode. AGT-338 lifted these out of this file
// per the standards-reviewer round 2 concern about
// `src/commands/` importing from `src/hooks/`.
import {
  COMMIT_PHASES_V4,
  parsePathRules,
  readPubkeyMapAt,
  readChangedFilesAtRef,
  type BranchRule as V4BranchRule,
  type CheckDef as V4CheckDef,
  type PathRule as V4PathRule,
  type PhaseInputV4,
} from "../lib/v4Trust.js";
// Re-export so external callers that imported from this hook before
// AGT-338's lift-out (none in production, but tests like
// tests/preReceiveV4.test.ts and tests/v4Roundtrip.test.ts) keep
// working without a churn-only test rewrite.
export {
  verifyV4MergeStructure,
  verifyV4TargetBranch,
  verifyV4SignerTrust,
  verifyV4OuterSignature,
  verifyV4ManifestSnapshot,
  verifyV4Approvals,
  verifyV4DiffHash,
  verifyV4ApprovalSignatures,
  verifyV4Checks,
  verifyV4TrustAnchorSignatures,
  verifyV4StampPathsGuard,
  parsePathRules,
  type PhaseInputV4,
  type PathRule,
  type BranchRule,
} from "../lib/v4Trust.js";

const ZERO_SHA = "0000000000000000000000000000000000000000";

// CheckDef / BranchRule / PathRule are owned by `src/lib/v4Trust.ts`
// post-AGT-338. Local aliases here so the hook's internal code reads
// identically; the runtime types are the same module's exports.
type CheckDef = V4CheckDef;
type BranchRule = V4BranchRule;
type PathRule = V4PathRule;

interface StampConfigAtRef {
  branches: Record<string, BranchRule>;
  /** Optional. Absent / empty → no path_rules layer, the v3-era
   *  behavior. AGT-336 added this. Map shape (glob → rule) chosen to
   *  match the spec doc and to mirror `branches:`'s map keying. */
  path_rules?: PathRule[];
}

// ---------- per-commit verification pipeline ----------

type PhaseResult = { ok: true } | { ok: false; reason: string };

interface PhaseInput {
  sha: string;
  branch: string;
  rule: BranchRule;
  trustedKeys: Map<string, string>;
  payload: AttestationPayload;
  payloadBytes: Buffer;
  signatureBase64: string;
}

type Phase = (input: PhaseInput) => PhaseResult;

function main(): void {
  const stdin = readAllStdin();
  const lines = stdin.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) process.exit(0);

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const [oldSha, newSha, refname] = parts as [string, string, string];
    verifyRef(oldSha, newSha, refname);
  }
}

function verifyRef(oldSha: string, newSha: string, refname: string): void {
  // Deletion: allow (branch protection at the git/forge level handles this
  // if the operator wants to prevent ref deletion).
  if (newSha === ZERO_SHA) return;

  // Tag pushes: a tag is accepted iff the commit it points at is reachable
  // from at least one protected branch (i.e., it was already verified when
  // it landed on that branch). Without this gate, a push of
  // <unverified-sha>:refs/tags/v9.99.99 would be mirrored to GitHub and
  // trigger any publish-on-tag workflow downstream operators have wired up
  // (npm release on tag, Cargo, PyPI, etc.). The stamp-cli post-receive
  // mirror added tag mirroring in 0.7.8 specifically because those flows
  // are common, so the same trust must apply to tag refs as to branch refs.
  if (refname.startsWith("refs/tags/")) {
    verifyTagPush(newSha, refname);
    return;
  }

  // Other ref classes (refs/notes/, refs/replace/, etc.) are not currently
  // mirrored and not used by the stamp protocol; pass through. If a future
  // change starts mirroring any of these, this allow-list must tighten.
  if (!refname.startsWith("refs/heads/")) return;
  const branch = refname.slice("refs/heads/".length);

  // For ref creation (old_sha is zeros), we need SOMETHING to read config
  // from. The "create" case is the bootstrap, and DESIGN.md is explicit:
  // operator seeds directly on the server, not via push. Reject.
  if (oldSha === ZERO_SHA) {
    reject(
      refname,
      `branch creation via push is not allowed. The operator must seed the repo directly on the server (see DESIGN.md "Bootstrap").`,
    );
  }

  // Load config + trusted keys from the pre-push state of this branch.
  const config = readConfigAt(oldSha);
  if (!config) {
    reject(
      refname,
      `no readable .stamp/config.yml at ${oldSha.slice(0, 8)}. Repo is not bootstrapped.`,
    );
  }

  const rule = resolveBranchRule(config.branches, branch);
  if (!rule) {
    // Not a protected branch — pass.
    return;
  }

  // Force-push check: new_sha must be a descendant of old_sha.
  if (!isAncestor(oldSha, newSha)) {
    reject(
      refname,
      `push is not fast-forward (old ${oldSha.slice(0, 8)} is not an ancestor of new ${newSha.slice(0, 8)}). Force-push to a protected branch is not allowed.`,
    );
  }

  // Race-safe FF check: pre-receive's stdin oldSha is the ref value when
  // the push session started. If a concurrent push has advanced the live
  // tip since then (Agent-1 lands B before Agent-2's pre-receive runs,
  // both starting from A), the stdin oldSha is stale — issue #20.
  // Re-read the live tip and require newSha to be a descendant of *that*
  // too, so the push is FF against actual repo state, not against what
  // the client-supplied wire protocol claimed was current.
  const liveTip = readLiveRef(refname);
  if (liveTip !== null && liveTip !== oldSha) {
    if (!isAncestor(liveTip, newSha)) {
      reject(
        refname,
        `concurrent push detected: live tip is ${liveTip.slice(0, 8)} ` +
          `but this push expected ${oldSha.slice(0, 8)}, and new ` +
          `${newSha.slice(0, 8)} is not a descendant of the live tip. ` +
          `Fetch the latest main and re-run stamp merge so your work ` +
          `lands on top of the current tip.`,
      );
    }
  }

  const trustedKeys = readTrustedKeysAt(oldSha);

  // Verify every new commit introduced by this push.
  const newCommits = listNewCommits(oldSha, newSha);
  for (const sha of newCommits) {
    verifyCommit(sha, branch, rule, trustedKeys, refname);
  }
}

/**
 * Verify a tag push: the pointed-at commit must be reachable from at least
 * one protected branch. Reads config from the bare repo's HEAD (the default
 * branch) — tag pushes don't carry their own branch context, so we anchor
 * on the operator-chosen default for "what counts as a protected branch."
 *
 * Handles both lightweight and annotated tags via `^{commit}` peeling.
 *
 * Exported via the module's verifyRef path; not unit-tested in isolation
 * because every interesting case requires a real git repo. The reviewer +
 * required-checks gates on PRs touching this file are the practical
 * coverage; integration is exercised by stamp-cli's own dogfooding push.
 */
function verifyTagPush(newSha: string, refname: string): void {
  // Resolve to the underlying commit. For lightweight tags, newSha already
  // IS the commit. For annotated tags, newSha is the tag object and
  // ^{commit} peels through the tag to its target.
  let pointedCommit: string;
  try {
    pointedCommit = run(["rev-parse", `${newSha}^{commit}`]).trim();
  } catch (err) {
    reject(
      refname,
      `cannot resolve tag ${newSha.slice(0, 8)} to a commit: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Find the bare repo's default branch via HEAD; that's the canonical
  // place to read .stamp/config.yml from for tag verification (tags
  // themselves don't have a branch context).
  let headRef: string;
  try {
    headRef = run(["symbolic-ref", "HEAD"]).trim();
  } catch {
    reject(
      refname,
      `cannot read repo HEAD; tag pushes require a bootstrapped default branch`,
    );
  }
  let defaultBranchTip: string;
  try {
    defaultBranchTip = run(["rev-parse", headRef]).trim();
  } catch {
    reject(
      refname,
      `cannot resolve ${headRef}; repo is not bootstrapped`,
    );
  }

  const config = readConfigAt(defaultBranchTip);
  if (!config) {
    reject(
      refname,
      `no readable .stamp/config.yml at ${defaultBranchTip.slice(0, 8)}; tag pushes require a bootstrapped repo`,
    );
  }

  // Enumerate every existing branch ref and keep the ones whose name
  // matches a rule in config.branches (exact or glob). A tag is acceptable
  // iff the pointed commit is reachable from at least one of these.
  const branchListing = run([
    "for-each-ref",
    "--format=%(refname:short)",
    "refs/heads/",
  ]);
  const allBranches = branchListing.split("\n").filter((b) => b.length > 0);

  const protectedBranches: string[] = [];
  for (const b of allBranches) {
    if (resolveBranchRule(config.branches, b)) protectedBranches.push(b);
  }

  if (protectedBranches.length === 0) {
    reject(
      refname,
      `no protected branches configured in .stamp/config.yml at the default branch; cannot evaluate tag push`,
    );
  }

  for (const b of protectedBranches) {
    const tip = run(["rev-parse", `refs/heads/${b}`]).trim();
    if (isAncestor(pointedCommit, tip)) {
      // Pointed commit is in the verified history of a protected branch —
      // it has already been gated by the same rules at branch-push time.
      return;
    }
  }

  reject(
    refname,
    `tag points at commit ${pointedCommit.slice(0, 8)} which is not reachable from any protected branch ` +
      `(${protectedBranches.join(", ")}). Tags can only point at commits that have already passed branch verification — ` +
      `merge to a protected branch first via the stamp flow, then create the tag from that commit.`,
  );
}

// Per-commit verification phases (in order). Each `fn` is a pure check;
// the orchestrator (`verifyCommit`) rejects on the first failure. Order
// is load-bearing — cheaper / more-structural checks first, and later
// phases assume earlier ones have run (e.g. verifyTrailerSignature relies
// on verifySignerTrust having confirmed the trusted-key lookup). When
// AGT-335 adds v4 phases, prefer appending.
//
// Trailer presence (no Stamp-Payload at all → reject) is handled in
// `verifyCommit` before the pipeline, since phases operate on an
// already-parsed `AttestationPayload`. Threat caught there: unstamped
// commit landing on a protected branch.
const COMMIT_PHASES: ReadonlyArray<{ name: string; fn: Phase }> = [
  { name: "verifyMergeStructure", fn: verifyMergeStructure },
  { name: "verifyTargetBranch", fn: verifyTargetBranch },
  { name: "verifySignerTrust", fn: verifySignerTrust },
  { name: "verifyTrailerSignature", fn: verifyTrailerSignature },
  { name: "verifyApprovals", fn: verifyApprovals },
  { name: "verifyChecks", fn: verifyChecks },
  { name: "verifySchemaVersion", fn: verifySchemaVersion },
  { name: "verifyReviewerHashesAtMergeBase", fn: verifyReviewerHashesAtMergeBase },
];

function verifyCommit(
  sha: string,
  branch: string,
  rule: BranchRule,
  trustedKeys: Map<string, string>,
  refname: string,
): void {
  // commit message body is everything after the first blank-line separator
  // in `git cat-file -p <commit>` output (headers then blank line then body)
  const commitMessage = run(["cat-file", "-p", sha]).split(/\n\n/s).slice(1).join("\n\n");

  const parsed = parseCommitAttestation(commitMessage);
  if (!parsed) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)} has no Stamp-Payload / Stamp-Verified trailers. Every commit to '${branch}' must be a stamped merge.`,
    );
  }

  // Dispatch by schema_version. The legacy v3 verifier and the v4
  // verifier coexist intentionally during the 1.x → 2.x bridge era — a
  // single repo can have both v3-stamped historical merges and v4
  // server-attested new merges. The two envelopes share the
  // Stamp-Payload / Stamp-Verified trailer keys; only the integer in
  // `schema_version` tells them apart (see attestationV4.ts module
  // docstring on the rationale for picking v4 specifically). Schema 1–2
  // were rejected by v3's `verifySchemaVersion` and remain so under v4
  // dispatch: any value < MIN_ACCEPTED_PAYLOAD_VERSION (3) rejects
  // outright before the pipeline runs.
  const rawSchemaVersion = (parsed.payload as { schema_version?: unknown })
    .schema_version;
  if (typeof rawSchemaVersion === "number" && rawSchemaVersion >= MIN_ACCEPTED_V4_SCHEMA_VERSION) {
    verifyCommitV4(sha, branch, rule, parsed.payloadBytes, parsed.signatureBase64, refname);
    return;
  }

  const input: PhaseInput = {
    sha,
    branch,
    rule,
    trustedKeys,
    payload: parsed.payload,
    payloadBytes: parsed.payloadBytes,
    signatureBase64: parsed.signatureBase64,
  };

  for (const phase of COMMIT_PHASES) {
    const result = phase.fn(input);
    if (!result.ok) reject(refname, result.reason);
  }
}

// ---------- phase implementations (pure; no reject / process.exit) ----------

/** Threat: stamped commit lying about what was merged — a wrong second
 *  parent or wrong merge-base would mean the attestation reviewed one
 *  diff while git applied another. */
function verifyMergeStructure(input: PhaseInput): PhaseResult {
  const { sha, branch, payload } = input;

  const parents = run(["rev-list", "--parents", "-n", "1", sha])
    .trim()
    .split(/\s+/)
    .slice(1);
  if (parents.length !== 2) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)} is not a merge commit (has ${parents.length} parent(s)). Every commit to '${branch}' must be a --no-ff merge.`,
    };
  }
  const [parent0, parent1] = parents as [string, string];

  if (parent1 !== payload.head_sha) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: second parent (${parent1.slice(0, 8)}) != payload.head_sha (${payload.head_sha.slice(0, 8)})`,
    };
  }

  const mergeBase = run(["merge-base", parent0, parent1]).trim();
  if (mergeBase !== payload.base_sha) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: merge-base(${parent0.slice(0, 8)}, ${parent1.slice(0, 8)}) = ${mergeBase.slice(0, 8)} != payload.base_sha (${payload.base_sha.slice(0, 8)})`,
    };
  }

  return { ok: true };
}

/** Threat: cross-branch replay — attestation produced for one protected
 *  branch reused on another. `target_branch` in the signed payload must
 *  match the branch being pushed. */
function verifyTargetBranch(input: PhaseInput): PhaseResult {
  const { sha, branch, payload } = input;
  if (payload.target_branch !== branch) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: payload.target_branch ("${payload.target_branch}") does not match the branch being pushed ("${branch}")`,
    };
  }
  return { ok: true };
}

/** Threat: signer key not in `.stamp/trusted-keys/` at the pre-push
 *  tree — unknown or attacker-controlled. */
function verifySignerTrust(input: PhaseInput): PhaseResult {
  const { sha, payload, trustedKeys } = input;
  if (!trustedKeys.has(payload.signer_key_id)) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: signer key ${payload.signer_key_id} is not in .stamp/trusted-keys/`,
    };
  }
  return { ok: true };
}

/** Threat: payload tampering or signature forgery — the Ed25519
 *  signature over the canonical payload bytes must verify against the
 *  trusted signer's pubkey. Assumes verifySignerTrust has passed. */
function verifyTrailerSignature(input: PhaseInput): PhaseResult {
  const { sha, payload, payloadBytes, signatureBase64, trustedKeys } = input;
  const trustedPem = trustedKeys.get(payload.signer_key_id)!;
  let sigValid = false;
  try {
    sigValid = verifyBytes(trustedPem, payloadBytes, signatureBase64);
  } catch (err) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: signature verification threw — ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!sigValid) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: Ed25519 signature does not verify against the signer's trusted key`,
    };
  }
  return { ok: true };
}

/** Threat: missing required reviewers — every name in the branch rule's
 *  `required:` list must appear with verdict='approved'. */
function verifyApprovals(input: PhaseInput): PhaseResult {
  const { sha, payload, rule } = input;
  const approvedReviewers = new Set(
    payload.approvals
      .filter((a) => a.verdict === "approved")
      .map((a) => a.reviewer),
  );
  const missing = rule.required.filter((r) => !approvedReviewers.has(r));
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: missing required approvals — ${missing.join(", ")}`,
    };
  }
  return { ok: true };
}

/** Threat: skipped or failing required checks (CI) — every
 *  `required_checks` entry in the committed config must be attested with
 *  exit_code === 0. */
function verifyChecks(input: PhaseInput): PhaseResult {
  const { sha, payload, rule } = input;
  const requiredChecks = rule.required_checks ?? [];
  const attestedByName = new Map(
    ((payload as { checks?: { name: string; exit_code: number }[] }).checks ?? [])
      .map((c) => [c.name, c]),
  );
  const missingChecks: string[] = [];
  const failingChecks: string[] = [];
  for (const req of requiredChecks) {
    const attested = attestedByName.get(req.name);
    if (!attested) {
      missingChecks.push(req.name);
      continue;
    }
    if (attested.exit_code !== 0) {
      failingChecks.push(`${req.name} (exit ${attested.exit_code})`);
    }
  }
  if (missingChecks.length > 0) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: attestation is missing required check(s) — ${missingChecks.join(", ")}`,
    };
  }
  if (failingChecks.length > 0) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: attestation records failing check(s) — ${failingChecks.join(", ")}`,
    };
  }
  return { ok: true };
}

/** Threat: known-broken v2 attestations — v2 sourced reviewer hashes
 *  from the merge commit's own (post-merge) tree, enabling a feature
 *  branch to modify a reviewer prompt and self-verify. v3+ binds to the
 *  merge-base tree (handled by verifyReviewerHashesAtMergeBase); v<3 is
 *  rejected outright with no upgrade path other than re-merging. */
function verifySchemaVersion(input: PhaseInput): PhaseResult {
  const { sha, payload } = input;
  const version = payload.schema_version ?? 1;
  if (version < MIN_ACCEPTED_PAYLOAD_VERSION) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: attestation schema_version ${version} is no longer accepted ` +
        `(minimum supported is ${MIN_ACCEPTED_PAYLOAD_VERSION} — earlier versions are known-broken under ` +
        `the feature-branch self-review attack). Re-create the merge with a current stamp-cli build ` +
        `which produces v${MIN_ACCEPTED_PAYLOAD_VERSION} attestations bound to the merge-base tree.`,
    };
  }
  return { ok: true };
}

/** Threat: feature branch modifying `.stamp/config.yml` or a reviewer
 *  prompt/tools/mcp config and self-verifying. Defense: recompute hashes
 *  from the merge-base tree (invariant under the diff).
 *  `payload.base_sha` is provably the merge-base because
 *  verifyMergeStructure already cross-checked it. */
function verifyReviewerHashesAtMergeBase(input: PhaseInput): PhaseResult {
  const { sha, payload } = input;
  const baseSha = payload.base_sha;
  const prefix = `commit ${sha.slice(0, 8)}: v3 attestation:`;

  let configYaml: string;
  try {
    configYaml = run(["show", `${baseSha}:.stamp/config.yml`]);
  } catch {
    return {
      ok: false,
      reason: `${prefix} .stamp/config.yml unreadable at merge-base ${baseSha.slice(0, 8)}`,
    };
  }
  const reviewers = readReviewersFromYaml(configYaml);

  for (const approval of payload.approvals) {
    const missing: string[] = [];
    if (!approval.prompt_sha256) missing.push("prompt_sha256");
    if (!approval.tools_sha256) missing.push("tools_sha256");
    if (!approval.mcp_sha256) missing.push("mcp_sha256");
    if (missing.length > 0) {
      return {
        ok: false,
        reason: `${prefix} approval for "${approval.reviewer}" is missing ${missing.join(", ")}`,
      };
    }
    const def = reviewers[approval.reviewer];
    if (!def) {
      return {
        ok: false,
        reason: `${prefix} reviewer "${approval.reviewer}" not defined in .stamp/config.yml at merge-base`,
      };
    }
    if (def.prompt === undefined) {
      // v3 attestation cites this reviewer's prompt_sha256, but the
      // committed config at merge-base has no prompt path. v3 envelopes
      // are the local-LLM path; reaching here means a v3-shaped
      // attestation referencing a Shape 4 (server-bundled) reviewer.
      // That combination can't exist in a healthy producer flow — v4 is
      // the envelope for server-attested reviews.
      return {
        ok: false,
        reason: `${prefix} reviewer "${approval.reviewer}" has no \`prompt:\` in .stamp/config.yml at merge-base; v3 attestation references prompt_sha256 but the producer flow for server-bundled prompts is v4 (server-attested). The attestation envelope and the config shape are inconsistent.`,
      };
    }
    let promptBytes: string;
    try {
      promptBytes = run(["show", `${baseSha}:${def.prompt}`]);
    } catch {
      return {
        ok: false,
        reason: `${prefix} reviewer "${approval.reviewer}" prompt "${def.prompt}" unreadable at merge-base`,
      };
    }

    const fields: Array<{ field: string; computed: string; expected: string }> = [
      { field: "prompt", computed: hashPromptBytes(Buffer.from(promptBytes, "utf8")), expected: approval.prompt_sha256! },
      { field: "tools", computed: hashTools(def.tools), expected: approval.tools_sha256! },
      { field: "mcp_servers", computed: hashMcpServers(def.mcp_servers), expected: approval.mcp_sha256! },
    ];
    for (const f of fields) {
      if (f.computed === f.expected) continue;
      return {
        ok: false,
        reason: `${prefix} reviewer "${approval.reviewer}" ${f.field} hash mismatch ` +
          `(expected ${f.expected.slice(0, 16)}..., committed tree has ${f.computed.slice(0, 16)}...). ` +
          `The committed config differs from what the attestation claims; re-run stamp merge or revert the change.`,
      };
    }
  }

  return { ok: true };
}

// ---------- v4 (server-attested) verification: dispatcher ----------
//
// The v4 phase functions + the COMMIT_PHASES_V4 pipeline live in
// `src/lib/v4Trust.ts` (lifted out of this file in AGT-338 so PR-mode
// — `src/commands/verifyPr.ts` — can call the SAME helpers without
// importing from `src/hooks/`). This dispatcher reads bytes off the
// commit trailer, builds the PhaseInputV4 from `base_sha`'s tree, and
// runs the pipeline. PR-mode builds its own PhaseInputV4 from a
// patch-id-keyed envelope and runs the PR-mode subset.

function verifyCommitV4(
  sha: string,
  branch: string,
  rule: BranchRule,
  payloadBytes: Buffer,
  signatureBase64: string,
  refname: string,
): void {
  // Re-parse payload bytes into the v4 shape. We DON'T re-derive bytes
  // via canonicalSerializePayload here — the operator signed the exact
  // bytes that landed in the Stamp-Payload trailer (see merge.ts:
  // `payloadBytes = canonicalSerializePayload(payload); signBytes(...)`
  // → those same bytes ride the trailer through base64), so the
  // signature target is the raw decoded trailer bytes. Re-canonicalizing
  // would work too but adds a needless surface; matches how v3
  // verifyTrailerSignature uses the raw bytes.
  let payload: AttestationPayloadV4;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8")) as AttestationPayloadV4;
  } catch (err) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: v4 payload is not valid JSON — ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Structural validation: the parseEnvelope helper in attestationV4
  // enforces this for the envelope shape, but the trailer wire format
  // carries the bare payload (not an envelope), so we re-implement the
  // minimum shape checks inline here. Field-level checks below the
  // pipeline (e.g. signer_key_id format) catch tampering that this
  // structural check would not.
  if (
    !payload ||
    typeof payload !== "object" ||
    typeof payload.schema_version !== "number" ||
    typeof payload.base_sha !== "string" ||
    typeof payload.head_sha !== "string" ||
    typeof payload.target_branch !== "string" ||
    typeof payload.diff_sha256 !== "string" ||
    typeof payload.signer_key_id !== "string" ||
    !Array.isArray(payload.approvals) ||
    !Array.isArray(payload.checks) ||
    !Array.isArray(payload.trust_anchor_signatures)
  ) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: v4 payload has invalid structure (missing or wrong-typed fields)`,
    );
  }
  if (payload.schema_version < MIN_ACCEPTED_V4_SCHEMA_VERSION) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: v4 attestation schema_version ${payload.schema_version} is below minimum ${MIN_ACCEPTED_V4_SCHEMA_VERSION}. Re-create the merge with a current stamp-cli build.`,
    );
  }

  // Load trust artifacts at base_sha. Sourcing from base_sha (the
  // merge-base of the merge commit's parents) is the v3→v4 carry-over
  // invariant: the trust root the verifier consults is the one that
  // existed BEFORE the diff, so a feature branch shipping a permissive
  // manifest cannot have that manifest trust its own additions. We
  // cross-check base_sha is actually the merge-base in
  // verifyV4MergeStructure before any of the subsequent phases run.
  let manifestYaml: string;
  try {
    manifestYaml = run(["show", `${payload.base_sha}:.stamp/trusted-keys/manifest.yml`]);
  } catch (err) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: .stamp/trusted-keys/manifest.yml is missing at base ${payload.base_sha.slice(0, 8)} — v4 attestations require the manifest in the merge-base tree. (${err instanceof Error ? err.message : String(err)})`,
    );
  }
  const manifest = parseManifest(manifestYaml);
  if (!manifest) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: .stamp/trusted-keys/manifest.yml at base ${payload.base_sha.slice(0, 8)} failed to parse (bad YAML, duplicate fingerprint, unknown capability, etc.)`,
    );
  }

  const pubkeyByFingerprint = readPubkeyMapAt(payload.base_sha);

  // Read path_rules from .stamp/config.yml at base_sha. We re-read
  // here (rather than reusing the config the outer verifyRef loaded
  // from oldSha) because v4's invariant is "trust artifacts come from
  // payload.base_sha." For a fast-forward merge oldSha === base_sha
  // and the two reads agree; for a non-trivial merge there's
  // intermediate history and base_sha is the only source-of-truth.
  // Matches the manifest read above.
  const configAtBase = readConfigAt(payload.base_sha);
  const pathRules = configAtBase?.path_rules ?? [];

  // Changed files: 3-dot diff (`base...head`) — same diff form used by
  // verifyV4DiffHash, so a rule that matches here matches what the
  // hash binding covers. Reading via `git diff --name-only` keeps us
  // off the working tree (load-bearing — the hook runs in a bare repo
  // with no checkout).
  const changedFiles = readChangedFilesAtRef(payload.base_sha, payload.head_sha);
  if (changedFiles === null) {
    // `reject` is typed `: never` (process.exit(1) inside), so the
    // bare `return` below is structurally unreachable. We keep it
    // anyway as belt-and-suspenders against any future refactor that
    // makes `reject` non-terminal: without it, the subsequent
    // PhaseInputV4 construction would propagate `null` into
    // `changedFiles`, and `verifyV4StampPathsGuard`'s `.filter()` on
    // null would crash with confusing secondary noise after the
    // primary informative rejection. Per AGT-336 product review.
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: unable to enumerate changed files between base ${payload.base_sha.slice(0, 8)} and head ${payload.head_sha.slice(0, 8)} for path_rules evaluation. Run \`stamp review --diff <base>..<head>\` and re-attempt the merge.`,
    );
    return;
  }

  const input: PhaseInputV4 = {
    sha,
    branch,
    rule,
    payload,
    payloadBytes,
    signatureBase64,
    manifest,
    pubkeyByFingerprint,
    pathRules,
    changedFiles,
  };

  for (const phase of COMMIT_PHASES_V4) {
    const result = phase.fn(input);
    if (!result.ok) reject(refname, result.reason);
  }
}



// ---------- git wrappers (hook runs in the bare repo's cwd) ----------

function run(args: string[]): string {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    throw new Error(
      `git ${args.join(" ")} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Hook-local mirror of lib/config.ts's findBranchRule. Kept here so the
 * hook stays self-contained (it already maintains its own readConfigAt /
 * BranchRule shape rather than importing loadConfig). Same resolution
 * rule: exact key first, then glob fallback, error on multi-glob match.
 */
function resolveBranchRule(
  branches: Record<string, BranchRule>,
  branchName: string,
): BranchRule | undefined {
  const exact = branches[branchName];
  if (exact !== undefined) return exact;
  const matchingKeys: string[] = [];
  for (const key of Object.keys(branches)) {
    if (!isGlobPattern(key)) continue;
    if (globToRegex(key).test(branchName)) matchingKeys.push(key);
  }
  if (matchingKeys.length === 0) return undefined;
  if (matchingKeys.length > 1) {
    throw new Error(
      `branch "${branchName}" matches multiple glob patterns in .stamp/config.yml: ${matchingKeys.map((k) => `"${k}"`).join(", ")}. ` +
        `Tighten the patterns or add an exact-match key for "${branchName}".`,
    );
  }
  return branches[matchingKeys[0]!];
}

function readConfigAt(sha: string): StampConfigAtRef | null {
  try {
    const raw = run(["show", `${sha}:.stamp/config.yml`]);
    const parsed = parseYaml(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as Record<string, unknown>;
    const branches: Record<string, BranchRule> = {};
    if (obj.branches && typeof obj.branches === "object") {
      for (const [name, rule] of Object.entries(obj.branches)) {
        if (!rule || typeof rule !== "object") continue;
        const r = rule as Record<string, unknown>;
        if (!Array.isArray(r.required)) continue;

        const required_checks: CheckDef[] = [];
        if (Array.isArray(r.required_checks)) {
          for (const c of r.required_checks) {
            if (c && typeof c === "object") {
              const cc = c as Record<string, unknown>;
              if (typeof cc.name === "string" && typeof cc.run === "string") {
                required_checks.push({ name: cc.name, run: cc.run });
              }
            }
          }
        }

        branches[name] = {
          required: r.required.map(String),
          ...(required_checks.length > 0 ? { required_checks } : {}),
        };
      }
    }
    const parsedPathRules = parsePathRules(obj.path_rules);
    for (const warning of parsedPathRules.warnings) {
      // Visible to the operator on push (git forwards pre-receive
      // stderr to the pushing client). Per AGT-336 security: silent
      // drops of malformed rules are an operational security gap;
      // surfacing each dropped rule by name lets an operator catch
      // a bad config deploy on the next merge instead of discovering
      // it the day an attacker exploits the missing gate.
      process.stderr.write(`stamp-verify: ${warning}\n`);
    }
    return {
      branches,
      ...(parsedPathRules.rules.length > 0 ? { path_rules: parsedPathRules.rules } : {}),
    };
  } catch {
    return null;
  }
}

function readTrustedKeysAt(sha: string): Map<string, string> {
  // Returns a map of fingerprint → PEM for every .pub file under
  // .stamp/trusted-keys/ at the given ref.
  const map = new Map<string, string>();
  let lsOut: string;
  try {
    lsOut = run(["ls-tree", "-r", "--name-only", sha, ".stamp/trusted-keys/"]);
  } catch {
    return map;
  }
  const files = lsOut.split("\n").filter((f) => f.endsWith(".pub"));
  for (const path of files) {
    try {
      const pem = run(["show", `${sha}:${path}`]);
      const fp = fingerprintFromPem(pem);
      map.set(fp, pem);
    } catch {
      // skip unreadable/invalid
    }
  }
  return map;
}

/**
 * Read the current SHA of `refname` directly from the bare repo, ignoring
 * the stdin-supplied oldSha. Used to belt-and-suspenders the FF check
 * against concurrent-push races where a peer's update lands between the
 * push session opening (which fixed our stdin oldSha) and our pre-receive
 * actually running. Returns null if the ref doesn't exist (e.g. the push
 * is creating it — handled separately).
 */
function readLiveRef(refname: string): string | null {
  try {
    return execFileSync("git", ["rev-parse", "--verify", refname], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

function isAncestor(ancestor: string, descendant: string): boolean {
  try {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", ancestor, descendant],
      { stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}

function listNewCommits(oldSha: string, newSha: string): string[] {
  // --first-parent follows only the target branch's linear history, so we
  // check the stamped merge commits directly added to main — not every
  // commit they brought in from feature branches.
  const out = run([
    "rev-list",
    "--first-parent",
    `${oldSha}..${newSha}`,
  ]).trim();
  if (!out) return [];
  return out.split("\n");
}

function readAllStdin(): string {
  const chunks: Buffer[] = [];
  const fd = 0;
  try {
    chunks.push(readFileSync(fd));
  } catch {
    // empty
  }
  return Buffer.concat(chunks).toString("utf8");
}

// ---------- error output ----------

function reject(refname: string, reason: string): never {
  process.stderr.write(`stamp-verify: rejecting ${refname}\n`);
  process.stderr.write(`  ${reason}\n`);
  process.exit(1);
}

// Run main() only when this module is the executed entrypoint — not
// when it's been imported by another module (notably the unit tests).
// Without this guard, importing the module invokes main() →
// readAllStdin() → the outer catch calls process.exit(1) → the test
// runner dies.
//
// FAIL-OPEN by design: this is a security gate. If we CAN'T determine
// whether we're the entrypoint (URL parse error, missing argv, etc.),
// we MUST default to running the hook. Returning `false` on
// uncertainty would cause the hook to exit 0 silently and approve
// every push — the worst possible failure mode for a verifier. The
// catch returns `true` so any path-comparison oddity surfaces as a
// hook that runs (and either passes or rejects on its own merits)
// rather than a hook that silently no-ops.
//
// Bundle-safe: when this module is bundled into dist/index.js (CLI),
// import.meta.url collapses to the bundle URL. A direct
// `node dist/index.js` run then makes the URL comparison return true
// (both sides resolve to the same bundle file), hijacking the CLI.
// To prevent this, we require argv[1]'s basename to be "pre-receive"
// before trusting the URL comparison — the hook is always installed
// under that name, and no CLI invocation will have that basename.
// This is safe to check first because a non-"pre-receive" argv[1]
// unambiguously indicates we're NOT the hook entrypoint.
//
// Uses `fileURLToPath` (from node:url) rather than constructing a URL
// by string concatenation: it handles symlink resolution AND
// percent-encoding the same way Node sets `import.meta.url`, so the
// comparison stays robust across deployment shapes (symlinked hook
// paths, paths with URL-special characters, etc.). Server-side hook
// invocations under git typically run through a symlink in the bare
// repo's `hooks/` directory; the naive `new URL(\`file://...\`)` form
// would have compared a symlink path on one side to a resolved real
// path on the other and returned `false`, silently disabling the
// hook on every push.
function isMainModule(): boolean {
  const argv1 = typeof process !== "undefined" ? process.argv?.[1] : undefined;
  if (!argv1) {
    // No argv[1] at all — almost certainly an import; don't run main.
    // But for a hook invocation argv[1] is always set, so the `false`
    // branch here only triggers in clearly non-hook contexts.
    return false;
  }
  // Bundle-safety gate: the hook is always installed as "pre-receive".
  // If argv[1]'s basename is anything else (e.g. "index.js", "stamp"),
  // this module has been bundled into a larger entry and we must not
  // fire main(). No need to fall through to the URL comparison.
  if (basename(argv1) !== "pre-receive") {
    return false;
  }
  try {
    return fileURLToPath(import.meta.url) === argv1;
  } catch {
    // URL parse failed for some unexpected reason. Default to running
    // the hook — better to run a verification we might not have needed
    // than to skip one we did.
    return true;
  }
}

if (isMainModule()) {
  try {
    main();
    process.exit(0);
  } catch (err) {
    process.stderr.write(
      `stamp-verify: internal error — ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}
