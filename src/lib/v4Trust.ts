/**
 * v4-trust-level verification pipeline (server-attested reviews, stamp 2.x).
 *
 * Owned here so both the pre-receive hook (server-gated mode, verifies the
 * v4 commit-trailer envelope) and the PR-mode verifier (`stamp verify-pr`
 * / `stamp/verify-attestation@v1`, verifies the v3 PR-attestation envelope
 * that embeds the same v4-trust fields) call the EXACT same phase
 * functions. AGT-338 standards reviewer round 2 flagged the prior shape
 * (PR-mode importing from `src/hooks/pre-receive.ts`) as a module-boundary
 * violation; `src/lib/v4Trust.ts` is the shared home this module-shift
 * resolves to.
 *
 * The phase functions are PURE — they take a `PhaseInputV4` and return a
 * `PhaseResultV4`. Construction of the input (reading the manifest, the
 * pubkey map, path_rules, changed files at base_sha) lives in the callers
 * because each caller's git-access surface differs (pre-receive runs in
 * the bare repo's cwd; verifyPr runs in the operator's working repo).
 *
 * What's NOT in this module:
 *   - The dispatcher that decides "this commit/envelope is v4 vs v3-PR
 *     vs legacy" — that's a caller concern (pre-receive routes by
 *     trailer `schema_version`; verifyPr routes by envelope
 *     `schema_version`).
 *   - Reading `.stamp/config.yml` / `.stamp/trusted-keys/*.pub` at a
 *     ref — each caller does its own git-show wiring (pre-receive's
 *     bare-repo `run` vs verifyPr's `spawnSync` with explicit cwd).
 *     The PUBLIC helpers `readReviewerDefsAtRef` and `readPubkeyMapAt`
 *     below are exported as a convenience that both callers can use,
 *     but they ARE module-internal to v4Trust (they call this module's
 *     `run` against `process.cwd()`); callers that need a different cwd
 *     should wrap or duplicate them.
 *
 * Caller responsibility (process.cwd()): the v4 phase functions shell
 * out to git via the module-local `run` helper, which uses
 * `execFileSync` against `process.cwd()`. Pre-receive's cwd is the bare
 * repo (default for git hooks). PR-mode chdirs into the operator's
 * working repo before invoking the pipeline. Both work; just don't
 * call these functions from a process whose cwd isn't a git repo with
 * the relevant commits / refs.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

import {
  canonicalSerializeApproval,
  canonicalSerializePayload,
  type AttestationPayloadV4,
} from "./attestationV4.js";
import { readReviewersFromYaml } from "./reviewerHash.js";
import { verifyBytes } from "./signing.js";
import { buildPubkeyMap } from "./sshReviewClient.js";
import {
  resolveCapability,
  snapshotSha256,
  type TrustedKeysManifest,
} from "./trustedKeysManifest.js";

// ─── Types shared with the hook + the PR-mode verifier ─────────────

export interface CheckDef {
  name: string;
  run: string;
}

/**
 * Branch-level rule the v4 pipeline checks against. Narrow projection
 * of the full config.ts `BranchRule` — only the fields the phase
 * functions read are kept here, so callers can pass either a hook-
 * parsed rule or a config.ts-parsed rule (structural compatibility).
 */
export interface BranchRule {
  required: string[];
  required_checks?: CheckDef[];
}

/**
 * One `path_rules:` entry from `.stamp/config.yml`. Keyed in the YAML
 * by its path-glob (e.g. `".stamp/**"`); the key is carried alongside
 * as `pattern` for error messages.
 *
 * `require_capability` is one of the manifest's known capabilities (we
 * keep the field a free string here — the manifest's own validator
 * decides which capability strings exist, and we just look up against
 * whatever it returns).
 *
 * `minimum_signatures` is the count of trust-anchor signatures, each
 * coming from a manifest-listed key that carries `require_capability`,
 * required when the merge's diff touches any file matching `pattern`.
 *
 * `bypass_review_cycle: true` means the path-gate REPLACES the normal
 * reviewer cycle for matched paths — `.stamp/**` changes are gated by
 * admin signatures, not by reviewer verdicts. `false` means the path-
 * gate is layered ON TOP OF the reviewer cycle (admins must also sign,
 * and reviewers must also have run).
 */
export interface PathRule {
  pattern: string;
  require_capability: string;
  minimum_signatures: number;
  bypass_review_cycle: boolean;
}

export type PhaseResultV4 = { ok: true } | { ok: false; reason: string };

export interface PhaseInputV4 {
  sha: string;
  branch: string;
  rule: BranchRule;
  payload: AttestationPayloadV4;
  payloadBytes: Buffer;
  signatureBase64: string;
  /** Manifest parsed from `.stamp/trusted-keys/manifest.yml` at
   *  payload.base_sha. The trust root for every signature check below. */
  manifest: TrustedKeysManifest;
  /** Fingerprint → PEM map built from `.stamp/trusted-keys/*.pub` at
   *  payload.base_sha. Resolves manifest entries to actual pubkeys. */
  pubkeyByFingerprint: Map<string, string>;
  /** `path_rules` parsed from `.stamp/config.yml` at payload.base_sha.
   *  Empty when the section is absent / malformed — the verifier then
   *  treats this commit as having no path-gate, the v3-era behavior.
   *  AGT-336 introduced this field; earlier phase-input shapes had no
   *  path_rules concept. */
  pathRules: PathRule[];
  /** Paths changed between payload.base_sha and payload.head_sha
   *  (3-dot diff; matches what `verifyV4DiffHash` hashes). The path-
   *  rules guard intersects this list with each rule's glob. Empty
   *  when the merge has no file changes (degenerate case — the
   *  diff_sha256 binding above will already have rejected most such
   *  merges, but the field can still legitimately be empty for a
   *  pure-tree-rearrangement). */
  changedFiles: string[];
}

export type PhaseV4 = (input: PhaseInputV4) => PhaseResultV4;

// ─── Pipeline ordering ──────────────────────────────────────────────

// ORDERING — defense-in-depth note (NOT security-load-bearing):
//
// Conceptually `verifyV4TrustAnchorSignatures` runs before
// `verifyV4StampPathsGuard` so a forged trust-anchor signature is
// caught with a clear "does not verify" message instead of via the
// guard's quieter "count short" path. But the guard's correctness
// does NOT depend on this ordering — it independently re-verifies
// every `trust_anchor_signatures` entry cryptographically before
// counting, so a future reorder degrades the UX (later/quieter
// error message) but does NOT open a hole. The structural property
// is enforced by the
// "rejects a forged trust_anchor_signature even if the upstream
// phase is bypassed" test in tests/preReceiveV4.test.ts, which
// drives the guard standalone against a forged entry and asserts
// the count stays at zero.
//
// If you reorder these phases, you'll still be secure. Just expect
// noisier-looking errors when something is actually wrong.
export const COMMIT_PHASES_V4: ReadonlyArray<{ name: string; fn: PhaseV4 }> = [
  { name: "verifyV4MergeStructure", fn: verifyV4MergeStructure },
  { name: "verifyV4TargetBranch", fn: verifyV4TargetBranch },
  { name: "verifyV4SignerTrust", fn: verifyV4SignerTrust },
  { name: "verifyV4OuterSignature", fn: verifyV4OuterSignature },
  // AGT-370: envelope-level manifest snapshot binding (lifted from
  // the per-approval slot in v4). Runs once before the per-approval
  // loop in verifyV4ApprovalSignatures — a single check replaces the
  // N-checks per envelope the v4 verifier did.
  { name: "verifyV4ManifestSnapshot", fn: verifyV4ManifestSnapshot },
  { name: "verifyV4Approvals", fn: verifyV4Approvals },
  { name: "verifyV4DiffHash", fn: verifyV4DiffHash },
  { name: "verifyV4ApprovalSignatures", fn: verifyV4ApprovalSignatures },
  { name: "verifyV4Checks", fn: verifyV4Checks },
  // Runs before verifyV4StampPathsGuard for UX (clearer error message
  // on forged sigs); the guard is correct out-of-order too.
  { name: "verifyV4TrustAnchorSignatures", fn: verifyV4TrustAnchorSignatures },
  // Independently re-verifies trust-anchor signatures — see the
  // ORDERING note above. Phase ordering is not security-load-bearing.
  { name: "verifyV4StampPathsGuard", fn: verifyV4StampPathsGuard },
];

/**
 * PR-mode pipeline: same as COMMIT_PHASES_V4 minus `verifyV4MergeStructure`.
 *
 * PR-mode verifies BEFORE the merge commit exists (the merge happens
 * on GitHub after this check passes), so there's no 2-parent merge
 * commit for `verifyV4MergeStructure` to operate on. The integrity
 * binding in PR-mode instead comes from:
 *   - the patch-id ref name (any base/head tampering changes patch-id
 *     and therefore the lookup ref);
 *   - `verifyV4DiffHash` re-hashing `base...head` against the signed
 *     `diff_sha256`;
 *   - the operator's outer signature over the full payload.
 *
 * Exported as a separate constant so PR-mode callers don't have to
 * recreate (or accidentally skip) the right subset.
 */
export const PR_MODE_PHASES_V4: ReadonlyArray<{ name: string; fn: PhaseV4 }> =
  COMMIT_PHASES_V4.filter((p) => p.name !== "verifyV4MergeStructure");

// ─── Phase implementations ──────────────────────────────────────────

/** Same threat model as v3 verifyMergeStructure: a stamped merge that
 *  lies about which parent / merge-base it covers would make the signed
 *  diff/prompt hashes refer to one history while git applied another.
 *  Only meaningful when a merge commit actually exists (server-gated
 *  mode); PR-mode skips this phase. */
export function verifyV4MergeStructure(input: PhaseInputV4): PhaseResultV4 {
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
      reason: `commit ${sha.slice(0, 8)}: v4 second parent (${parent1.slice(0, 8)}) != payload.head_sha (${payload.head_sha.slice(0, 8)})`,
    };
  }

  const mergeBase = run(["merge-base", parent0, parent1]).trim();
  if (mergeBase !== payload.base_sha) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 merge-base(${parent0.slice(0, 8)}, ${parent1.slice(0, 8)}) = ${mergeBase.slice(0, 8)} != payload.base_sha (${payload.base_sha.slice(0, 8)})`,
    };
  }

  return { ok: true };
}

/** Threat: cross-branch replay — attestation produced for one
 *  protected branch reused on another. */
export function verifyV4TargetBranch(input: PhaseInputV4): PhaseResultV4 {
  const { sha, branch, payload } = input;
  if (payload.target_branch !== branch) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 payload.target_branch ("${payload.target_branch}") does not match the branch being pushed ("${branch}")`,
    };
  }
  return { ok: true };
}

/** Threat: operator's signer key is not trusted at base_sha. The
 *  manifest is the v4 trust root — having the pubkey committed isn't
 *  enough; the manifest must bind the fingerprint to a capability that
 *  permits signing the envelope (admin or operator). Server-only keys
 *  must not be able to sign envelopes. */
export function verifyV4SignerTrust(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, manifest, pubkeyByFingerprint } = input;
  const caps = resolveCapability(manifest, payload.signer_key_id);
  if (caps === null) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 signer key ${payload.signer_key_id} is not listed in .stamp/trusted-keys/manifest.yml at base ${payload.base_sha.slice(0, 8)}`,
    };
  }
  if (!caps.includes("admin") && !caps.includes("operator")) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 signer key ${payload.signer_key_id} has capabilities [${caps.join(", ")}] in the manifest at base ${payload.base_sha.slice(0, 8)} — needs 'admin' or 'operator' to sign a v4 envelope. Update the manifest entry and re-merge.`,
    };
  }
  if (!pubkeyByFingerprint.has(payload.signer_key_id)) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 signer key ${payload.signer_key_id} is in the manifest but no matching .pub file exists in .stamp/trusted-keys/ at base ${payload.base_sha.slice(0, 8)}. Commit the public key alongside the manifest entry and re-merge.`,
    };
  }
  return { ok: true };
}

/** Threat: payload tampering or signature forgery on the outer
 *  envelope. The operator's Ed25519 signature over the canonical
 *  payload bytes — same bytes that ride the trailer — must verify
 *  against the operator's pubkey from base_sha. Assumes
 *  verifyV4SignerTrust passed. */
export function verifyV4OuterSignature(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, payloadBytes, signatureBase64, pubkeyByFingerprint } = input;
  const pem = pubkeyByFingerprint.get(payload.signer_key_id)!;
  let sigValid = false;
  try {
    sigValid = verifyBytes(pem, payloadBytes, signatureBase64);
  } catch (err) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 outer signature verification threw — ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!sigValid) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 outer Ed25519 signature does not verify against the operator's trusted key ${payload.signer_key_id}`,
    };
  }
  return { ok: true };
}

/** Threat: missing required reviewers — every name in the branch
 *  rule's `required:` list must appear with verdict='approved'. */
export function verifyV4Approvals(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, rule } = input;
  const approvedReviewers = new Set(
    payload.approvals
      .filter((a) => a.approval.verdict === "approved")
      .map((a) => a.approval.reviewer),
  );
  const missing = rule.required.filter((r) => !approvedReviewers.has(r));
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 missing required approvals — ${missing.join(", ")}`,
    };
  }
  return { ok: true };
}

/** Threat: the operator signed a verdict against one diff but git
 *  applied a different diff. We re-hash the actual base...head diff
 *  in the bare repo and compare to both the top-level diff_sha256
 *  (signed by the operator's envelope signature) AND each approval's
 *  diff_sha256 (signed by the server). Mismatch at either level
 *  rejects: the top level is the operator binding, the per-approval
 *  is the server binding, and they must agree for the merge to be
 *  trustworthy. */
export function verifyV4DiffHash(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload } = input;
  // Use 3-dot diff to match resolveDiff() in src/lib/git.ts, which is
  // what merge.ts feeds to buildV4Trailers — the bytes the server and
  // the operator hashed both flow from that same `git diff base...head`
  // form. merge.ts then encodes the utf-8 string via
  // `Buffer.from(diff, "utf8")` before hashing; we do exactly the same
  // so the hash is byte-identical to what the operator and the server
  // computed.
  let diffText: string;
  try {
    diffText = run(["diff", `${payload.base_sha}...${payload.head_sha}`]);
  } catch (err) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 unable to compute base...head diff — ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  const actualDiffSha256 = createHash("sha256")
    .update(Buffer.from(diffText, "utf8"))
    .digest("hex");
  if (actualDiffSha256 !== payload.diff_sha256) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 diff_sha256 mismatch — payload claims ${payload.diff_sha256.slice(0, 12)}… but base...head hashes to ${actualDiffSha256.slice(0, 12)}…. The operator signed against a different diff than what the commit actually merges.`,
    };
  }
  for (const entry of payload.approvals) {
    if (entry.approval.diff_sha256 !== actualDiffSha256) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval for "${entry.approval.reviewer}" was server-signed against diff_sha256 ${entry.approval.diff_sha256.slice(0, 12)}… but base...head hashes to ${actualDiffSha256.slice(0, 12)}…. The server's verdict is for a different diff.`,
      };
    }
  }
  return { ok: true };
}

/**
 * AGT-370: envelope-level manifest snapshot binding. The operator's
 * outer signature commits to `payload.manifest_snapshot_sha256`; this
 * phase confirms that value equals the snapshot of the manifest the
 * verifier reads at `base_sha`.
 *
 * Lenient revocation moves from per-approval to per-envelope: a server
 * key revoked AFTER `base_sha` remains valid for envelopes whose
 * `base_sha` predates the revocation, because the manifest at that
 * base still lists it. A key never listed in the manifest at `base_sha`
 * cannot produce a server signature this verifier will accept (see
 * `verifyV4ApprovalSignatures` below).
 *
 * Replaces the per-approval `trusted_keys_snapshot_sha256` check that
 * lived in `verifyV4ApprovalSignatures` in v4. Single check per
 * envelope, not N — same semantics, less surface.
 */
export function verifyV4ManifestSnapshot(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, manifest } = input;
  const computed = snapshotSha256(manifest);
  if (payload.manifest_snapshot_sha256 !== computed) {
    return {
      ok: false,
      reason:
        `commit ${sha.slice(0, 8)}: v4 manifest_snapshot_sha256 ` +
        `(${payload.manifest_snapshot_sha256.slice(0, 16)}…) does not match the ` +
        `manifest at base ${payload.base_sha.slice(0, 8)} ` +
        `(${computed.slice(0, 16)}…). The envelope was signed against a ` +
        `different snapshot of the trust set than the one committed at the ` +
        `merge base. Re-run \`stamp merge\` (or \`stamp attest\`) so the ` +
        `outer signature binds to the current manifest.`,
    };
  }
  return { ok: true };
}

/** Threat: per-approval signature forgery or swapped prompt hash. For
 *  each approval:
 *    1. The inner server_key_id (authoritative — settled decision #9)
 *       must resolve to a key in the manifest AT base_sha with the
 *       'server' capability. Past approvals are grandfathered through
 *       the envelope-level snapshot check
 *       (`verifyV4ManifestSnapshot`): a key revoked on a later commit
 *       but still present at base_sha is accepted (lenient revocation).
 *    2. The outer server_attestation.server_key_id must match the
 *       inner; this prevents an attacker from swapping in a different
 *       server key's pubkey at verify time.
 *    3. The signature must verify against `canonicalSerializeApproval`
 *       of the inner approval body.
 *    4. The approval's base_sha / head_sha / target_branch must
 *       match the payload's — a stale verdict for a different
 *       merge can't be folded in.
 *
 *  AGT-370 removed the v4-era step that recomputed `prompt_sha256`
 *  from the reviewer's prompt file at base_sha. The server-signed
 *  `prompt_sha256` is trusted by transitivity:
 *  manifest (at base_sha) → server key (with `server` capability) →
 *  signed approval body (this phase verifies the Ed25519) →
 *  `prompt_sha256`. Re-hashing from the merge-base tree was never the
 *  trust anchor; it was a belt-and-suspenders second-line defense that
 *  is now impossible (the server filesystem-cache that AGT-370 wires
 *  into has no path back to the operator's repo tree) and structurally
 *  redundant given the signed chain. The change is intentional: it
 *  removes a dependency that forced the server to maintain a bare
 *  clone of every reviewed repo, and the security property survives
 *  because tampering the signed bytes still fails the Ed25519 check
 *  (test: "tampering the signed bytes still fails signature
 *  verification" in `tests/v4Roundtrip.test.ts`).
 *
 *  Anticipated objection: "the verifier still has the operator's tree,
 *  so the recompute could be independent of the server." Correct in the
 *  abstract — but AGT-370's deployment shape (project [shape-2-
 *  topology-correction]) removes `.stamp/reviewers/*.md` from reviewed
 *  repos entirely. The merge-base tree has nothing for the verifier to
 *  hash. Restoring the recompute would require keeping prompts in the
 *  repo, which is the bare-repo dependency this project removes. The
 *  trust shift is the design, not an oversight: prompt bytes are now
 *  anchored at the server's signing key (governed by the manifest),
 *  not at the operator's working tree. Do not re-introduce the
 *  tree-side recompute without re-opening the topology decision.
 */
export function verifyV4ApprovalSignatures(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, manifest, pubkeyByFingerprint } = input;

  for (const entry of payload.approvals) {
    const a = entry.approval;
    const reviewerLabel = `"${a.reviewer}"`;

    // Per-approval body integrity: the inner signed payload binds
    // base / head / target_branch — they must match the envelope's
    // view, otherwise an approval for a different merge could be
    // folded in.
    if (a.base_sha !== payload.base_sha) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel} was signed against base_sha ${a.base_sha.slice(0, 8)} but envelope's base_sha is ${payload.base_sha.slice(0, 8)}`,
      };
    }
    if (a.head_sha !== payload.head_sha) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel} was signed against head_sha ${a.head_sha.slice(0, 8)} but envelope's head_sha is ${payload.head_sha.slice(0, 8)}`,
      };
    }

    // Outer server_attestation.server_key_id is what the operator
    // exported into the envelope; it MUST match the inner signed
    // payload's server_key_id. The inner is authoritative (settled
    // architectural decision #9); the outer is for fast pubkey lookup.
    // A mismatch means someone tampered with one or the other after
    // signing.
    if (entry.server_attestation.server_key_id !== a.server_key_id) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel}: server_attestation.server_key_id (${entry.server_attestation.server_key_id}) does not match inner approval.server_key_id (${a.server_key_id}). The inner signed payload is authoritative; one of the two was tampered with after signing.`,
      };
    }

    // Trust-key lookup uses the INNER signed server_key_id (settled
    // decision #9). The base_sha manifest is the source of truth.
    const caps = resolveCapability(manifest, a.server_key_id);
    if (caps === null) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel} was signed by ${a.server_key_id}, but that key is not in .stamp/trusted-keys/manifest.yml at base ${payload.base_sha.slice(0, 8)}`,
      };
    }
    if (!caps.includes("server")) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel} was signed by ${a.server_key_id}, but that key's capabilities [${caps.join(", ")}] don't include 'server' at base ${payload.base_sha.slice(0, 8)}`,
      };
    }

    const serverPem = pubkeyByFingerprint.get(a.server_key_id);
    if (!serverPem) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel}: no .pub file in .stamp/trusted-keys/ at base ${payload.base_sha.slice(0, 8)} matches fingerprint ${a.server_key_id}`,
      };
    }

    let sigOk = false;
    try {
      sigOk = verifyBytes(
        serverPem,
        canonicalSerializeApproval(a),
        entry.server_attestation.signature,
      );
    } catch (err) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel}: server signature verification threw — ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (!sigOk) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 approval ${reviewerLabel}: server signature does not verify against ${a.server_key_id} over canonical approval bytes`,
      };
    }
  }
  return { ok: true };
}

/** Threat: required checks skipped or failing. Same enforcement as v3
 *  — the v4 envelope's checks list mirrors v3's CheckAttestation
 *  field set. */
export function verifyV4Checks(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, rule } = input;
  const requiredChecks = rule.required_checks ?? [];
  const attestedByName = new Map(payload.checks.map((c) => [c.name, c]));
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
      reason: `commit ${sha.slice(0, 8)}: v4 attestation is missing required check(s) — ${missingChecks.join(", ")}`,
    };
  }
  if (failingChecks.length > 0) {
    return {
      ok: false,
      reason: `commit ${sha.slice(0, 8)}: v4 attestation records failing check(s) — ${failingChecks.join(", ")}`,
    };
  }
  return { ok: true };
}

/** Threat: a forged trust-anchor signature smuggled into the envelope.
 *  This phase verifies any `trust_anchor_signatures` that ARE present —
 *  each must come from an admin-capability key in the manifest at
 *  base_sha and verify over the canonical payload with
 *  trust_anchor_signatures emptied (the documented signing target per
 *  attestationV4.ts).
 *
 *  This phase does NOT enforce "diff touches .stamp/** ⇒ require N
 *  admin signatures." That gate is `verifyV4StampPathsGuard` below
 *  (requires reading path_rules from .stamp/config.yml + applying
 *  minimum_signatures).
 */
export function verifyV4TrustAnchorSignatures(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, manifest, pubkeyByFingerprint } = input;
  if (payload.trust_anchor_signatures.length === 0) return { ok: true };

  // Canonical bytes the admins signed: the payload with
  // trust_anchor_signatures replaced by an empty array. Documented in
  // attestationV4.ts on TrustAnchorSignatureV4.
  const payloadForAdmins: AttestationPayloadV4 = {
    ...payload,
    trust_anchor_signatures: [],
  };
  const adminSigningBytes = canonicalSerializePayload(payloadForAdmins);

  const seen = new Set<string>();
  for (const ts of payload.trust_anchor_signatures) {
    if (seen.has(ts.signer_key_id)) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 trust_anchor_signatures contains a duplicate entry for ${ts.signer_key_id}`,
      };
    }
    seen.add(ts.signer_key_id);

    const caps = resolveCapability(manifest, ts.signer_key_id);
    if (caps === null) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 trust_anchor_signatures includes ${ts.signer_key_id}, which is not in the manifest at base ${payload.base_sha.slice(0, 8)}`,
      };
    }
    if (!caps.includes("admin")) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 trust_anchor_signatures includes ${ts.signer_key_id} with capabilities [${caps.join(", ")}] — needs 'admin' to counter-sign at base ${payload.base_sha.slice(0, 8)}`,
      };
    }
    const pem = pubkeyByFingerprint.get(ts.signer_key_id);
    if (!pem) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 trust_anchor_signatures includes ${ts.signer_key_id} but no matching .pub file is committed at base ${payload.base_sha.slice(0, 8)}`,
      };
    }
    let ok = false;
    try {
      ok = verifyBytes(pem, adminSigningBytes, ts.signature);
    } catch (err) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 trust-anchor signature by ${ts.signer_key_id} threw on verify — ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (!ok) {
      return {
        ok: false,
        reason: `commit ${sha.slice(0, 8)}: v4 trust-anchor signature by ${ts.signer_key_id} does not verify`,
      };
    }
  }
  return { ok: true };
}

/** Threat: an operator (or compromised reviewer key) pushes a commit
 *  that modifies `.stamp/**` (the trust root) through the normal
 *  reviewer cycle, smuggling in a permissive reviewer prompt, a
 *  newly-trusted attacker pubkey, or a tampered config. The reviewer
 *  cycle is structurally vulnerable to this — a sufficiently permissive
 *  new prompt could approve its own merging. The path-rules gate
 *  imposes a STRUCTURAL requirement that admin-capability trust-anchor
 *  signatures accompany any merge that touches a path-rule's glob.
 *
 *  Per AGT-335's retro: `verifyV4TrustAnchorSignatures` above already
 *  validates any admin sigs that are present (a forged or non-admin
 *  sig is caught end-to-end against the manifest at base_sha). This
 *  phase adds the missing piece — the REQUIREMENT layer.
 *
 *  For each rule whose glob set intersects the merge's changed-files
 *  list, count the trust_anchor_signatures whose signer_key_id
 *  resolves (via the manifest at base_sha) to a key carrying
 *  `require_capability`. Reject when that count is below
 *  `minimum_signatures`.
 *
 *  When `bypass_review_cycle: false` AND the rule matches, also
 *  require that the reviewer cycle actually ran for this merge
 *  (envelope.approvals non-empty). `verifyV4Approvals` above already
 *  enforces the branch rule's `required:` list, so the empty-list
 *  check here is the safety net for repos whose `branches.<x>.required`
 *  is empty (a permissive branch-level config that happens to be
 *  pointing at a path-rule that demands the cycle).
 *
 *  When `bypass_review_cycle: true` (the spec example for `.stamp/**`)
 *  the admin gate REPLACES the reviewer gate for these paths — no
 *  additional reviewer-cycle requirement is added by this phase.
 *
 *  Capability resolution uses `resolveCapability(manifest, key_id)`,
 *  same lookup as `verifyV4TrustAnchorSignatures`. The manifest is
 *  the one at base_sha (lenient-revocation snapshot semantics —
 *  decision #5). Forged/non-admin sigs were already weeded out by the
 *  earlier phase, so each entry we COUNT here is guaranteed to be:
 *  (a) in the manifest at base_sha, (b) carrying the capability it
 *  claims, (c) a valid signature over the canonical payload-without-
 *  trust-anchors bytes. We just have to count the matching ones.
 */
export function verifyV4StampPathsGuard(input: PhaseInputV4): PhaseResultV4 {
  const { sha, payload, manifest, pubkeyByFingerprint, pathRules, changedFiles } = input;

  // No path_rules configured → no path-gate, no rejection. Repos
  // pre-AGT-336 / pre-path_rules deployment get the v3-era behavior
  // (the admin-sig defense-in-depth from verifyV4TrustAnchorSignatures
  // still applies to any sigs that ARE present; just no requirement).
  if (pathRules.length === 0) return { ok: true };

  // SECURITY-CRITICAL: independently validate every trust_anchor_signatures
  // entry before counting it toward `minimum_signatures`. We do NOT rely
  // on the upstream `verifyV4TrustAnchorSignatures` phase to have already
  // proved each entry genuine — doing so would make this gate's
  // correctness depend on a declaration-site ordering that future
  // maintainers might unwittingly change. Re-verifying here makes the
  // gate fail-closed independent of phase order: a forged entry whose
  // `signer_key_id` happens to match a real admin fingerprint will not
  // be counted, regardless of what (if anything) ran before us. The
  // cost is a handful of additional Ed25519 verifies (~µs each); the
  // security upside is full structural independence between the two
  // phases. The "rejects a forged trust_anchor_signature even if the
  // upstream phase is bypassed" test in tests/preReceiveV4.test.ts
  // structurally enforces this property.
  //
  // Each verified signer's fingerprint is collected into `validSigners`.
  // We do NOT short-circuit on the first failure: a forged entry alongside
  // genuine ones must not prevent the genuine ones from being counted.
  // The earlier phase will have already rejected the whole envelope if any
  // forged entry exists; this code path is the defense-in-depth fallback.
  const payloadForAdmins: AttestationPayloadV4 = {
    ...payload,
    trust_anchor_signatures: [],
  };
  const adminSigningBytes = canonicalSerializePayload(payloadForAdmins);
  const validSigners = new Set<string>();
  for (const ts of payload.trust_anchor_signatures) {
    if (validSigners.has(ts.signer_key_id)) continue; // dedupe
    const pem = pubkeyByFingerprint.get(ts.signer_key_id);
    if (!pem) continue;
    let ok = false;
    try {
      ok = verifyBytes(pem, adminSigningBytes, ts.signature);
    } catch {
      ok = false;
    }
    if (ok) validSigners.add(ts.signer_key_id);
  }

  for (const rule of pathRules) {
    const matched = changedFiles.filter((f) => pathMatchesAny(f, [rule.pattern]));
    if (matched.length === 0) continue; // Rule doesn't apply to this merge.

    // Count signers with the required capability per the manifest at
    // base_sha. resolveCapability returns null for keys not in the
    // manifest. We iterate `validSigners` (the cryptographically-
    // verified subset built above), not the raw envelope list — a
    // forged entry whose `signer_key_id` happens to be a real admin
    // fingerprint must NOT count toward the gate, even if the
    // upstream phase has somehow been bypassed.
    let qualifying = 0;
    for (const keyId of validSigners) {
      const caps = resolveCapability(manifest, keyId);
      if (caps !== null && caps.includes(rule.require_capability as (typeof caps)[number])) {
        qualifying++;
      }
    }
    if (qualifying < rule.minimum_signatures) {
      const sample = matched.slice(0, 3).join(", ");
      const moreSuffix = matched.length > 3 ? `, +${matched.length - 3} more` : "";
      return {
        ok: false,
        reason:
          `commit ${sha.slice(0, 8)}: v4 path_rules gate for pattern "${rule.pattern}" requires ` +
          `${rule.minimum_signatures} signature(s) from keys with capability '${rule.require_capability}' ` +
          `(diff touches ${matched.length} matched path(s): ${sample}${moreSuffix}), ` +
          `but only ${qualifying} qualifying trust_anchor_signature(s) are present at base ${payload.base_sha.slice(0, 8)}. ` +
          `Re-run the merge after collecting the required admin counter-signatures.`,
      };
    }

    // bypass_review_cycle: false → reviewer cycle must also have run
    // for this merge. We can't validate the reviewer-set against the
    // path itself (the cycle is branch-scoped, not path-scoped, in v4)
    // so the minimum we can enforce here is "at least one approval was
    // recorded." Anything stricter would re-implement
    // verifyV4Approvals; anything looser would let a path-rule with
    // bypass_review_cycle: false silently pass on a no-approvals
    // envelope when the branch's required list happens to be empty.
    if (!rule.bypass_review_cycle && payload.approvals.length === 0) {
      return {
        ok: false,
        reason:
          `commit ${sha.slice(0, 8)}: v4 path_rules gate for pattern "${rule.pattern}" has ` +
          `bypass_review_cycle=false (admin signatures + reviewer cycle required), but the envelope ` +
          `carries no approvals — the reviewer cycle did not run for this merge.`,
      };
    }
  }

  return { ok: true };
}

// ─── Helpers (git plumbing + glob matching) ────────────────────────

/**
 * Module-local git wrapper. Uses `execFileSync` against `process.cwd()` —
 * pre-receive's cwd is the bare repo (default for git hooks); PR-mode
 * chdirs into the operator's repo before invoking the pipeline. Both
 * positions work; callers that don't keep cwd inside a git repo with
 * the relevant commits will see "git ... failed" thrown errors here.
 */
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

/** Build the fingerprint → PEM map from `.stamp/trusted-keys/*.pub` at
 *  the given ref. Exported so PR-mode and pre-receive's PhaseInputV4
 *  construction both use the same shape (`buildPubkeyMap`'s readAtBase
 *  callback receives the FULL repo-relative path; do NOT double-prepend).
 *  See AGT-338 retro on the pubkey-wiring gotcha. */
export function readPubkeyMapAt(ref: string): Map<string, string> {
  let lsOut: string;
  try {
    lsOut = run(["ls-tree", "--name-only", ref, ".stamp/trusted-keys/"]);
  } catch {
    return new Map();
  }
  const names: string[] = [];
  for (const line of lsOut.split("\n")) {
    if (!line) continue;
    const prefix = ".stamp/trusted-keys/";
    const basename = line.startsWith(prefix) ? line.slice(prefix.length) : line;
    if (basename.endsWith(".pub")) names.push(basename);
  }
  return buildPubkeyMap(names, (relPath) => run(["show", `${ref}:${relPath}`]));
}

/** Read reviewer definitions from `.stamp/config.yml` at the given ref.
 *  Used by `verifyV4ApprovalSignatures` to re-derive prompt_sha256
 *  against the merge-base tree. */
export function readReviewerDefsAtRef(
  ref: string,
): Record<string, { prompt: string }> {
  let yaml: string;
  try {
    yaml = run(["show", `${ref}:.stamp/config.yml`]);
  } catch {
    return {};
  }
  const defs = readReviewersFromYaml(yaml);
  // readReviewersFromYaml returns the rich reviewer shape (prompt,
  // tools, mcp_servers, etc.); for v4 we only need the prompt path.
  const out: Record<string, { prompt: string }> = {};
  for (const [name, def] of Object.entries(defs)) {
    if (def && typeof def.prompt === "string") {
      out[name] = { prompt: def.prompt };
    }
  }
  return out;
}

/** List of files changed between base_sha and head_sha via
 *  `git diff -z --name-only base...head`. Returns `null` if the diff
 *  is unreadable (e.g. unknown SHA); callers should treat null as a
 *  hard error (something else has gone very wrong if base/head don't
 *  resolve — earlier phases would have caught that).
 *
 *  Uses `-z` (null-terminated output) rather than newline-terminated.
 *  Without `-z`, git's `core.quotePath` (default: true) wraps any
 *  filename containing non-ASCII bytes or shell-special characters
 *  in double quotes and C-escapes the bytes — so `.stamp/café.md`
 *  surfaces as `".stamp/caf\303\251.md"` and fails to match a
 *  `.stamp/**` rule. Per AGT-336 security review (round 1): not a
 *  practical bypass vector for the typical `.stamp/` layout, but
 *  cheap to harden against, and the alternative (raise `quotePath`
 *  to a config knob the verifier reads) would be more surface for
 *  less benefit. */
export function readChangedFilesAtRef(
  baseSha: string,
  headSha: string,
): string[] | null {
  let out: string;
  try {
    out = run(["diff", "-z", "--name-only", `${baseSha}...${headSha}`]);
  } catch {
    return null;
  }
  // -z output: null-byte-separated filenames. Final byte is also a
  // null (terminator), so a trailing empty element appears in the
  // split — filter it out alongside any other empties.
  return out.split("\0").filter((l) => l.length > 0);
}

/**
 * Path-glob → anchored regex. Distinct from `globToRegex` in
 * `lib/refPatterns.ts` because **paths** have hierarchy and conventional
 * path-glob syntax distinguishes `*` (anything except `/`) from `**`
 * (anything including `/`). The ref-glob equivalent collapses both into
 * a single dotstar, which is wrong for `.stamp/*` (would match
 * `.stamp/sub/file` — too permissive) and for `src/**.ts` (would over-
 * match across directories).
 *
 * Supported metacharacters:
 *   `**`  → `.*`   (any characters, including `/`)
 *   `*`   → `[^/]*`   (any characters, EXCLUDING `/`)
 *   `?`   → `[^/]`    (one character, excluding `/`)
 *
 * Everything else is regex-escaped, so `.` matches literal `.` and not
 * any-char. Translation order matters: `**` must translate before `*`
 * to avoid `**` collapsing into `[^/]*[^/]*`.
 *
 * No support for `{a,b}` alternation, character classes, or negation —
 * the small handful of patterns path_rules will exercise (`.stamp/**`,
 * `.github/workflows/*.yml`) don't need them, and a richer surface
 * means more ways for an operator to write a permissive rule by
 * accident.
 */
export function pathGlobToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const DOUBLE = "\x00DOUBLESTAR\x00";
  const translated = escaped
    .replace(/\*\*/g, DOUBLE)
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .split(DOUBLE)
    .join(".*");
  return new RegExp(`^${translated}$`);
}

/** True if `filePath` matches any pattern in `patterns` under path-glob
 *  semantics (see `pathGlobToRegex`). Empty list → false. */
export function pathMatchesAny(filePath: string, patterns: string[]): boolean {
  for (const p of patterns) {
    if (pathGlobToRegex(p).test(filePath)) return true;
  }
  return false;
}

// ─── path_rules YAML parse ─────────────────────────────────────────

/**
 * Result of parsing the `path_rules:` section. `warnings` contains
 * stderr-surfaceable messages for malformed rules; callers (pre-
 * receive's hook, verifyPr's loader) write each one to stderr so the
 * operator sees a visible signal on the first push after a bad config
 * deploy — matters because a silently-dropped `.stamp/**` rule is
 * exactly the misconfiguration an attacker would benefit from.
 *
 * Per AGT-336 security round 1: silent drops were flagged as an
 * operational security gap. A future `stamp config check` linter
 * remains the right home for structured pre-flight validation; this
 * stderr surface is the necessary interim measure.
 */
export interface ParsedPathRules {
  rules: PathRule[];
  warnings: string[];
}

/**
 * Parse the `path_rules:` section out of a parsed `.stamp/config.yml`.
 *
 * Spec form (per docs/plans/server-attested-reviews.md "Path rules"):
 *
 * ```yaml
 * path_rules:
 *   ".stamp/**":
 *     require_capability: admin
 *     minimum_signatures: 2
 *     bypass_review_cycle: true
 * ```
 *
 * Returns `{ rules, warnings }`. Empty `rules` when the section is
 * absent / malformed at the top level — the verifier treats "no
 * path_rules" identically to "path_rules: {}", which is the safe-by-
 * default posture (no gate, but also no false-positive rejection of
 * well-formed envelopes from repos that haven't adopted path_rules
 * yet).
 *
 * Per-rule, we drop entries with missing required fields or wrong
 * types BUT emit a `warnings` entry naming the offending field. The
 * caller writes each warning to stderr.
 */
export function parsePathRules(raw: unknown): ParsedPathRules {
  if (raw === undefined || raw === null) return { rules: [], warnings: [] };
  if (typeof raw !== "object" || Array.isArray(raw)) {
    return {
      rules: [],
      warnings: [
        `path_rules: top-level value must be a YAML map (e.g. \`".stamp/**": { ... }\`). Got ${Array.isArray(raw) ? "an array" : typeof raw}; entire path_rules section ignored.`,
      ],
    };
  }
  const out: PathRule[] = [];
  const warnings: string[] = [];
  for (const [pattern, rule] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof pattern !== "string" || pattern.length === 0) {
      warnings.push(`path_rules: empty or non-string pattern key skipped.`);
      continue;
    }
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
      warnings.push(
        `path_rules["${pattern}"]: rule body must be a YAML map with require_capability/minimum_signatures/bypass_review_cycle fields. Rule ignored — the path is NOT gated.`,
      );
      continue;
    }
    const r = rule as Record<string, unknown>;
    if (typeof r.require_capability !== "string" || r.require_capability.length === 0) {
      warnings.push(
        `path_rules["${pattern}"]: require_capability must be a non-empty string (e.g. \`admin\`). Got ${typeof r.require_capability}; rule ignored — the path is NOT gated.`,
      );
      continue;
    }
    if (
      typeof r.minimum_signatures !== "number" ||
      !Number.isInteger(r.minimum_signatures) ||
      r.minimum_signatures < 1
    ) {
      warnings.push(
        `path_rules["${pattern}"]: minimum_signatures must be a positive integer (got ${JSON.stringify(r.minimum_signatures)}). Rule ignored — the path is NOT gated.`,
      );
      continue;
    }
    if (typeof r.bypass_review_cycle !== "boolean") {
      warnings.push(
        `path_rules["${pattern}"]: bypass_review_cycle must be a YAML boolean (true or false; YAML's \`yes\`/\`no\`/\`on\`/\`off\` are NOT parsed as booleans here). Got ${JSON.stringify(r.bypass_review_cycle)}; rule ignored — the path is NOT gated.`,
      );
      continue;
    }
    out.push({
      pattern,
      require_capability: r.require_capability,
      minimum_signatures: r.minimum_signatures,
      bypass_review_cycle: r.bypass_review_cycle,
    });
  }
  // Sort by pattern for deterministic iteration / stable error messages.
  out.sort((a, b) => (a.pattern < b.pattern ? -1 : a.pattern > b.pattern ? 1 : 0));
  return { rules: out, warnings };
}
