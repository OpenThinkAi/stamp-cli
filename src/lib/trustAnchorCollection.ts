/**
 * Shared admin trust-anchor signature collection (AGT-337 / AGT-355 / WS1).
 *
 * Both `stamp merge` (commit-trailer / v4 envelope) and `stamp attest`
 * (v3 PR-attestation envelope) need to read admin counter-signatures
 * from `refs/notes/stamp-trust-anchor-sigs`, verify each against the
 * canonical signing target, and enforce the path_rules thresholds at
 * base_sha. Both call sites converge on the SAME signing-bytes via
 * `trustAnchorSigningBytes`, so the producer-side collector belongs in
 * one place — the merge-only copy that lived in `src/commands/merge.ts`
 * locked PR-mode out of `.stamp/**` diffs (the hardcoded
 * `trust_anchor_signatures: []` gap documented at AGT-355).
 *
 * The verifier (`src/lib/v4Trust.ts`) is untouched and still treats v3
 * PR-mode and v4 commit-trailer envelopes identically: it casts the v3
 * envelope to the embedded v4 payload view, then runs the same
 * `verifyV4TrustAnchorSignatures` / `verifyV4StampPathsGuard` phases.
 * Collection is the only side that diverged; this module makes it
 * converge again.
 */

import { parse as parseYaml } from "yaml";
import type {
  ApprovalEntryV4,
  CheckAttestationV4,
  TrustAnchorSignatureV4,
} from "./attestationV4.js";
import { showAtRef } from "./git.js";
import { verifyBytes } from "./signing.js";
import { listChangedFiles, readNote, TRUST_ANCHOR_NOTES_REF } from "./trustAnchorNotes.js";
import { trustAnchorSigningBytes } from "./trustAnchorPayload.js";
import {
  resolveCapability,
  type Capability,
  type TrustedKeysManifest,
} from "./trustedKeysManifest.js";
import { parsePathRules } from "./v4Trust.js";

/**
 * Inputs to the collector. Object-shaped (not positional) because the
 * call sites are 12-field-wide and positional args silently degrade
 * under future field additions.
 *
 * - `repoRoot`, `baseSha`, `headSha`, `targetBranch`: identify the
 *   feature branch being attested / merged.
 * - `diffSha256`, `manifestSnapshotSha256`, `approvals`, `checks`,
 *   `operatorFingerprint`: all factors of the v4-payload bytes
 *   (admins sign exactly the same target via `stamp admin sign`).
 *   `checks` is `[]` for PR-mode (file-level comment in attest.ts
 *   explains why); merge passes its real pre-merge check results.
 * - `manifest`, `pubkeyByFingerprint`: trust artifacts at base_sha,
 *   already resolved by the caller. Sharing them avoids re-parsing
 *   the manifest the caller has just parsed.
 *
 * Caller's command-mode goes in `errorContext` so error strings name
 * the right command in their recovery hints ("re-run `stamp merge`"
 * vs. "re-run `stamp attest`").
 */
export interface CollectTrustAnchorSignaturesInput {
  repoRoot: string;
  baseSha: string;
  headSha: string;
  targetBranch: string;
  diffSha256: string;
  manifestSnapshotSha256: string;
  approvals: ApprovalEntryV4[];
  checks: CheckAttestationV4[];
  operatorFingerprint: string;
  manifest: TrustedKeysManifest;
  pubkeyByFingerprint: Map<string, string>;
  /** Producer command label, woven into recovery hints. Defaults to
   *  `stamp merge` to preserve the historical merge-only message
   *  wording. */
  errorContext?: { command: string };
  /** schema_version to bake into the signing-target bytes. Defaults
   *  to the v4 commit-trailer's `CURRENT_V4_SCHEMA_VERSION` (the
   *  historical behavior). PR-mode callers MUST pass
   *  `PR_ATTESTATION_SCHEMA_VERSION` so the bytes match what the
   *  v3 PR-mode verifier reconstructs from the wire envelope. See
   *  `src/lib/trustAnchorPayload.ts`'s `schemaVersion` field doc for
   *  the full rationale. */
  signingSchemaVersion?: number;
}

/**
 * Read the collected admin signatures from the trust-anchor notes-ref
 * and assemble the verified subset for the v4/v3 envelope.
 *
 * Inputs reconstruct the signing target — the same canonical bytes the
 * pre-receive verifier (`verifyV4TrustAnchorSignatures`) will check
 * against on push. Verifying here means we (a) reject stale notes whose
 * signatures don't match the fresh payload, and (b) refuse to land a
 * merge/attestation the server would reject, surfacing the failure on
 * the operator's machine with a clean recovery path.
 *
 * Path-rule discovery uses path_rules at base_sha (matching the
 * verifier's snapshot semantics). If no rule matches the diff, we
 * return [] and short-circuit — the diff isn't gated by `path_rules`,
 * the verifier won't require sigs, and a stale note from a previous
 * iteration doesn't get folded in.
 */
export function collectTrustAnchorSignatures(
  input: CollectTrustAnchorSignaturesInput,
): TrustAnchorSignatureV4[] {
  const command = input.errorContext?.command ?? "stamp merge";

  // Read path_rules at base_sha. If none configured or none match the
  // diff, the verifier's `verifyV4StampPathsGuard` won't require sigs;
  // emit an empty list and skip both the note read and the gate check.
  // This preserves back-compat for repos pre-path_rules.
  let configYaml: string;
  try {
    configYaml = showAtRef(input.baseSha, ".stamp/config.yml", input.repoRoot);
  } catch {
    // No config at base — caller's earlier phases would already have
    // failed. Defensive: treat as no path_rules.
    return [];
  }
  let parsedYaml: unknown;
  try {
    parsedYaml = parseYaml(configYaml);
  } catch {
    return [];
  }
  if (!parsedYaml || typeof parsedYaml !== "object") return [];
  const rawPathRules = (parsedYaml as { path_rules?: unknown }).path_rules;
  const { rules: pathRules } = parsePathRules(rawPathRules);
  if (pathRules.length === 0) return [];

  // Enumerate changed files and find matching rules.
  const changedFiles = listChangedFiles(
    input.repoRoot,
    input.baseSha,
    input.headSha,
  );
  if (!changedFiles) return [];
  const matchingRules = pathRules.filter((r) =>
    changedFiles.some((f) => pathRuleMatches(f, r.pattern)),
  );
  if (matchingRules.length === 0) return [];

  // Read the note keyed by the feature-branch head SHA — that's where
  // `stamp admin sign --pending <head>` deposited the signatures.
  const note = readNote(input.repoRoot, input.headSha);
  if (!note || note.signatures.length === 0) {
    // No notes, but rules require sigs. Fail loudly with the most
    // demanding rule's threshold.
    const worst = matchingRules.reduce(
      (max, r) => (r.minimum_signatures > max.minimum_signatures ? r : max),
      matchingRules[0]!,
    );
    throw new Error(
      `path_rules["${worst.pattern}"] requires ${worst.minimum_signatures} admin signature(s) with capability '${worst.require_capability}', ` +
        `but no signatures are recorded on ${TRUST_ANCHOR_NOTES_REF} for ${input.headSha.slice(0, 12)}. ` +
        `Collect them with \`stamp admin sign --pending ${input.headSha.slice(0, 12)}\` (run by each admin), ` +
        `then re-run \`${command}\`.`,
    );
  }

  // Re-derive the signing target the SAME way `stamp admin sign` did:
  // the v4 payload with `trust_anchor_signatures: []`. Both call sites
  // MUST go through `trustAnchorSigningBytes` so any future field
  // addition propagates to both producers atomically.
  const signingTarget = trustAnchorSigningBytes({
    baseSha: input.baseSha,
    headSha: input.headSha,
    targetBranch: input.targetBranch,
    diffSha256: input.diffSha256,
    manifestSnapshotSha256: input.manifestSnapshotSha256,
    approvals: input.approvals,
    checks: input.checks,
    signerKeyId: input.operatorFingerprint,
    ...(input.signingSchemaVersion !== undefined
      ? { schemaVersion: input.signingSchemaVersion }
      : {}),
  });

  const verified: TrustAnchorSignatureV4[] = [];
  const failures: string[] = [];
  const seen = new Set<string>();
  for (const sig of note.signatures) {
    if (seen.has(sig.signer_key_id)) continue;
    seen.add(sig.signer_key_id);

    const caps = resolveCapability(input.manifest, sig.signer_key_id);
    if (caps === null) {
      failures.push(
        `${sig.signer_key_id} not in manifest at base ${input.baseSha.slice(0, 8)}`,
      );
      continue;
    }
    if (!caps.includes("admin")) {
      failures.push(
        `${sig.signer_key_id} lacks 'admin' capability (has [${caps.join(", ")}])`,
      );
      continue;
    }
    const pem = input.pubkeyByFingerprint.get(sig.signer_key_id);
    if (!pem) {
      failures.push(`no .pub file at base for ${sig.signer_key_id}`);
      continue;
    }
    let ok = false;
    try {
      ok = verifyBytes(pem, signingTarget, sig.signature);
    } catch {
      ok = false;
    }
    if (!ok) {
      failures.push(
        `signature by ${sig.signer_key_id} does not verify against the current payload (stale — re-sign after refresh)`,
      );
      continue;
    }
    verified.push({
      signer_key_id: sig.signer_key_id,
      signature: sig.signature,
    });
  }

  // Per-rule threshold check: count verified sigs with the rule's
  // required capability. Same logic as `verifyV4StampPathsGuard`,
  // applied here so a too-low count surfaces at producer time with a
  // clean operator message rather than via a pre-receive rejection.
  for (const rule of matchingRules) {
    let qualifying = 0;
    for (const sig of verified) {
      const caps = resolveCapability(input.manifest, sig.signer_key_id);
      if (caps !== null && caps.includes(rule.require_capability as Capability)) {
        qualifying++;
      }
    }
    if (qualifying < rule.minimum_signatures) {
      const failSummary =
        failures.length > 0
          ? ` Note signatures rejected: ${failures.join("; ")}.`
          : "";
      throw new Error(
        `path_rules["${rule.pattern}"] requires ${rule.minimum_signatures} admin signature(s) with capability '${rule.require_capability}', ` +
          `but only ${qualifying} verifying signature(s) are present on ${TRUST_ANCHOR_NOTES_REF} for ${input.headSha.slice(0, 12)}.${failSummary} ` +
          `Collect more with \`stamp admin sign --pending ${input.headSha.slice(0, 12)}\` (and have admins re-sign if previously stale), then re-run \`${command}\`.`,
      );
    }
  }

  return verified;
}

/** Local copy of the verifier's path-glob → regex semantics. Kept
 *  in this module rather than importing the verifier's private helper —
 *  smaller surface area than restructuring the hook for export. Must
 *  stay byte-identical to `pathMatchesAny` in v4Trust.ts. */
function pathRuleMatches(filePath: string, pattern: string): boolean {
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
  return new RegExp(`^${translated}$`).test(filePath);
}
