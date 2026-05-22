/**
 * Shape 4 migration-bootstrap support (AGT-398).
 *
 * Every existing repo migrating to Shape 4 (server-attested without code
 * transfer) hits a deadlock: the migration PR adds `review_server` + a
 * `[server]`-capability trust-anchor entry to `.stamp/**`. `stamp review`
 * sources config from `base_sha` (a security boundary — a feature branch
 * cannot unilaterally point at an attacker-controlled review server),
 * which doesn't yet have `review_server`, so review runs LOCALLY and the
 * DB carries no server signatures. `stamp attest` then sources config
 * from the working tree, sees `review_server`, and demands a v3 envelope
 * with the server signatures it cannot produce. The v2 fallback is
 * rejected by `MIN_ACCEPTED_PR_ATTESTATION_VERSION = 3`. `path_rules`
 * `.stamp/**` `bypass_review_cycle: true` doesn't help — it bypasses the
 * reviewer-cycle gate, but the schema-floor check downstream still fires.
 *
 * Shape 2 migrations dodge this by going through the 1.x bridge; Shape 4
 * didn't exist in 1.x so there's no equivalent fallback. Without this
 * module every Shape 4 migration of an existing repo deadlocks.
 *
 * --- The bootstrap flow ---
 *
 * `stamp attest --migrate-existing` produces a v3-shaped envelope with
 *   - `server_signatures` empty
 *   - a NEW operator-signed `migration_bootstrap` field naming the paths
 *     activated by this PR (e.g. `[".stamp/config.yml",
 *     ".stamp/trusted-keys/manifest.yml",
 *     ".stamp/trusted-keys/<server-fp>.pub"]`)
 *   - exactly one entry in `trust_anchor_signatures`: an admin-capability
 *     signature over the bootstrap-specific signing bytes (the payload
 *     with `trust_anchor_signatures: []`, including the bootstrap marker)
 *
 * The flag is REFUSED on any diff that isn't a narrow Shape-4-activation:
 *   - adds `review_server:` to a branch rule in `.stamp/config.yml`
 *   - adds (not modifies) entries in `.stamp/trusted-keys/manifest.yml`
 *     with `[server]` capability and `role_source: server`
 *   - adds (not modifies) corresponding `*.pub` files under
 *     `.stamp/trusted-keys/`
 *   - optionally adjusts the `reviewers:` block from prompt-paths form to
 *     `{}` form (the Shape 4 cleanup) — see `validateShape4ActivationDiff`
 *
 * --- Trust model ---
 *
 * The bootstrap envelope is accepted by the verifier only when ALL of:
 *   1. The marker is present in the operator-signed bytes (so a
 *      non-bootstrap envelope can't claim bootstrap status by tampering).
 *   2. The operator signature over the payload (including the marker)
 *      verifies.
 *   3. An admin-capability signature in `trust_anchor_signatures`
 *      verifies and the admin holds `admin` per the manifest at
 *      `base_sha`.
 *   4. `path_rules` at base covers every touched path with
 *      `bypass_review_cycle: true`.
 *   5. The diff matches the Shape-4-activation whitelist — re-validated
 *      at verify time, NOT trusted from attest-time alone.
 *
 * Empty `server_signatures` is OK ONLY when the bootstrap marker is
 * present. Non-bootstrap envelopes with empty `server_signatures`
 * continue to be rejected.
 *
 * --- Why a marker in the operator-signed bytes (not a trailer) ---
 *
 * The marker must be SIGNED so a non-bootstrap envelope cannot retro-fit
 * itself into the bootstrap-acceptance path by tampering. Placing it in
 * the same JSON payload `serializePayload` covers (the operator's outer
 * signature target) means the operator's signature commits to "this is a
 * bootstrap envelope" and the verifier can dispatch on the marker safely
 * without an additional signature surface.
 */

import { spawnSync } from "node:child_process";
import { canonicalSerializePayload, type AttestationPayloadV4 } from "./attestationV4.js";
import { parse as parseYaml } from "yaml";

/** Carried on a v3 PR-attestation payload to signal "this is a Shape 4
 *  migration-bootstrap envelope". When set, the verifier accepts an empty
 *  `approvals` / no server signatures under the additional gates
 *  documented above. */
export interface MigrationBootstrapMarker {
  /** Sorted, repo-relative paths the bootstrap PR activates. Every entry
   *  MUST be under `.stamp/**`, MUST match the Shape-4-activation
   *  whitelist at both attest and verify time, AND MUST equal the actual
   *  set of changed files between base and head. The verifier
   *  re-computes the actual diff and compares; a mismatch rejects. */
  activated_paths: string[];
}

/**
 * Outcome of a whitelist check on a diff. The whitelist permits
 * exclusively the narrow set of changes that constitutes a Shape 4
 * activation (see module docstring). Anything outside the whitelist
 * rejects with a specific `reason`.
 */
export type Shape4ValidationResult =
  | { ok: true; activatedPaths: string[] }
  | { ok: false; reason: string };

/** Inputs to `validateShape4ActivationDiff`. The caller (attest at
 *  attest time, verifyPr at verify time) supplies repo-root + the base
 *  + head SHAs; this module shells out to git for the file content via
 *  `git show`. We deliberately do NOT take pre-read content as a
 *  parameter because the verifier MUST be able to re-derive bytes from
 *  the merge-base + head trees independently — trusting attest-side
 *  content would defeat the re-validation property the ticket calls
 *  out as load-bearing. */
export interface Shape4ValidationInput {
  repoRoot: string;
  baseSha: string;
  headSha: string;
}

/**
 * Validate a diff against the Shape 4 activation whitelist.
 *
 * Allowed changes (and ONLY these):
 *   - `.stamp/config.yml`: ADDS `review_server:` to a branch rule.
 *     Optionally MAY also adjust the `reviewers:` block from prompt-paths
 *     form to `{}` form (the Shape 4 cleanup change) — see below for
 *     the strict definition of "cleanup".
 *   - `.stamp/trusted-keys/manifest.yml`: ADDS (not modifies) entries
 *     carrying `[server]` capability AND `role_source: server`. Existing
 *     entries MUST NOT be modified or removed.
 *   - `.stamp/trusted-keys/<fingerprint>.pub`: ADDED (not modified) `*.pub`
 *     files. Removal or modification of an existing pubkey is refused.
 *
 * Any file outside `.stamp/**` rejects. Any modification (vs addition) of
 * an existing manifest entry or pubkey rejects. Any branch-rule change
 * other than the `review_server:` addition rejects. The "cleanup" path
 * for `reviewers:` is GUARDED — see `isPermittedConfigChange` — so an
 * attacker cannot smuggle prompt-path manipulation through this surface.
 *
 * Returns `{ ok: true, activatedPaths }` on success, with paths sorted.
 * The caller writes these into `migration_bootstrap.activated_paths`.
 */
export function validateShape4ActivationDiff(
  input: Shape4ValidationInput,
): Shape4ValidationResult {
  const { repoRoot, baseSha, headSha } = input;

  const changedFilesResult = spawnSync(
    "git",
    ["diff", "-z", "--name-status", `${baseSha}...${headSha}`],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (changedFilesResult.status !== 0) {
    return {
      ok: false,
      reason:
        `could not enumerate diff between ${baseSha.slice(0, 8)} and ` +
        `${headSha.slice(0, 8)}: ${(changedFilesResult.stderr ?? "").trim()}`,
    };
  }

  // -z + --name-status output: tokens are NUL-separated. A non-rename
  // entry is two tokens (`<status>` then `<path>`); a rename/copy entry
  // is three tokens (`R<score>` or `C<score>`, then `<from>`, then
  // `<to>`). We deliberately reject any rename/copy outright — Shape 4
  // activation should never need one and accepting them would expand
  // the surface.
  const tokens = (changedFilesResult.stdout ?? "").split("\0").filter((s) => s.length > 0);
  const entries: { status: string; path: string }[] = [];
  for (let i = 0; i < tokens.length; ) {
    const status = tokens[i]!;
    if (/^[RC]\d*$/.test(status)) {
      return {
        ok: false,
        reason: `bootstrap diff contains a rename/copy change (status "${status}") — only add/modify is permitted in a Shape 4 activation`,
      };
    }
    const path = tokens[i + 1];
    if (path === undefined) {
      return {
        ok: false,
        reason: `bootstrap diff: malformed git output (status "${status}" with no path)`,
      };
    }
    entries.push({ status, path });
    i += 2;
  }

  if (entries.length === 0) {
    return {
      ok: false,
      reason: "bootstrap diff is empty — nothing to activate",
    };
  }

  // Every touched path MUST be under `.stamp/`. The narrow surface is the
  // whole point of the bootstrap flag.
  for (const e of entries) {
    if (!e.path.startsWith(".stamp/")) {
      return {
        ok: false,
        reason: `bootstrap diff touches "${e.path}" outside .stamp/ — the bootstrap flag accepts only Shape-4-activation changes under .stamp/**. Use the normal flow for non-bootstrap changes.`,
      };
    }
  }

  // Per-path validation. We allow exactly four classes:
  //   - .stamp/config.yml (modify-only; M)
  //   - .stamp/trusted-keys/manifest.yml (modify-only; M)
  //   - .stamp/trusted-keys/*.pub (add-only; A)
  //   - .stamp/reviewers/*.md (delete-only; D) — Shape 4 ditches the
  //     in-repo prompt copies; the server is the canonical source.
  let sawReviewServerAdd = false;
  for (const e of entries) {
    if (
      e.path.startsWith(".stamp/reviewers/") &&
      e.path.endsWith(".md")
    ) {
      if (e.status !== "D") {
        return {
          ok: false,
          reason: `bootstrap diff modifies or adds "${e.path}" (status "${e.status}") — the bootstrap flag only permits deleting .stamp/reviewers/*.md files in this directory (Shape 4 retires in-repo prompts), not modifying or adding them.`,
        };
      }
      continue;
    }
    if (e.path === ".stamp/config.yml") {
      if (e.status !== "M" && e.status !== "A") {
        return {
          ok: false,
          reason: `bootstrap diff has unexpected status "${e.status}" on .stamp/config.yml — only modification (M) or initial add (A) is permitted`,
        };
      }
      const cfgResult = validateConfigYamlChange({
        repoRoot,
        baseSha,
        headSha,
        statusAdd: e.status === "A",
      });
      if (!cfgResult.ok) return cfgResult;
      sawReviewServerAdd = sawReviewServerAdd || cfgResult.activatesReviewServer;
      continue;
    }
    if (e.path === ".stamp/trusted-keys/manifest.yml") {
      if (e.status !== "M" && e.status !== "A") {
        return {
          ok: false,
          reason: `bootstrap diff has unexpected status "${e.status}" on .stamp/trusted-keys/manifest.yml — only modification (M) or initial add (A) is permitted`,
        };
      }
      const manifestResult = validateManifestChange({
        repoRoot,
        baseSha,
        headSha,
        statusAdd: e.status === "A",
      });
      if (!manifestResult.ok) return manifestResult;
      continue;
    }
    if (
      e.path.startsWith(".stamp/trusted-keys/") &&
      e.path.endsWith(".pub")
    ) {
      if (e.status !== "A") {
        return {
          ok: false,
          reason: `bootstrap diff modifies or removes "${e.path}" (status "${e.status}") — the bootstrap flag only permits adding new .pub files, never modifying or removing existing ones`,
        };
      }
      continue;
    }
    return {
      ok: false,
      reason: `bootstrap diff touches "${e.path}" (status "${e.status}") which is not in the Shape-4-activation whitelist (.stamp/config.yml, .stamp/trusted-keys/manifest.yml, or new .stamp/trusted-keys/*.pub files)`,
    };
  }

  // The activation is meaningless without a review_server addition.
  // Refuse if no .stamp/config.yml change introduces one — a diff that
  // only adds keys without activating server-attested mode is not a
  // Shape 4 activation and should go through the normal flow.
  if (!sawReviewServerAdd) {
    return {
      ok: false,
      reason: `bootstrap diff does not add review_server: to any branch rule in .stamp/config.yml — a Shape 4 activation must add review_server. If your diff only adds trust-anchor keys, use the normal admin-sign flow.`,
    };
  }

  const activatedPaths = entries.map((e) => e.path).sort();
  return { ok: true, activatedPaths };
}

/** Verify the `.stamp/config.yml` change is exclusively a `review_server`
 *  addition (and optionally the Shape 4 reviewers-cleanup). Refuses any
 *  other diff. */
interface ConfigChangeResult {
  ok: boolean;
  reason?: string;
  activatesReviewServer: boolean;
}

function validateConfigYamlChange(args: {
  repoRoot: string;
  baseSha: string;
  headSha: string;
  statusAdd: boolean;
}): Shape4ValidationResult & { activatesReviewServer: boolean } {
  // Initial-add (status A) means the repo previously had no
  // .stamp/config.yml; this is not a Shape 4 activation of an EXISTING
  // repo — refuse. Operators bootstrapping a new repo go through
  // `stamp init`, not the bootstrap flag.
  if (args.statusAdd) {
    return {
      ok: false,
      reason: `.stamp/config.yml does not exist at base ${args.baseSha.slice(0, 8)} — the bootstrap flag is for activating Shape 4 on an existing stamp-gated repo, not for first-time stamp init`,
      activatesReviewServer: false,
    };
  }
  const baseYaml = readAtRef(args.repoRoot, args.baseSha, ".stamp/config.yml");
  const headYaml = readAtRef(args.repoRoot, args.headSha, ".stamp/config.yml");
  if (baseYaml === null || headYaml === null) {
    return {
      ok: false,
      reason: `.stamp/config.yml is unreadable at base ${args.baseSha.slice(0, 8)} or head ${args.headSha.slice(0, 8)}`,
      activatesReviewServer: false,
    };
  }
  let baseParsed: unknown;
  let headParsed: unknown;
  try {
    baseParsed = parseYaml(baseYaml);
    headParsed = parseYaml(headYaml);
  } catch (err) {
    return {
      ok: false,
      reason: `.stamp/config.yml parse error: ${err instanceof Error ? err.message : String(err)}`,
      activatesReviewServer: false,
    };
  }
  if (
    !baseParsed ||
    typeof baseParsed !== "object" ||
    Array.isArray(baseParsed) ||
    !headParsed ||
    typeof headParsed !== "object" ||
    Array.isArray(headParsed)
  ) {
    return {
      ok: false,
      reason: `.stamp/config.yml at base or head did not parse to an object`,
      activatesReviewServer: false,
    };
  }
  const baseObj = baseParsed as Record<string, unknown>;
  const headObj = headParsed as Record<string, unknown>;

  // Top-level: only `branches` and `reviewers` may differ. `path_rules`
  // and any other key must be byte-identical between base and head
  // (deep equality over parsed JSON; the parser already normalized YAML
  // formatting differences).
  const allowedDiffKeys = new Set(["branches", "reviewers"]);
  const allKeys = new Set([...Object.keys(baseObj), ...Object.keys(headObj)]);
  for (const k of allKeys) {
    if (allowedDiffKeys.has(k)) continue;
    if (!deepEqual(baseObj[k], headObj[k])) {
      return {
        ok: false,
        reason: `.stamp/config.yml: bootstrap diff modifies "${k}" outside the allowed (branches, reviewers) set — refused`,
        activatesReviewServer: false,
      };
    }
  }

  // Branches: each branch's rule may differ ONLY by adding `review_server`.
  // No other field of an existing branch may be added/removed/modified;
  // no branch entries may be added or removed wholesale.
  const baseBranches = (baseObj.branches as Record<string, unknown>) ?? {};
  const headBranches = (headObj.branches as Record<string, unknown>) ?? {};
  if (
    typeof baseBranches !== "object" ||
    baseBranches === null ||
    Array.isArray(baseBranches) ||
    typeof headBranches !== "object" ||
    headBranches === null ||
    Array.isArray(headBranches)
  ) {
    return {
      ok: false,
      reason: `.stamp/config.yml: branches must be objects at both base and head`,
      activatesReviewServer: false,
    };
  }
  const baseBranchKeys = Object.keys(baseBranches);
  const headBranchKeys = Object.keys(headBranches);
  if (
    baseBranchKeys.length !== headBranchKeys.length ||
    !baseBranchKeys.every((k) => headBranchKeys.includes(k))
  ) {
    return {
      ok: false,
      reason: `.stamp/config.yml: bootstrap diff adds or removes branch entries (base: [${baseBranchKeys.join(", ")}], head: [${headBranchKeys.join(", ")}]) — only review_server addition on existing branches is permitted`,
      activatesReviewServer: false,
    };
  }
  let anyBranchActivatesReviewServer = false;
  for (const name of baseBranchKeys) {
    const baseRule = baseBranches[name] as Record<string, unknown> | undefined;
    const headRule = headBranches[name] as Record<string, unknown> | undefined;
    if (!baseRule || !headRule) {
      return {
        ok: false,
        reason: `.stamp/config.yml: branch "${name}" is missing at base or head`,
        activatesReviewServer: false,
      };
    }
    if (Array.isArray(baseRule) || Array.isArray(headRule)) {
      return {
        ok: false,
        reason: `.stamp/config.yml: branch "${name}" must be an object`,
        activatesReviewServer: false,
      };
    }
    // Compute the symmetric difference. All keys in base must be in
    // head with byte-identical values (a removal is refused; a value
    // change is refused). All keys in head not in base must be exactly
    // `review_server` (the only legal addition).
    const baseKeys = Object.keys(baseRule);
    const headKeys = Object.keys(headRule);
    for (const k of baseKeys) {
      if (!(k in headRule)) {
        return {
          ok: false,
          reason: `.stamp/config.yml: branch "${name}" removes field "${k}" — bootstrap diff cannot remove branch-rule fields`,
          activatesReviewServer: false,
        };
      }
      if (!deepEqual(baseRule[k], headRule[k])) {
        return {
          ok: false,
          reason: `.stamp/config.yml: branch "${name}" modifies field "${k}" — bootstrap diff can only ADD review_server, not modify existing fields`,
          activatesReviewServer: false,
        };
      }
    }
    for (const k of headKeys) {
      if (k in baseRule) continue;
      if (k !== "review_server") {
        return {
          ok: false,
          reason: `.stamp/config.yml: branch "${name}" adds field "${k}" — bootstrap diff can only add "review_server"`,
          activatesReviewServer: false,
        };
      }
      // Sanity-check the new review_server is a plausible URL form.
      if (typeof headRule.review_server !== "string" || !headRule.review_server) {
        return {
          ok: false,
          reason: `.stamp/config.yml: branch "${name}".review_server must be a non-empty string`,
          activatesReviewServer: false,
        };
      }
      anyBranchActivatesReviewServer = true;
    }
  }

  // Reviewers: permit ONLY the Shape 4 cleanup change — base reviewers
  // map carries `{ prompt: "..." }` entries, head map carries `{}` for
  // the same reviewer names (server-bundled prompt mode). Any other
  // structural change (adding/removing reviewers, modifying tools or
  // mcp_servers, etc.) refuses. The strict definition: each reviewer
  // entry's HEAD shape must be either (a) byte-identical to its base
  // shape, or (b) an empty object `{}`. The set of reviewer NAMES must
  // be unchanged.
  const baseReviewers = (baseObj.reviewers as Record<string, unknown>) ?? {};
  const headReviewers = (headObj.reviewers as Record<string, unknown>) ?? {};
  if (
    typeof baseReviewers !== "object" ||
    baseReviewers === null ||
    Array.isArray(baseReviewers) ||
    typeof headReviewers !== "object" ||
    headReviewers === null ||
    Array.isArray(headReviewers)
  ) {
    return {
      ok: false,
      reason: `.stamp/config.yml: reviewers must be objects at both base and head`,
      activatesReviewServer: false,
    };
  }
  const baseRevKeys = Object.keys(baseReviewers).sort();
  const headRevKeys = Object.keys(headReviewers).sort();
  if (
    baseRevKeys.length !== headRevKeys.length ||
    !baseRevKeys.every((k, i) => k === headRevKeys[i])
  ) {
    return {
      ok: false,
      reason: `.stamp/config.yml: bootstrap diff adds or removes reviewer entries (base: [${baseRevKeys.join(", ")}], head: [${headRevKeys.join(", ")}]) — Shape 4 activation may only cleanup prompt paths, not add or remove reviewers`,
      activatesReviewServer: false,
    };
  }
  for (const name of baseRevKeys) {
    const baseRev = baseReviewers[name];
    const headRev = headReviewers[name];
    if (deepEqual(baseRev, headRev)) continue;
    // Allowed: head shape is `{}` (empty map) — the Shape 4 cleanup.
    if (
      headRev !== null &&
      typeof headRev === "object" &&
      !Array.isArray(headRev) &&
      Object.keys(headRev as Record<string, unknown>).length === 0
    ) {
      continue;
    }
    return {
      ok: false,
      reason: `.stamp/config.yml: reviewer "${name}" modified outside the Shape-4 cleanup pattern (HEAD must equal BASE or be {}); refused`,
      activatesReviewServer: false,
    };
  }

  return { ok: true, activatedPaths: [], activatesReviewServer: anyBranchActivatesReviewServer };
}

/** Verify the manifest change adds (only) `[server]`-capability entries
 *  with `role_source: server`, and never modifies or removes an existing
 *  entry. */
function validateManifestChange(args: {
  repoRoot: string;
  baseSha: string;
  headSha: string;
  statusAdd: boolean;
}): Shape4ValidationResult {
  const headYaml = readAtRef(args.repoRoot, args.headSha, ".stamp/trusted-keys/manifest.yml");
  if (headYaml === null) {
    return {
      ok: false,
      reason: `.stamp/trusted-keys/manifest.yml unreadable at head ${args.headSha.slice(0, 8)}`,
    };
  }
  let headParsed: unknown;
  try {
    headParsed = parseYaml(headYaml);
  } catch (err) {
    return {
      ok: false,
      reason: `.stamp/trusted-keys/manifest.yml parse error at head: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (
    !headParsed ||
    typeof headParsed !== "object" ||
    Array.isArray(headParsed) ||
    !(headParsed as { keys?: unknown }).keys ||
    typeof (headParsed as { keys: unknown }).keys !== "object"
  ) {
    return {
      ok: false,
      reason: `.stamp/trusted-keys/manifest.yml: missing or malformed top-level "keys" map at head`,
    };
  }
  const headKeys = (headParsed as { keys: Record<string, unknown> }).keys;

  // base may be missing (initial add — first time the manifest appears).
  let baseKeys: Record<string, unknown> = {};
  if (!args.statusAdd) {
    const baseYaml = readAtRef(args.repoRoot, args.baseSha, ".stamp/trusted-keys/manifest.yml");
    if (baseYaml === null) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml unreadable at base ${args.baseSha.slice(0, 8)}`,
      };
    }
    let baseParsed: unknown;
    try {
      baseParsed = parseYaml(baseYaml);
    } catch (err) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml parse error at base: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (
      !baseParsed ||
      typeof baseParsed !== "object" ||
      Array.isArray(baseParsed) ||
      !(baseParsed as { keys?: unknown }).keys ||
      typeof (baseParsed as { keys: unknown }).keys !== "object"
    ) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: missing or malformed top-level "keys" map at base`,
      };
    }
    baseKeys = (baseParsed as { keys: Record<string, unknown> }).keys;
  }

  // Every base entry must be byte-identical in head — no modifications,
  // no removals.
  for (const name of Object.keys(baseKeys)) {
    if (!(name in headKeys)) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: bootstrap diff removes entry "${name}" — refused (only additions of [server]+role_source:server entries are permitted)`,
      };
    }
    if (!deepEqual(baseKeys[name], headKeys[name])) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: bootstrap diff modifies existing entry "${name}" — refused (only additions are permitted)`,
      };
    }
  }

  // Every newly-added entry in head must carry [server] capability AND
  // role_source: server.
  for (const name of Object.keys(headKeys)) {
    if (name in baseKeys) continue;
    const entry = headKeys[name];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: new entry "${name}" is not a YAML object`,
      };
    }
    const e = entry as Record<string, unknown>;
    if (!Array.isArray(e.capabilities)) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: new entry "${name}" missing capabilities array`,
      };
    }
    const caps = e.capabilities.filter((c): c is string => typeof c === "string");
    // We DELIBERATELY require [server] as the ONLY capability on new
    // bootstrap entries — adding an [admin] or [operator] key through
    // this surface is outside the Shape 4 activation pattern and
    // belongs in a normal admin-sign flow.
    if (caps.length !== 1 || caps[0] !== "server") {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: new entry "${name}" has capabilities [${caps.join(", ")}] — bootstrap diff only permits adding entries with capabilities: [server] exactly`,
      };
    }
    if (e.role_source !== "server") {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: new entry "${name}" must have role_source: server (got ${JSON.stringify(e.role_source)}). This invariant flags entries auto-published by stamp-server.`,
      };
    }
    if (typeof e.fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(e.fingerprint)) {
      return {
        ok: false,
        reason: `.stamp/trusted-keys/manifest.yml: new entry "${name}" has invalid fingerprint`,
      };
    }
  }

  return { ok: true, activatedPaths: [] };
}

/** Build the canonical signing bytes for an admin's trust-anchor
 *  signature on a bootstrap envelope. Mirrors the existing v4
 *  trust-anchor signing-target convention — payload with
 *  `trust_anchor_signatures: []` — but ALSO includes the bootstrap
 *  marker in the payload so the admin's signature commits to the
 *  bootstrap intent (an admin sig collected for a non-bootstrap payload
 *  cannot be replayed onto a bootstrap envelope and vice-versa).
 *
 *  The v4 payload type does not have a `migration_bootstrap` field, so
 *  we inject it as an extra key. `canonicalSerializePayload` sorts keys
 *  deterministically, so the order doesn't matter; the key name is
 *  shared between attest and verify via `MIGRATION_BOOTSTRAP_KEY`.
 */
export const MIGRATION_BOOTSTRAP_KEY = "migration_bootstrap";

/** Bytes the admin signs over for a bootstrap envelope. The v4
 *  trust-anchor verifier replays this construction at verify time. */
export function bootstrapAdminSigningBytes(args: {
  payloadV4: AttestationPayloadV4;
  marker: MigrationBootstrapMarker;
}): Buffer {
  const augmented = {
    ...args.payloadV4,
    [MIGRATION_BOOTSTRAP_KEY]: args.marker,
    trust_anchor_signatures: [],
  } as AttestationPayloadV4 & { [MIGRATION_BOOTSTRAP_KEY]: MigrationBootstrapMarker };
  return canonicalSerializePayload(augmented);
}

// ─── helpers ───────────────────────────────────────────────────────

function readAtRef(repoRoot: string, ref: string, relPath: string): string | null {
  const result = spawnSync("git", ["show", `${ref}:${relPath}`], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) return null;
  return result.stdout ?? "";
}

/** Deep structural equality over JSON-compatible values. Object key
 *  order does NOT matter; array element order DOES matter. Used to
 *  compare base vs head sub-trees of `.stamp/config.yml`. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const aKeys = Object.keys(ao).sort();
  const bKeys = Object.keys(bo).sort();
  if (aKeys.length !== bKeys.length) return false;
  for (let i = 0; i < aKeys.length; i++) {
    if (aKeys[i] !== bKeys[i]) return false;
    if (!deepEqual(ao[aKeys[i]!], bo[bKeys[i]!])) return false;
  }
  return true;
}
