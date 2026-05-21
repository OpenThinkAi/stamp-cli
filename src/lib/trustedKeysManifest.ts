/**
 * Trusted-keys manifest: the YAML file that maps named keys to their
 * capabilities under the v4 server-attested-reviews trust model.
 *
 * Lives at `.stamp/trusted-keys/manifest.yml` alongside the existing
 * `.stamp/trusted-keys/*.pub` pubkey files (which the manifest references
 * by fingerprint, not filename). This module ONLY parses and hashes the
 * manifest — it does not load pubkeys, verify signatures, or enforce
 * capability checks at gate time. Downstream code in M4 (the pre-receive
 * hook + verifier) consumes `resolveCapability` to decide whether a
 * signer is competent to attest to a given payload.
 *
 * The manifest hash is bound into the outer envelope of a v4/v5
 * attestation as `AttestationPayloadV4.manifest_snapshot_sha256`
 * (operator-signed; lifted from the per-approval slot in AGT-370). The
 * verifier uses it to implement lenient revocation: revoking a `server`
 * key by editing the manifest blocks FUTURE merges (their snapshot
 * hash references the post-revocation manifest) without retroactively
 * invalidating PAST merges (whose snapshot hash references the
 * manifest as it stood at attestation time).
 *
 * --- Schema (informal) ---
 *
 *   keys:
 *     <name>:                            # operator-chosen short name; unique
 *       fingerprint: sha256:<64-hex>     # same form as fingerprintFromPem()
 *       capabilities: [admin|operator|server, ...]
 *       role_source: server              # OPTIONAL; metadata only — flags
 *                                        # entries auto-published by
 *                                        # stamp-server (don't hand-edit)
 *
 * Capabilities are additive; a single human key may carry both `admin`
 * and `operator`. The capability vocabulary is small and CLOSED — unknown
 * capability strings reject at parse time so a typo can't silently
 * downgrade a key. Adding a new capability is an intentional schema bump
 * that needs verifier + writer co-changes.
 *
 * `role_source: server` is parsed and preserved (so a future
 * stamp-server can read it back) but carries NO semantic meaning here;
 * the v4 verifier reads `capabilities` only.
 *
 * --- Hash (snapshot) ---
 *
 * `snapshotSha256(manifest)` computes `sha256:<hex>` over the canonical
 * JSON serialization of the parsed manifest (NOT the raw YAML bytes).
 * Reasons for hashing the parsed form rather than the file bytes:
 *
 *   - YAML allows many byte-equivalent representations of the same data
 *     (key order, quoting style, trailing whitespace, comments). Hashing
 *     bytes would change the snapshot every time someone re-sorted keys
 *     or added a comment.
 *   - The verifier needs to recompute the snapshot from the manifest as
 *     committed in `.stamp/trusted-keys/manifest.yml` at `base_sha`. If
 *     the hash were over bytes, a benign reformat between attestation
 *     and verification would falsely invalidate the attestation.
 *   - The codebase already uses JSON-canonicalize-then-hash for
 *     reviewer/tool hashing (`src/lib/reviewerHash.ts`); using the same
 *     pattern here keeps one canonicalization story in the codebase.
 *
 * The canonical form sorts object keys recursively and sorts the
 * capabilities array (capabilities are a set, not a list) so equivalent
 * inputs hash identically.
 *
 * --- Worked example (from design.md "Trusted-keys manifest" section) ---
 *
 *   keys:
 *     alice:
 *       fingerprint: sha256:aaa...
 *       capabilities: [admin]
 *     bob:
 *       fingerprint: sha256:bbb...
 *       capabilities: [admin]
 *     agent-bot:
 *       fingerprint: sha256:ccc...
 *       capabilities: [operator]
 *     review-server-prod:
 *       fingerprint: sha256:ddd...
 *       capabilities: [server]
 *       role_source: server
 *
 * See `tests/trustedKeysManifest.test.ts` for the parsed shape + the
 * deterministic snapshot hash this example produces.
 */

import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";

/** Where the manifest lives, relative to repo root. Single source of
 *  truth for the path; downstream code (pre-receive hook, verifier,
 *  stamp-server's manifest publisher) imports this constant rather than
 *  hard-coding the string. */
export const MANIFEST_RELATIVE_PATH = ".stamp/trusted-keys/manifest.yml";

/** Closed capability vocabulary. Adding a new capability requires
 *  updating both the writer (so it can emit it) and the verifier (so it
 *  knows what to enforce), so we reject unknown strings at parse time. */
export type Capability = "admin" | "operator" | "server";

const KNOWN_CAPABILITIES: readonly Capability[] = ["admin", "operator", "server"];

/** Hard cap on the manifest's parsed YAML size. The verifier reads the
 *  manifest at `base_sha` from git history before validating anything,
 *  so an oversized blob could otherwise DoS the parse path. 256KB is
 *  generous — a manifest with thousands of keys still fits. */
export const MAX_MANIFEST_BYTES = 256 * 1024;

/** Maximum number of entries in a single manifest. Same DoS reasoning as
 *  MAX_MANIFEST_BYTES, applied post-parse. A real operator with
 *  thousands of trusted keys has bigger structural problems. */
export const MAX_MANIFEST_ENTRIES = 10_000;

/** Regex for the fingerprint shape produced by `fingerprintFromPem`. The
 *  manifest is hand-edited (or stamp-published) so we validate the shape
 *  to catch typos before they become opaque "key not found" errors at
 *  verify time. */
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/;

/** Allowed shape for the manifest entry `<name>` key. Operator-chosen so
 *  we're permissive: ASCII letters, digits, dashes, underscores, dots.
 *  The name is metadata — it's the FINGERPRINT that's load-bearing for
 *  capability resolution. */
const NAME_PATTERN = /^[A-Za-z0-9_.-]+$/;

/** Parsed shape of a single key entry. `role_source` is preserved
 *  verbatim when present, but the only currently-meaningful value is
 *  `"server"`; future values are accepted and round-tripped so a newer
 *  stamp-server can publish richer metadata without an old client
 *  refusing the manifest. */
export interface TrustedKeyEntry {
  /** Operator-chosen short name. Unique within the manifest. */
  name: string;
  /** sha256:<64-hex>, matches the output of `fingerprintFromPem`. */
  fingerprint: string;
  /** Non-empty, deduplicated, sorted set of known capabilities. */
  capabilities: Capability[];
  /** Optional metadata flag. Preserved when present; not enforced. */
  role_source?: string;
}

export interface TrustedKeysManifest {
  /** Ordered by the name's lexicographic order so traversal is
   *  predictable; parse-time validation rejects duplicates. */
  entries: TrustedKeyEntry[];
}

/**
 * Parse a manifest's YAML bytes into a structured `TrustedKeysManifest`.
 * Strict: returns `null` on any of the following failure modes (the
 * verifier's job is to refuse, not to crash):
 *   - oversized input
 *   - YAML parse error
 *   - missing top-level `keys` object
 *   - empty `keys` object (an empty manifest is not a meaningful
 *     state; either the file shouldn't exist or it should have entries)
 *   - entry missing `fingerprint` or `capabilities`
 *   - malformed name, fingerprint, capability, or `role_source`
 *   - unknown capability string
 *   - empty capability list (a key with no capabilities is dead weight
 *     and likely a config error)
 *   - duplicate fingerprint across two different named entries (would
 *     create ambiguous capability resolution)
 *
 * `null` rather than throwing because every caller this is wired into
 * — the pre-receive hook, `stamp verify`, the snapshot hasher — needs
 * to surface its own error message with its own context. Throwing
 * would force every caller into try/catch boilerplate.
 */
export function parseManifest(yamlText: string): TrustedKeysManifest | null {
  if (typeof yamlText !== "string") return null;
  if (Buffer.byteLength(yamlText, "utf8") > MAX_MANIFEST_BYTES) return null;

  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const top = parsed as { keys?: unknown };
  const rawKeys = top.keys;
  if (!rawKeys || typeof rawKeys !== "object" || Array.isArray(rawKeys)) {
    return null;
  }

  const names = Object.keys(rawKeys as Record<string, unknown>);
  if (names.length === 0) return null;
  if (names.length > MAX_MANIFEST_ENTRIES) return null;

  const fingerprintsSeen = new Set<string>();
  const entries: TrustedKeyEntry[] = [];

  for (const name of names) {
    if (!NAME_PATTERN.test(name)) return null;

    const def = (rawKeys as Record<string, unknown>)[name];
    if (!def || typeof def !== "object" || Array.isArray(def)) return null;
    const d = def as Record<string, unknown>;

    if (typeof d.fingerprint !== "string") return null;
    if (!FINGERPRINT_PATTERN.test(d.fingerprint)) return null;
    if (fingerprintsSeen.has(d.fingerprint)) return null;
    fingerprintsSeen.add(d.fingerprint);

    if (!Array.isArray(d.capabilities)) return null;
    if (d.capabilities.length === 0) return null;
    const capSet = new Set<Capability>();
    for (const cap of d.capabilities) {
      if (typeof cap !== "string") return null;
      if (!isKnownCapability(cap)) return null;
      capSet.add(cap);
    }
    // Sort so equivalent inputs produce equal entries (and equal hashes).
    const capabilities = [...capSet].sort() as Capability[];

    let role_source: string | undefined;
    if (d.role_source !== undefined) {
      if (typeof d.role_source !== "string" || d.role_source.length === 0) {
        return null;
      }
      role_source = d.role_source;
    }

    entries.push({
      name,
      fingerprint: d.fingerprint,
      capabilities,
      ...(role_source !== undefined ? { role_source } : {}),
    });
  }

  // Sort by name for stable traversal + deterministic canonical
  // serialization downstream.
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  return { entries };
}

function isKnownCapability(s: string): s is Capability {
  return (KNOWN_CAPABILITIES as readonly string[]).includes(s);
}

/**
 * Produce the deterministic byte form used as input to the snapshot
 * hash. Two manifests with the same logical content (same names, same
 * fingerprints, same capability sets, same role_source values) MUST
 * serialize to the same bytes regardless of:
 *   - source YAML key order (parseManifest sorts entries by name)
 *   - capability ordering in the source (parseManifest sorts each set)
 *   - JS object key insertion order (we sort keys here too)
 *   - YAML quoting / comment / whitespace differences (we round-trip
 *     through the parsed shape)
 *
 * The canonical form is JSON, not YAML, for two reasons:
 *   - The codebase already uses JSON-canonicalize-then-hash for
 *     reviewer/tool/MCP hashing (`src/lib/reviewerHash.ts`); a second
 *     canonicalization regime would be a maintenance liability.
 *   - JSON has stricter, simpler determinism rules than YAML (no
 *     anchors, no tags, one number format, one string quoting). Easier
 *     to reason about cross-implementation byte equality if a future
 *     verifier ships in Go or Rust.
 *
 * Returns a `Buffer` (rather than a string) so the caller can feed it
 * directly to `crypto.createHash().update(...)` without an encoding
 * round-trip.
 */
export function serializeManifestCanonical(
  manifest: TrustedKeysManifest,
): Buffer {
  // Build the canonical structure with sorted entry-array (already
  // sorted by parseManifest, but we re-sort defensively in case a
  // caller constructed the manifest manually) and per-entry key
  // ordering: capabilities sorted, top-level keys in a fixed order.
  const sortedEntries = [...manifest.entries].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );

  // Use the object-of-names shape (matches the YAML schema) rather
  // than an array-of-entries shape, so a future reader can map the
  // canonical JSON 1:1 against the YAML if they want.
  const keys: Record<string, Record<string, unknown>> = {};
  for (const e of sortedEntries) {
    const entry: Record<string, unknown> = {
      capabilities: [...e.capabilities].sort(),
      fingerprint: e.fingerprint,
    };
    if (e.role_source !== undefined) {
      entry.role_source = e.role_source;
    }
    keys[e.name] = entry;
  }

  // Wrap so the canonical form mirrors the file's `keys:` top-level.
  const canonical = { keys };
  return Buffer.from(JSON.stringify(canonical), "utf8");
}

/**
 * `sha256:<hex>` of the canonical serialization of `manifest`. This is
 * the value bound into a v4/v5 attestation envelope as
 * `AttestationPayloadV4.manifest_snapshot_sha256` (AGT-370 — lifted
 * from the per-approval slot in v4). Matches the existing fingerprint
 * prefix convention so downstream code can treat all stamp hashes (key
 * fingerprints, manifest snapshots, future per-payload digests)
 * uniformly.
 */
export function snapshotSha256(manifest: TrustedKeysManifest): string {
  const bytes = serializeManifestCanonical(manifest);
  const hex = createHash("sha256").update(bytes).digest("hex");
  return `sha256:${hex}`;
}

/**
 * Serialize a manifest as human-readable YAML matching the documented
 * schema. Used by the admin rotation commands (`stamp admin add-key`,
 * `stamp admin revoke`) when mutating `.stamp/trusted-keys/manifest.yml`
 * in place.
 *
 * Determinism contract — TWO manifests with the same logical content
 * MUST produce byte-identical YAML:
 *   - entries sorted by name
 *   - capabilities sorted within each entry
 *   - field order within an entry: fingerprint, capabilities, role_source
 *   - flow-style capability arrays (`[admin, operator]`) so a diff
 *     stays single-line and matches the migration-guide style emitted
 *     by `migrateServerAttested.ts:serializeManifest`
 *   - single trailing newline (POSIX-clean)
 *
 * Round-trip contract — `parseManifest(serializeManifestYaml(m))` MUST
 * equal `m` for any `m` that itself came out of `parseManifest`, and the
 * snapshot hash MUST match. Tests in `trustedKeysManifest.test.ts`
 * enforce both invariants.
 *
 * We emit YAML by hand rather than going through `yaml`'s stringifier
 * for two reasons:
 *   - the shape is small and fixed; the hand-rolled form is easier to
 *     diff-review than the library's output (it's also what
 *     `migrateServerAttested.ts:serializeManifest` already does, so the
 *     codebase has one consistent hand-rolled style for manifest YAML)
 *   - the library doesn't guarantee deterministic field order across
 *     versions; hand-rolling pins the order, which matters because
 *     these files get diff-reviewed by humans
 */
export function serializeManifestYaml(manifest: TrustedKeysManifest): string {
  const sorted = [...manifest.entries].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  const lines: string[] = ["keys:"];
  for (const entry of sorted) {
    const capsSorted = [...entry.capabilities].sort();
    lines.push(`  ${entry.name}:`);
    lines.push(`    fingerprint: ${entry.fingerprint}`);
    lines.push(`    capabilities: [${capsSorted.join(", ")}]`);
    if (entry.role_source !== undefined) {
      // SECURITY: emit role_source double-quoted, with internal
      // double-quotes + backslashes escaped, so a `role_source` value
      // containing a newline or YAML metacharacter can't break the
      // surrounding YAML structure. The parser currently constrains
      // role_source to non-empty strings; if a future schema migration
      // widens the accepted values to include arbitrary tokens, this
      // guard keeps the writer safe without requiring a coordinated
      // change. Using YAML's standard escape grammar (double-quoted
      // scalars: `\\`, `\"`, `\n`) so the output stays YAML 1.2
      // compliant.
      const escaped = entry.role_source
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"')
        .replace(/\n/g, "\\n");
      lines.push(`    role_source: "${escaped}"`);
    }
  }
  return lines.join("\n") + "\n";
}

/**
 * Look up the capabilities for a given fingerprint. Returns `null` if
 * no entry in the manifest matches — distinct from `[]` (which
 * `parseManifest` rejects at parse time, so it's not a valid manifest
 * state anyway). The downstream verifier translates `null` into a
 * "signer not in manifest" error and `[]` is never returned.
 */
export function resolveCapability(
  manifest: TrustedKeysManifest,
  fingerprint: string,
): Capability[] | null {
  for (const entry of manifest.entries) {
    if (entry.fingerprint === fingerprint) {
      // Return a copy so callers can't mutate the manifest.
      return [...entry.capabilities];
    }
  }
  return null;
}
