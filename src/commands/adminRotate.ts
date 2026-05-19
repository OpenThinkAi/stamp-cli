/**
 * Admin key rotation tooling (AGT-348).
 *
 * Three sub-commands under the `stamp admin` group, each operating on
 * `.stamp/trusted-keys/manifest.yml` (and, for `add-key`, the sibling
 * `.stamp/trusted-keys/*.pub` files):
 *
 *   - `stamp admin add-key <pubkey-path> --name <name> --capabilities ...`
 *       Add a new trusted-keys entry. Copies the pubkey file alongside
 *       the manifest mutation so the verifier's
 *       `readTrustedKeysAt(base_sha)` lookup finds the PEM at merge
 *       time. Commits both files in one commit on the current branch.
 *
 *   - `stamp admin revoke <fingerprint>`
 *       Remove the manifest entry for the given fingerprint. We do NOT
 *       delete the on-disk `.pub` file — the verifier's snapshot model
 *       binds each attestation to the manifest at its base_sha (see the
 *       module docstring in `trustedKeysManifest.ts` for the
 *       lenient-revocation rationale), so the orphaned pub doesn't grant
 *       any future authority and removing it would create a separate
 *       commit churning a path that has no trust-anchor meaning.
 *
 *   - `stamp admin list-keys`
 *       Read-only: dump the manifest as a flat name + fingerprint +
 *       capabilities table. Does not commit, does not trigger anything.
 *
 * --- "Trigger the multi-sig collection flow" — what this means ---
 *
 * Per the AGT-348 scope clarification: the rotation commands do NOT
 * auto-invoke `runAdminSign`. Multi-admin collection is inherently
 * async (different admins, possibly different machines, definitely
 * different runs of the CLI). After committing, each command prints a
 * banner pointing the operator at:
 *
 *     stamp admin sign --pending <new-sha>
 *
 * and explains that the commit needs `minimum_signatures` admin counter-
 * signatures before `stamp merge` will accept it through the
 * `path_rules` gate. That's the "trigger" — surface the next step
 * clearly so the operator (or the second admin they coordinate with)
 * runs it explicitly. AGT-337 ships `runAdminSign` as the collection
 * primitive; AGT-348 is the producer of pending commits, not a
 * re-implementation of the collector.
 *
 * --- bypass_review_cycle UX warning ---
 *
 * `.stamp/**` mutations match a `path_rules` entry that typically
 * carries `bypass_review_cycle: true`, so the LLM reviewer gate does
 * NOT run on these commits. The commit goes straight to the
 * admin-signature gate. Operators familiar with the standard `stamp
 * review → merge → push` flow will see "0 reviewer verdicts" on the
 * commit and may worry. The banner output below explicitly calls this
 * out so the operator isn't confused — the bypass is by design, gated
 * by the admin counter-signature requirement instead of the reviewer
 * cycle.
 */

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fingerprintFromPem, publicKeyFingerprintFilename } from "../lib/keys.js";
import {
  findRepoRoot,
  stampTrustedKeysDir,
} from "../lib/paths.js";
import {
  MANIFEST_RELATIVE_PATH,
  parseManifest,
  serializeManifestYaml,
  type Capability,
  type TrustedKeyEntry,
  type TrustedKeysManifest,
} from "../lib/trustedKeysManifest.js";

/** Mirrors the parser's `NAME_PATTERN` — duplicated here so the writer
 *  rejects bad names early with a clear error rather than producing a
 *  manifest the parser would reject. (Keeping the duplicate is cheaper
 *  than exporting the pattern from the parser module just for this.) */
const NAME_PATTERN = /^[A-Za-z0-9_.-]+$/;

/** Same fingerprint shape as `fingerprintFromPem`. */
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/;

/** Closed capability vocabulary — duplicated from the parser for the
 *  same reason as `NAME_PATTERN`. Adding a new capability is a coordinated
 *  schema change; this list must stay in sync with `KNOWN_CAPABILITIES`
 *  in `trustedKeysManifest.ts`. */
const KNOWN_CAPABILITIES: readonly Capability[] = ["admin", "operator", "server"];

export interface AdminAddKeyOptions {
  /** Path to the `.pub` file to trust. */
  pubkeyPath: string;
  /** Short name for the manifest entry — must match `NAME_PATTERN`. */
  name: string;
  /** Comma-separated capability string from the CLI (`admin,operator`). */
  capabilities: string;
}

export interface AdminRevokeOptions {
  /** Fingerprint of the entry to remove (`sha256:<64-hex>`). */
  fingerprint: string;
}

export interface AdminListKeysOptions {
  /** When true, emit JSON instead of the human table. Useful for
   *  scripting against the manifest from operator tooling. */
  json?: boolean;
}

// ─── add-key ───────────────────────────────────────────────────────

export function runAdminAddKey(opts: AdminAddKeyOptions): void {
  const repoRoot = findRepoRoot();
  const manifestPath = join(repoRoot, MANIFEST_RELATIVE_PATH);
  const trustedDir = stampTrustedKeysDir(repoRoot);

  // Validate name shape BEFORE touching any files so the operator gets
  // the error immediately. (Parser would reject post-hoc but with a
  // less actionable message.)
  if (!NAME_PATTERN.test(opts.name)) {
    throw new Error(
      `--name ${JSON.stringify(opts.name)} is invalid. Names must match ${NAME_PATTERN} (ASCII letters, digits, '.', '-', '_').`,
    );
  }

  // Validate + normalize capabilities. Reject unknown strings at parse
  // time so a typo can't silently grant the wrong authority.
  const caps = parseCapabilitiesFlag(opts.capabilities);

  // Read pubkey from disk and compute fingerprint via the existing
  // helper. fingerprintFromPem throws on malformed PEM; we wrap to give
  // a path-aware message.
  if (!existsSync(opts.pubkeyPath)) {
    throw new Error(`pubkey file not found: ${opts.pubkeyPath}`);
  }
  const pem = readFileSync(opts.pubkeyPath, "utf8");

  // SECURITY: explicitly require a SPKI public-key PEM header before
  // we touch this file. Node's `createPublicKey()` — which
  // `fingerprintFromPem` calls under the hood — happily accepts PKCS8
  // PRIVATE key PEM and derives the public key from it; that means a
  // typo like `stamp admin add-key ~/.stamp/keys/ed25519` (pointing at
  // the private half) would silently succeed and then `copyFileSync`
  // below would commit the PRIVATE key file into .stamp/trusted-keys/.
  // Rejecting any input that doesn't carry the public-key armor closes
  // that path and stays correct even if `fingerprintFromPem`'s
  // implementation later changes.
  if (!pem.includes("-----BEGIN PUBLIC KEY-----")) {
    throw new Error(
      `${opts.pubkeyPath} does not look like a public key PEM ` +
        `(no "-----BEGIN PUBLIC KEY-----" header). Refusing to import — ` +
        `did you accidentally pass the private key path? ` +
        `Public keys live at ~/.stamp/keys/ed25519.pub (note the .pub suffix).`,
    );
  }

  let fingerprint: string;
  try {
    fingerprint = fingerprintFromPem(pem);
  } catch (err) {
    throw new Error(
      `${opts.pubkeyPath} is not a valid public key PEM: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  // Note: no defensive recheck of `fingerprint` shape — the parser
  // re-checks at the round-trip self-test below, and `fingerprintFromPem`
  // is the single source of truth for that shape across the codebase.

  // Read existing manifest. If the file is missing entirely the
  // operator is on a pre-manifest repo and the right answer is "run
  // `stamp init --migrate-to-server-attested` first"; we don't
  // bootstrap from empty here because that would silently create a
  // manifest with one entry and no admins, which the gate can't
  // unlock.
  if (!existsSync(manifestPath)) {
    throw new Error(
      `no manifest at ${MANIFEST_RELATIVE_PATH}. Run \`stamp init --migrate-to-server-attested\` to bootstrap one, then re-run \`stamp admin add-key\`.`,
    );
  }
  const existing = parseManifest(readFileSync(manifestPath, "utf8"));
  if (!existing) {
    throw new Error(
      `${MANIFEST_RELATIVE_PATH} failed to parse. Fix the file (see \`stamp admin list-keys\` for the current state) before adding a new key.`,
    );
  }

  // Refuse duplicate names AND duplicate fingerprints. The parser
  // already rejects both at re-parse time but the message would point
  // at the post-write state; surfacing here gives a cleaner error.
  for (const e of existing.entries) {
    if (e.name === opts.name) {
      throw new Error(
        `manifest already has an entry named ${JSON.stringify(opts.name)} (fingerprint ${e.fingerprint}). Pick a different --name, or run \`stamp admin revoke ${e.fingerprint}\` first.`,
      );
    }
    if (e.fingerprint === fingerprint) {
      throw new Error(
        `manifest already trusts ${fingerprint} as ${JSON.stringify(e.name)}. Capabilities can be edited by removing + re-adding, or by hand-editing ${MANIFEST_RELATIVE_PATH}.`,
      );
    }
  }

  const newEntry: TrustedKeyEntry = {
    name: opts.name,
    fingerprint,
    capabilities: caps,
  };
  // No pre-sort here — `serializeManifestYaml` re-sorts entries by
  // name internally (it has to, for callers that construct manifests
  // by hand). Sorting twice would be wasteful and would invite the
  // future-maintainer confusion of "which sort is authoritative".
  const updated: TrustedKeysManifest = {
    entries: [...existing.entries, newEntry],
  };
  const yamlText = serializeManifestYaml(updated);

  // Self-check: writing then re-parsing must round-trip to the same
  // logical manifest. Catches a writer bug at write time rather than
  // at verify time on someone else's machine.
  const reparsed = parseManifest(yamlText);
  if (!reparsed) {
    throw new Error(
      "internal error: serialized manifest failed to re-parse. Refusing to write a broken file. File a bug at https://github.com/OpenThinkAi/stamp-cli/issues.",
    );
  }

  // Write the manifest, then copy the pubkey into trusted-keys/ under
  // its canonical filename (sha256_<hex>.pub) — the verifier reads pubs
  // by enumerating .pub files and matching fingerprints, so the
  // filename matters less than the content, but we match the existing
  // `stamp keys trust` convention so `stamp keys list` output stays
  // tidy.
  writeFileSync(manifestPath, yamlText);
  const pubDestFilename = publicKeyFingerprintFilename(fingerprint);
  const pubDestPath = join(trustedDir, pubDestFilename);
  if (!existsSync(pubDestPath)) {
    copyFileSync(opts.pubkeyPath, pubDestPath);
  }
  // If the pub already exists with the right fingerprint (operator
  // previously ran `stamp keys trust` then forgot to update the
  // manifest), don't overwrite — we already verified the manifest
  // entry didn't exist above, so we're consolidating a half-done
  // trust action rather than clobbering anything.

  // Stage + commit both files in one commit.
  const relManifest = relative(repoRoot, manifestPath);
  const relPub = relative(repoRoot, pubDestPath);
  gitAdd(repoRoot, [relManifest, relPub]);
  const subject = `AGT-348: add admin key ${opts.name} (${fingerprint})`;
  const body = [
    `Adds entry to .stamp/trusted-keys/manifest.yml with capabilities ` +
      `[${caps.join(", ")}].`,
    ``,
    `Requires admin counter-signatures via \`stamp admin sign --pending <sha>\``,
    `before this commit can be merged through the path_rules gate.`,
  ].join("\n");
  const newSha = gitCommit(repoRoot, subject, body);

  printPostCommitBanner({
    action: "add-key",
    sha: newSha,
    name: opts.name,
    fingerprint,
    capabilities: caps,
  });
}

// ─── revoke ────────────────────────────────────────────────────────

export function runAdminRevoke(opts: AdminRevokeOptions): void {
  const repoRoot = findRepoRoot();
  const manifestPath = join(repoRoot, MANIFEST_RELATIVE_PATH);

  // Validate fingerprint shape up front. Catches `revoke abc123`-style
  // typos before any git state changes.
  if (!FINGERPRINT_PATTERN.test(opts.fingerprint)) {
    throw new Error(
      `fingerprint ${JSON.stringify(opts.fingerprint)} is not in the expected sha256:<64-hex> form. Run \`stamp admin list-keys\` to copy a fingerprint exactly.`,
    );
  }

  if (!existsSync(manifestPath)) {
    throw new Error(
      `no manifest at ${MANIFEST_RELATIVE_PATH} — nothing to revoke.`,
    );
  }
  const existing = parseManifest(readFileSync(manifestPath, "utf8"));
  if (!existing) {
    throw new Error(
      `${MANIFEST_RELATIVE_PATH} failed to parse. Fix the file before revoking.`,
    );
  }

  const target = existing.entries.find((e) => e.fingerprint === opts.fingerprint);
  if (!target) {
    throw new Error(
      `no entry in ${MANIFEST_RELATIVE_PATH} with fingerprint ${opts.fingerprint}. Run \`stamp admin list-keys\` to see what's currently trusted.`,
    );
  }

  // Refuse to revoke the last admin — the resulting manifest would
  // have no key able to satisfy `require_capability: admin` on the
  // path_rules gate, meaning ALL future `.stamp/**` changes (including
  // re-adding an admin) would be unmergeable. The operator can recover
  // by reverting the commit but it's a confusing failure mode; refuse
  // at write time with an actionable error.
  const remainingAdmins = existing.entries.filter(
    (e) => e.fingerprint !== opts.fingerprint && e.capabilities.includes("admin"),
  );
  if (target.capabilities.includes("admin") && remainingAdmins.length === 0) {
    throw new Error(
      `refusing to revoke the last admin key (${target.name} ${opts.fingerprint}). ` +
        `The .stamp/** path_rules gate would become unmergeable with zero admins remaining. ` +
        `Add a replacement admin first via \`stamp admin add-key\`, then revoke.`,
    );
  }

  const updated: TrustedKeysManifest = {
    entries: existing.entries.filter((e) => e.fingerprint !== opts.fingerprint),
  };
  // parseManifest rejects empty manifests, so a single-entry manifest
  // can't be fully drained either — but the last-admin check above
  // already catches the realistic shape of that case. Defense-in-depth
  // re-check here in case a future capability set allows it:
  if (updated.entries.length === 0) {
    throw new Error(
      `revoking ${opts.fingerprint} would leave an empty manifest, which the parser rejects. Add a replacement key before revoking.`,
    );
  }
  const yamlText = serializeManifestYaml(updated);
  const reparsed = parseManifest(yamlText);
  if (!reparsed) {
    throw new Error(
      "internal error: serialized manifest failed to re-parse. Refusing to write a broken file. File a bug at https://github.com/OpenThinkAi/stamp-cli/issues.",
    );
  }

  writeFileSync(manifestPath, yamlText);

  const relManifest = relative(repoRoot, manifestPath);
  gitAdd(repoRoot, [relManifest]);
  const subject = `AGT-348: revoke admin key ${target.name} (${opts.fingerprint})`;
  const body = [
    `Removes entry from .stamp/trusted-keys/manifest.yml.`,
    ``,
    `Requires admin counter-signatures via \`stamp admin sign --pending <sha>\``,
    `before this commit can be merged through the path_rules gate.`,
    ``,
    `Note: the on-disk .pub file under .stamp/trusted-keys/ is intentionally`,
    `left in place. Future attestations bind to the manifest at base_sha`,
    `(lenient revocation per the v4 design), so an orphaned pub grants no`,
    `authority. Remove the .pub manually if you want the tree to stay tidy.`,
  ].join("\n");
  const newSha = gitCommit(repoRoot, subject, body);

  printPostCommitBanner({
    action: "revoke",
    sha: newSha,
    name: target.name,
    fingerprint: opts.fingerprint,
    capabilities: target.capabilities,
  });
}

// ─── list-keys ─────────────────────────────────────────────────────

export function runAdminListKeys(opts: AdminListKeysOptions = {}): void {
  const repoRoot = findRepoRoot();
  const manifestPath = join(repoRoot, MANIFEST_RELATIVE_PATH);
  if (!existsSync(manifestPath)) {
    if (opts.json) {
      process.stdout.write(JSON.stringify({ entries: [] }, null, 2) + "\n");
      return;
    }
    console.log(`no manifest at ${MANIFEST_RELATIVE_PATH}.`);
    console.log(
      "Run `stamp init --migrate-to-server-attested` to bootstrap one for this repo.",
    );
    return;
  }
  const manifest = parseManifest(readFileSync(manifestPath, "utf8"));
  if (!manifest) {
    throw new Error(
      `${MANIFEST_RELATIVE_PATH} failed to parse. Fix the file by hand (see \`git show HEAD:${MANIFEST_RELATIVE_PATH}\` for the last good version) before continuing.`,
    );
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(manifest, null, 2) + "\n");
    return;
  }

  // NOTE — AGT-348 AC #4 asks for "last-rotated metadata" but the
  // current schema (parser + canonical hasher) has no last_rotated
  // field. Adding it is a schema bump that affects the snapshot hash
  // and needs backwards-compat handling for 2.0-alpha manifests — out
  // of scope for this ticket per the orchestrator's clarification.
  // Follow-up: file a separate ticket for rotation telemetry. The
  // listing below shows name / fingerprint / capabilities only.
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`trusted-keys manifest — ${manifest.entries.length} entr${manifest.entries.length === 1 ? "y" : "ies"}`);
  console.log(`  ${manifestPath}`);
  console.log(bar);
  for (const e of manifest.entries) {
    const caps = `[${e.capabilities.join(", ")}]`;
    const roleSrc = e.role_source ? `  role_source=${e.role_source}` : "";
    console.log(`  ${e.name}`);
    console.log(`    fingerprint:  ${e.fingerprint}`);
    console.log(`    capabilities: ${caps}${roleSrc}`);
  }
  console.log(bar);
}

// ─── shared helpers ────────────────────────────────────────────────

function parseCapabilitiesFlag(raw: string): Capability[] {
  // Accept comma-separated, tolerate whitespace, dedup, sort. Reject
  // unknown strings — caller already documents the closed vocabulary
  // in the --help text but we surface it again here for clarity when
  // someone fat-fingers `--capabilities admin,opperator`.
  const tokens = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (tokens.length === 0) {
    throw new Error(
      `--capabilities must list at least one of: ${KNOWN_CAPABILITIES.join(", ")} (got empty).`,
    );
  }
  const set = new Set<Capability>();
  for (const tok of tokens) {
    if (!isKnownCapability(tok)) {
      throw new Error(
        `--capabilities contains unknown capability ${JSON.stringify(tok)}. ` +
          `Known values: ${KNOWN_CAPABILITIES.join(", ")}.`,
      );
    }
    set.add(tok);
  }
  return [...set].sort() as Capability[];
}

function isKnownCapability(s: string): s is Capability {
  return (KNOWN_CAPABILITIES as readonly string[]).includes(s);
}

function gitAdd(repoRoot: string, paths: string[]): void {
  execFileSync("git", ["add", "--", ...paths], {
    cwd: repoRoot,
    stdio: ["ignore", "ignore", "pipe"],
  });
}

function gitCommit(repoRoot: string, subject: string, body: string): string {
  // Use -F - to stream the message via stdin: avoids tempfile churn
  // and sidesteps any shell-escape pitfalls with multi-line messages.
  const message = body ? `${subject}\n\n${body}\n` : `${subject}\n`;
  execFileSync("git", ["commit", "-q", "-F", "-"], {
    cwd: repoRoot,
    input: message,
    stdio: ["pipe", "ignore", "pipe"],
  });
  return execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

interface PostCommitBannerInput {
  action: "add-key" | "revoke";
  sha: string;
  name: string;
  fingerprint: string;
  capabilities: Capability[];
}

function printPostCommitBanner(input: PostCommitBannerInput): void {
  const bar = "─".repeat(72);
  const verb = input.action === "add-key" ? "added" : "revoked";
  console.log(bar);
  console.log(`${verb} ${input.name} (${input.fingerprint})`);
  console.log(bar);
  console.log(`  commit:        ${input.sha}`);
  console.log(`  capabilities:  [${input.capabilities.join(", ")}]`);
  console.log(`  manifest:      ${MANIFEST_RELATIVE_PATH}`);
  console.log(bar);
  console.log("This commit modifies `.stamp/**` and is gated by `path_rules`.");
  console.log("It will NOT run through the reviewer cycle (bypass_review_cycle: true);");
  console.log("it needs admin counter-signatures instead. Next step:");
  console.log();
  console.log(`  stamp admin sign --pending ${input.sha.slice(0, 12)}`);
  console.log();
  console.log("Once `minimum_signatures` admins have signed, run `stamp merge` from");
  console.log("the target branch to land this change.");
}

