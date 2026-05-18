/**
 * `stamp init --migrate-to-server-attested` orchestrator (AGT-342).
 *
 * Wraps the pure helpers in `src/lib/migrateServerAttested.ts` with the
 * interactive prompt, dry-run handling, and file IO. Kept thin so the
 * helpers stay unit-testable; the only logic here is sequencing.
 *
 * Acceptance criteria from the project handoff:
 *
 *   1. Detect existing `.stamp/trusted-keys/*.pub`; write `manifest.yml`
 *      with each entry defaulted to `capabilities: [operator]`.
 *   2. Interactive prompt promotes selected keys to `[admin, operator]`.
 *   3. `mcp_servers` / `tools` blocks in `.stamp/config.yml` get
 *      commented out + a stderr warning.
 *   4. Default `path_rules:` block added gating `.stamp/**`.
 *   5. `--dry-run` prints proposed changes without writing.
 *   6. Idempotent: re-running on a manifest that already has
 *      capabilities skips the manifest write; a config that already has
 *      `path_rules:` triggers only a (silenced-when-matching) warning.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

import { readLineSync } from "../lib/humanMerge.js";
import {
  configPath,
  DEFAULT_PATH_RULES_BLOCK,
  detectExistingKeys,
  disambiguateNames,
  rewriteConfigForMigration,
  serializeManifest,
  type DetectedKey,
} from "../lib/migrateServerAttested.js";
import {
  ensureDir,
  findRepoRoot,
  stampTrustedKeysDir,
} from "../lib/paths.js";
import { MANIFEST_RELATIVE_PATH } from "../lib/trustedKeysManifest.js";

export interface MigrateToServerAttestedOptions {
  /** When true, print proposed changes without writing them. */
  dryRun?: boolean;
  /**
   * Test seam: when set, used as the source of admin-promotion selection
   * instead of prompting on stdin. Indexes are 1-based to mirror what the
   * operator would type; out-of-range values are silently dropped (same
   * permissive behavior as the live prompt). Pass `[]` to test the
   * "promote none" path without faking a TTY.
   */
  selectAdminIndexes?: number[];
}

/**
 * Entry point invoked by `stamp init --migrate-to-server-attested`.
 * Returns void; throws on hard errors (no keys to migrate, write
 * failure). Soft conditions (path_rules already present, mcp_servers
 * commented out) print to stderr/stdout.
 */
export function runMigrateToServerAttested(
  opts: MigrateToServerAttestedOptions = {},
): void {
  const repoRoot = findRepoRoot();
  const dryRun = opts.dryRun === true;

  // 1. Detect existing pubkeys. Errors here are fatal — there's nothing
  //    to migrate without input.
  const detected = disambiguateNames(
    detectExistingKeys(repoRoot, (filename, reason) => {
      console.error(`note: skipping .stamp/trusted-keys/${filename} — ${reason}`);
    }),
  );

  // 2. Interactive promotion. Skipped (every key stays operator) when
  //    `--dry-run` is passed, when stdin isn't a TTY, or when the
  //    manifest already lists capability assignments (idempotent
  //    re-run). The test seam `selectAdminIndexes` bypasses the TTY
  //    check so the prompt path can be exercised in unit tests.
  const manifestPath = join(repoRoot, MANIFEST_RELATIVE_PATH);
  const manifestExists = existsSync(manifestPath);

  let adminFingerprints: Set<string>;
  if (manifestExists) {
    // Idempotent re-run: read the existing assignments and keep them.
    // We don't re-prompt; promoting an already-promoted key is a no-op
    // and re-prompting would surprise an operator who picked their
    // admins last time.
    adminFingerprints = readExistingAdminFingerprints(manifestPath);
    console.log(
      `Manifest already present at ${relative(repoRoot, manifestPath)} — ` +
        `preserving existing capability assignments (idempotent re-run).`,
    );
  } else if (opts.selectAdminIndexes !== undefined) {
    adminFingerprints = pickAdminsFromIndexes(
      detected,
      opts.selectAdminIndexes,
    );
  } else if (dryRun) {
    // Don't prompt during dry-run — operators expect dry-run to be
    // side-effect free, including no blocking on stdin. The preview
    // shows every key at default `[operator]`; the real run will
    // prompt.
    adminFingerprints = new Set();
    console.log(
      "Dry-run: skipping admin-promotion prompt; preview uses default " +
        "`[operator]` for every key. Re-run without --dry-run to choose.",
    );
  } else if (process.stdin.isTTY && process.stdout.isTTY) {
    adminFingerprints = promptForAdminPromotion(detected);
  } else {
    // Non-interactive (CI, pipe) without --dry-run + no seam. Default
    // to no promotions and tell the operator how to choose.
    adminFingerprints = new Set();
    console.error(
      "warning: non-interactive stdin — no keys will be promoted to " +
        "`admin`. Re-run from a TTY to pick admin keys, or hand-edit " +
        `${relative(repoRoot, manifestPath)} after this command finishes.`,
    );
  }

  // 3. Build the new manifest text. Even on a re-run we re-serialize so
  //    a manually-edited file gets re-normalized to the canonical form
  //    the rest of the pipeline expects.
  const manifestText = serializeManifest(detected, adminFingerprints);

  // 4. Rewrite .stamp/config.yml: comment out mcp_servers/tools, append
  //    path_rules block when none exists. Read raw to preserve operator
  //    comments + formatting.
  const cfgPath = configPath(repoRoot);
  if (!existsSync(cfgPath)) {
    throw new Error(
      `expected .stamp/config.yml at ${cfgPath} but found none. ` +
        `Run \`stamp init\` first.`,
    );
  }
  const cfgInput = readFileSync(cfgPath, "utf8");
  const rewrite = rewriteConfigForMigration(cfgInput);

  // 5. Write or preview. Dry-run prints both files' proposed contents
  //    plus a one-line summary of side-effects; the real path writes
  //    each file (idempotent: skip a write when the on-disk bytes
  //    already match).
  if (dryRun) {
    printDryRun({
      repoRoot,
      manifestPath,
      manifestText,
      manifestExists,
      cfgPath,
      cfgInput,
      cfgRewrite: rewrite,
      detected,
      adminFingerprints,
    });
    return;
  }

  if (rewrite.commentedBlocks.length > 0) {
    console.error(
      `warning: Phase 1 server-attested reviewers are diff-only — ` +
        `${rewrite.commentedBlocks
          .map((b) => `\`${b}:\``)
          .join(" + ")} block(s) in .stamp/config.yml have been commented ` +
        `out (not deleted). See docs/migration-1.x-to-2.x.md for ` +
        `adaptation options.`,
    );
  }
  for (const w of rewrite.warnings) {
    console.error(`warning: ${w}`);
  }

  let manifestAction: "wrote" | "unchanged";
  if (manifestExists && readFileSync(manifestPath, "utf8") === manifestText) {
    manifestAction = "unchanged";
  } else {
    ensureDir(dirname(manifestPath));
    writeFileSync(manifestPath, manifestText);
    manifestAction = "wrote";
  }

  let cfgAction: "wrote" | "unchanged";
  if (!rewrite.changed) {
    cfgAction = "unchanged";
  } else {
    writeFileSync(cfgPath, rewrite.text);
    cfgAction = "wrote";
  }

  console.log();
  console.log("Migration scaffold complete.");
  console.log(
    `  manifest:    ${relative(repoRoot, manifestPath)} (${manifestAction})`,
  );
  console.log(
    `  config:      ${relative(repoRoot, cfgPath)} (${cfgAction})`,
  );
  if (rewrite.pathRulesAppended) {
    console.log(
      "  path_rules:  appended default `.stamp/**` gate (admin + 2 signatures)",
    );
  }
  console.log();
  console.log(
    "Next steps:\n" +
      "  1. Commit the migration scaffold to a feature branch.\n" +
      "  2. Land it through the existing 1.x reviewer cycle (this is\n" +
      "     the migration commit — every later .stamp/** change goes\n" +
      "     through path_rules).\n" +
      "  3. Add `branches.<name>.review_server: ssh://git@<host>:<port>`\n" +
      "     to .stamp/config.yml to route reviews through stamp-server.\n" +
      "  See docs/migration-1.x-to-2.x.md.",
  );
}

/**
 * Test-seam wrapper around the same logic as the interactive prompt.
 * 1-based indexes mirror what the operator would type (`1,3`).
 */
function pickAdminsFromIndexes(
  detected: DetectedKey[],
  indexes: number[],
): Set<string> {
  const out = new Set<string>();
  for (const idx of indexes) {
    if (!Number.isInteger(idx)) continue;
    if (idx < 1 || idx > detected.length) continue;
    out.add(detected[idx - 1]!.fingerprint);
  }
  return out;
}

/**
 * Prompt the operator to select which detected keys should also gain
 * `admin` capability. Lists every key with its fingerprint and source
 * filename so the operator can identify each. Empty answer (or `none`)
 * promotes nothing.
 *
 * The prompt accepts a comma- and/or whitespace-separated list of
 * 1-based indexes:
 *   1,3   -> promote the 1st and 3rd entry
 *   2     -> promote only the 2nd
 *   none  -> promote nothing
 *   all   -> promote every key (rare, but useful for single-operator
 *            repos where every key is the same human)
 */
function promptForAdminPromotion(detected: DetectedKey[]): Set<string> {
  console.log();
  console.log(
    "Existing trusted keys (Phase 1 default: `[operator]`). Pick which " +
      "should ALSO carry `admin` capability — admins gate `.stamp/**` " +
      "changes via path_rules. You can change this later by editing the " +
      "manifest through an admin-signed commit.",
  );
  console.log();
  for (let i = 0; i < detected.length; i++) {
    const k = detected[i]!;
    console.log(
      `  ${i + 1}. ${k.name} — ${k.fingerprint}  (${k.filename})`,
    );
  }
  console.log();
  process.stdout.write(
    "Promote which keys to admin? [comma-separated indexes, `all`, or `none`]: ",
  );
  const answer = readLineSync().trim().toLowerCase();
  if (answer === "" || answer === "none") return new Set();
  if (answer === "all") {
    return new Set(detected.map((k) => k.fingerprint));
  }
  const indexes = answer
    .split(/[,\s]+/)
    .filter((s) => s.length > 0)
    .map((s) => Number.parseInt(s, 10));
  return pickAdminsFromIndexes(detected, indexes);
}

/**
 * Parse an existing `manifest.yml` for entries whose `capabilities`
 * list contains `admin`, and return the set of their fingerprints. Used
 * for the idempotent-re-run path — we preserve the operator's prior
 * admin choices rather than re-prompting.
 *
 * Best-effort: the canonical parse + validation lives in
 * `trustedKeysManifest.ts`. Re-using it would force a synchronous
 * import + tolerate strict parse failures; we deliberately stay loose
 * here because a malformed manifest still benefits from a re-scaffold
 * (the rewrite produces a clean canonical form).
 */
function readExistingAdminFingerprints(manifestPath: string): Set<string> {
  const out = new Set<string>();
  let text: string;
  try {
    text = readFileSync(manifestPath, "utf8");
  } catch {
    return out;
  }
  // Walk the file line-by-line: each entry is a 2-space-indented key
  // followed by a 4-space-indented `fingerprint:` and `capabilities:`.
  // The hand-rolled serializer emits this exact shape; we accept loose
  // formatting (any indent) for hand edits but stay simple.
  const lines = text.split("\n");
  let currentFingerprint: string | null = null;
  let currentCaps: string[] = [];
  for (const line of lines) {
    const fpMatch = line.match(/^\s+fingerprint:\s*(sha256:[0-9a-f]{64})\b/);
    if (fpMatch) {
      // Commit the previous entry when we hit a new fingerprint.
      if (currentFingerprint && currentCaps.includes("admin")) {
        out.add(currentFingerprint);
      }
      currentFingerprint = fpMatch[1]!;
      currentCaps = [];
      continue;
    }
    const capMatch = line.match(/^\s+capabilities:\s*\[([^\]]*)\]/);
    if (capMatch) {
      currentCaps = capMatch[1]!
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
    }
  }
  if (currentFingerprint && currentCaps.includes("admin")) {
    out.add(currentFingerprint);
  }
  return out;
}

interface DryRunSnapshot {
  repoRoot: string;
  manifestPath: string;
  manifestText: string;
  manifestExists: boolean;
  cfgPath: string;
  cfgInput: string;
  cfgRewrite: ReturnType<typeof rewriteConfigForMigration>;
  detected: DetectedKey[];
  adminFingerprints: Set<string>;
}

function printDryRun(s: DryRunSnapshot): void {
  console.log("--- dry-run: --migrate-to-server-attested ---");
  console.log();
  console.log(`Detected ${s.detected.length} pubkey(s) in .stamp/trusted-keys/:`);
  for (const k of s.detected) {
    const promoted = s.adminFingerprints.has(k.fingerprint) ? "admin" : "—";
    console.log(`  - ${k.name} (${k.filename}) [admin promotion: ${promoted}]`);
  }
  console.log();

  console.log(
    `Would write ${relative(s.repoRoot, s.manifestPath)} ` +
      `(${s.manifestExists ? "exists; would overwrite" : "new"}):`,
  );
  console.log(indent(s.manifestText, "    "));

  if (s.cfgRewrite.changed) {
    console.log(`Would rewrite ${relative(s.repoRoot, s.cfgPath)}.`);
    if (s.cfgRewrite.commentedBlocks.length > 0) {
      console.log(
        `  - Comment out: ${s.cfgRewrite.commentedBlocks
          .map((b) => `\`${b}:\``)
          .join(", ")}`,
      );
    }
    if (s.cfgRewrite.pathRulesAppended) {
      console.log("  - Append default `path_rules:` block:");
      console.log(indent(DEFAULT_PATH_RULES_BLOCK, "      "));
    }
  } else {
    console.log(
      `Would leave ${relative(s.repoRoot, s.cfgPath)} unchanged.`,
    );
  }

  for (const w of s.cfgRewrite.warnings) {
    console.log(`  warning: ${w}`);
  }

  console.log();
  console.log("--- end dry-run ---");
}

function indent(text: string, prefix: string): string {
  return text
    .split("\n")
    .map((l) => (l.length > 0 ? prefix + l : l))
    .join("\n");
}

/** Re-export for use by `stamp init --migrate-to-server-attested`
 *  argument-handling code that wants the same `stampTrustedKeysDir`
 *  path shape without pulling `paths.js` directly. */
export { stampTrustedKeysDir };
