/**
 * `stamp init --migrate-to-server-attested` orchestrator (AGT-342 + WS2).
 *
 * Drives the one-PR Shape 4 setup end-to-end:
 *
 *   1. Detect existing `.stamp/trusted-keys/*.pub` → manifest entries
 *      defaulting to `[operator]`. Interactive prompt promotes selected
 *      keys to `[admin, operator]`.
 *   2. Fetch the server's review-signing pubkey over SSH (via the
 *      `--server <host:port>` flag or `~/.stamp/server.yml`). Compute its
 *      `sha256:<hex>` fingerprint. Write the pubkey to
 *      `.stamp/trusted-keys/review-server-prod.pub`.
 *   3. Add a `review-server-prod` manifest entry with `[server]` capability
 *      + `role_source: server`.
 *   4. Rewrite `.stamp/config.yml`:
 *        - add `review_server: ssh://git@<host>:<port>` to the default
 *          branch's rule (idempotent),
 *        - rewrite each reviewer entry to `{}` form (Shape 4 cleanup —
 *          server holds the canonical prompt bytes),
 *        - smart-default `minimum_signatures` based on the admin count
 *          chosen above (1 when there's exactly one admin, else 2).
 *   5. Delete `.stamp/reviewers/*.md` (Shape 4 doesn't carry in-repo
 *      prompts). Preserve the directory itself in case operators have
 *      other files there.
 *   6. Scaffold `.github/workflows/stamp-verify.yml` if absent.
 *   7. `--dry-run`: print proposed changes without writing or fetching.
 *
 * The output is designed to pass `stamp attest --migrate-existing`'s
 * diff whitelist cleanly: the activation envelope signs the `.stamp/**`
 * subset (config, manifest, new pubkey, deleted reviewers); the workflow
 * file is outside that subset and rides in the same PR for the operator
 * but doesn't need to be inside the activation envelope (the verifier
 * runs in CI on the NEXT PR onward).
 */

import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

import { readLineSync } from "../lib/humanMerge.js";
import { fingerprintFromPem } from "../lib/keys.js";
import {
  detectExistingKeys,
  disambiguateNames,
  renderPathRulesBlock,
  rewriteConfigForMigration,
  serializeManifest,
  type DetectedKey,
} from "../lib/migrateServerAttested.js";
import { maybeWriteVerifyWorkflow } from "../lib/verifyWorkflow.js";
import {
  ensureDir,
  findRepoRoot,
  stampConfigFile,
  stampReviewersDir,
  stampTrustedKeysDir,
} from "../lib/paths.js";
import { fetchServerReviewSigningPubkey } from "../lib/serverPubkeyFetch.js";
import {
  loadServerConfig,
  parseServerFlag,
  type ServerConfig,
} from "../lib/serverConfig.js";
import {
  MANIFEST_RELATIVE_PATH,
  parseManifest,
} from "../lib/trustedKeysManifest.js";

/** Manifest entry name we install for the server's review-signing key.
 *  Single canonical name keeps the WS2 one-PR setup deterministic; multi-
 *  server fleets rename by hand-editing after the scaffold. */
const SERVER_MANIFEST_NAME = "review-server-prod";

/** Pubkey filename for the server's review-signing key. Mirrors the
 *  manifest name so an operator scanning the directory sees a 1:1
 *  correspondence. Static so the idempotency check is straightforward. */
const SERVER_PUBKEY_FILENAME = `${SERVER_MANIFEST_NAME}.pub`;

/** Placeholder shown in --dry-run when we deliberately skip the SSH
 *  fetch. The real run fetches the pubkey; the preview avoids the
 *  network call so dry-run stays offline-safe. */
const DRY_RUN_PUBKEY_PLACEHOLDER = "<SERVER_REVIEW_SIGNING_PUBKEY>";
const DRY_RUN_FINGERPRINT_PLACEHOLDER = "sha256:<computed-at-real-run>";

export interface MigrateToServerAttestedOptions {
  /** When true, print proposed changes without writing or fetching. */
  dryRun?: boolean;
  /** `<host>:<port>` override for the server. When omitted, falls back
   *  to `~/.stamp/server.yml`. */
  server?: string;
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
 * Returns void; throws on hard errors (no keys to migrate, no server
 * config available, write failure). Soft conditions (path_rules already
 * present, etc.) print to stderr/stdout.
 */
export function runMigrateToServerAttested(
  opts: MigrateToServerAttestedOptions = {},
): void {
  const repoRoot = findRepoRoot();
  const dryRun = opts.dryRun === true;

  // 1. Resolve the server. Required in both dry-run and real-run because
  //    the rewrite needs `review_server: ssh://...` to be a concrete URL
  //    (otherwise the dry-run preview would be misleading).
  const server = resolveServerForMigration(opts.server);

  // 2. Detect existing pubkeys. Errors here are fatal — there's nothing
  //    to migrate without input. Filter out the server pubkey file from
  //    the detected set so an idempotent re-run doesn't try to re-add it
  //    as an operator-cap key (the server entry is added separately
  //    below with [server] + role_source: server).
  const detectedRaw = detectExistingKeys(repoRoot, (filename, reason) => {
    console.error(`note: skipping .stamp/trusted-keys/${filename} — ${reason}`);
  });
  const detected = disambiguateNames(
    detectedRaw.filter((k) => k.filename !== SERVER_PUBKEY_FILENAME),
  );

  // 3. Interactive admin promotion. Same logic as before; idempotent re-
  //    run preserves the operator's prior selection.
  const manifestPath = join(repoRoot, MANIFEST_RELATIVE_PATH);
  const manifestExists = existsSync(manifestPath);

  let adminFingerprints: Set<string>;
  if (manifestExists) {
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
    adminFingerprints = new Set();
    console.log(
      "Dry-run: skipping admin-promotion prompt; preview uses default " +
        "`[operator]` for every key. Re-run without --dry-run to choose.",
    );
  } else if (process.stdin.isTTY && process.stdout.isTTY) {
    adminFingerprints = promptForAdminPromotion(detected);
  } else {
    adminFingerprints = new Set();
    console.error(
      "warning: non-interactive stdin — no keys will be promoted to " +
        "`admin`. Re-run from a TTY to pick admin keys, or hand-edit " +
        `${relative(repoRoot, manifestPath)} after this command finishes.`,
    );
  }

  // 4. Smart-default minimum_signatures. Single-admin repos need 1 (a
  //    2-signature gate would deadlock every subsequent .stamp/** PR).
  const adminCount = adminFingerprints.size;
  const minimumSignatures = adminCount === 1 ? 1 : 2;
  if (adminCount === 1) {
    console.error(
      "warning: single admin key detected — setting path_rules .stamp/** " +
        "`minimum_signatures: 1`. Promote a second admin (re-run the " +
        "migration and pick two) to harden the gate.",
    );
  } else if (adminCount === 0 && !dryRun && !manifestExists) {
    console.error(
      "warning: no admin keys selected — path_rules .stamp/** will require " +
        `${minimumSignatures} admin signature(s), which means no admin-cap key ` +
        "can sign trust-anchor changes. The scaffolded manifest is still " +
        "valid; hand-edit it to add capabilities: [admin] before the first " +
        "post-migration PR.",
    );
  }

  // 5. Fetch the server's review-signing pubkey. Dry-run uses a
  //    placeholder so the preview stays offline-safe; real run does the
  //    SSH call up front so we fail fast if the server is unreachable.
  let serverPubkeyPem: string;
  let serverFingerprint: string;
  if (dryRun) {
    serverPubkeyPem = DRY_RUN_PUBKEY_PLACEHOLDER + "\n";
    serverFingerprint = DRY_RUN_FINGERPRINT_PLACEHOLDER;
  } else {
    serverPubkeyPem = fetchServerReviewSigningPubkey(server);
    try {
      serverFingerprint = fingerprintFromPem(serverPubkeyPem);
    } catch (err) {
      throw new Error(
        `server returned an unparseable review-signing pubkey: ${err instanceof Error ? err.message : String(err)}. ` +
          `Expected SPKI PEM bytes from \`stamp-server-pubkey --review-signing\`. ` +
          `Confirm the server image is recent (2.0.1+) and that ANTHROPIC_API_KEY is set on the server.`,
      );
    }
  }

  // 6. Build the new manifest text. Two cases:
  //    (a) No existing manifest: build from `detected` + admin promotions
  //        + server entry (the fresh-1.x-to-Shape-4 path).
  //    (b) Existing manifest: PRESERVE every existing entry verbatim
  //        (name, fingerprint, capabilities, role_source) and APPEND the
  //        server entry if it's not already there. Re-serializing
  //        existing entries from the parsed model would lose any
  //        operator-chosen entry name that doesn't match the filename
  //        stem — and the bootstrap whitelist refuses any modification
  //        of an existing entry. The append-only path is the only safe
  //        edit at this surface.
  let manifestText: string;
  if (manifestExists) {
    manifestText = appendServerEntryToManifest(
      readFileSync(manifestPath, "utf8"),
      { name: SERVER_MANIFEST_NAME, fingerprint: serverFingerprint },
    );
  } else {
    manifestText = serializeManifest(
      detected,
      adminFingerprints,
      [{ name: SERVER_MANIFEST_NAME, fingerprint: serverFingerprint }],
    );
  }

  // 7. Rewrite .stamp/config.yml: add review_server, rewrite reviewers
  //    to `{}` form, append/update path_rules with smart-defaulted
  //    minimum_signatures.
  const cfgPath = stampConfigFile(repoRoot);
  if (!existsSync(cfgPath)) {
    throw new Error(
      `expected .stamp/config.yml at ${cfgPath} but found none. ` +
        `Run \`stamp init\` first.`,
    );
  }
  const cfgInput = readFileSync(cfgPath, "utf8");
  const defaultBranch = detectDefaultBranch(cfgInput);
  if (!defaultBranch) {
    throw new Error(
      `could not find any branch under \`branches:\` in .stamp/config.yml. ` +
        `Add at least one branch rule before running the migration.`,
    );
  }
  const reviewServerUrl = `ssh://${server.user}@${server.host}:${server.port}`;
  const rewrite = rewriteConfigForMigration(cfgInput, {
    reviewServer: { branch: defaultBranch, url: reviewServerUrl },
    rewriteReviewersToEmpty: true,
    minimumSignatures,
  });

  // 8. Discover .stamp/reviewers/*.md to delete (Shape 4 retires the
  //    in-repo prompt copies; the server holds the canonical bytes).
  const reviewersDir = stampReviewersDir(repoRoot);
  const reviewerFilesToDelete = listReviewerPromptFiles(reviewersDir);

  // 9. Workflow file scaffolding.
  const verifyWorkflowPath = join(
    repoRoot,
    ".github",
    "workflows",
    "stamp-verify.yml",
  );
  const verifyWorkflowExists = existsSync(verifyWorkflowPath);

  // 10. Dry-run path: print everything, no IO, no fetch.
  if (dryRun) {
    printDryRun({
      repoRoot,
      manifestPath,
      manifestText,
      manifestExists,
      cfgPath,
      cfgRewrite: rewrite,
      detected,
      adminFingerprints,
      server,
      serverFingerprint,
      defaultBranch,
      reviewServerUrl,
      reviewerFilesToDelete,
      verifyWorkflowExists,
      verifyWorkflowPath,
      minimumSignatures,
    });
    return;
  }

  // 11. Real-run path. Surface warnings on stderr.
  for (const w of rewrite.warnings) {
    console.error(`warning: ${w}`);
  }

  // 11a. Write server pubkey. Idempotency: if it exists with matching
  //      content, no-op; if it differs, warn and leave the file alone
  //      (the operator may have committed a key from a different server).
  const serverPubkeyPath = join(
    stampTrustedKeysDir(repoRoot),
    SERVER_PUBKEY_FILENAME,
  );
  let pubkeyAction: "wrote" | "exists" | "differs";
  if (existsSync(serverPubkeyPath)) {
    const existing = readFileSync(serverPubkeyPath, "utf8");
    if (existing === serverPubkeyPem) {
      pubkeyAction = "exists";
    } else {
      pubkeyAction = "differs";
      console.error(
        `warning: ${relative(repoRoot, serverPubkeyPath)} exists with different ` +
          `content than the server returned (fingerprint ${serverFingerprint}). ` +
          `Leaving the existing file in place. Hand-edit if you want to swap servers.`,
      );
    }
  } else {
    ensureDir(dirname(serverPubkeyPath));
    writeFileSync(serverPubkeyPath, serverPubkeyPem);
    pubkeyAction = "wrote";
  }

  // 11b. Manifest write (idempotent — re-serializing produces identical
  //      bytes when the on-disk content matches).
  let manifestAction: "wrote" | "unchanged";
  if (manifestExists && readFileSync(manifestPath, "utf8") === manifestText) {
    manifestAction = "unchanged";
  } else {
    ensureDir(dirname(manifestPath));
    writeFileSync(manifestPath, manifestText);
    manifestAction = "wrote";
  }

  // 11c. Config write.
  let cfgAction: "wrote" | "unchanged";
  if (!rewrite.changed) {
    cfgAction = "unchanged";
  } else {
    writeFileSync(cfgPath, rewrite.text);
    cfgAction = "wrote";
  }

  // 11d. Delete .stamp/reviewers/*.md.
  const deletedReviewers: string[] = [];
  for (const f of reviewerFilesToDelete) {
    rmSync(f, { force: true });
    deletedReviewers.push(relative(repoRoot, f));
  }

  // 11e. Workflow file. Default mode = local-only is fine here; the
  //      forge-direct / server-gated distinction doesn't apply to the
  //      Shape 4 init (the workflow file should always land). Pass
  //      prCheckOpt=true to force write regardless of mode.
  const wf = maybeWriteVerifyWorkflow(repoRoot, true, "local-only");

  // 12. Summary.
  console.log();
  console.log("Shape 4 migration scaffold complete.");
  console.log(
    `  manifest:        ${relative(repoRoot, manifestPath)} (${manifestAction})`,
  );
  console.log(
    `  config:          ${relative(repoRoot, cfgPath)} (${cfgAction})`,
  );
  console.log(
    `  server pubkey:   ${relative(repoRoot, serverPubkeyPath)} (${pubkeyAction})`,
  );
  console.log(`  fingerprint:     ${serverFingerprint}`);
  if (rewrite.reviewServerBranchAdded) {
    console.log(
      `  review_server:   added to branch "${rewrite.reviewServerBranchAdded}" -> ${reviewServerUrl}`,
    );
  }
  if (rewrite.reviewersRewrittenTo.length > 0) {
    console.log(
      `  reviewers:       rewrote to {} form: ${rewrite.reviewersRewrittenTo.join(", ")}`,
    );
  }
  if (rewrite.pathRulesAppended) {
    console.log(
      `  path_rules:      appended .stamp/** gate (admin + ${minimumSignatures} signature${minimumSignatures === 1 ? "" : "s"})`,
    );
  }
  if (deletedReviewers.length > 0) {
    console.log(`  removed prompts: ${deletedReviewers.join(", ")}`);
  }
  console.log(`  verify workflow: ${wf.path} (${wf.action})`);
  console.log();
  console.log(
    "Next steps:\n" +
      "  1. Review the diff (git diff). It should touch ONLY .stamp/** and\n" +
      "     .github/workflows/stamp-verify.yml.\n" +
      "  2. Commit on a feature branch.\n" +
      "  3. Run `stamp attest --into main --migrate-existing --push origin`\n" +
      "     to produce the bootstrap envelope. (Only the .stamp/** subset is\n" +
      "     covered by the activation envelope; the workflow file is outside\n" +
      "     and lands in the same PR.)\n" +
      "  4. Open the PR; the verifier accepts the bootstrap envelope.\n" +
      "  See docs/migration-1.x-to-2.x.md `Upgrade walkthrough — Shape 4`.",
  );
  console.log();
  console.log(
    "Trust model note: the server's review-signing pubkey was fetched over\n" +
      "SSH using TOFU (trust-on-first-use). To harden, verify the fingerprint\n" +
      `out-of-band against the operator's independent record:\n` +
      `  ssh -p ${server.port} ${server.user}@${server.host} stamp-server-pubkey --review-signing | \\\n` +
      `    openssl pkey -pubin -in - -outform DER | sha256sum\n` +
      `Expected: ${serverFingerprint.replace("sha256:", "")}`,
  );
}

/**
 * Append a `[server]+role_source:server` entry to an existing manifest's
 * `keys:` map without disturbing existing entries. Idempotent: if any
 * existing entry has the same fingerprint OR name, leaves the file
 * alone (and warns to stderr if the fingerprint differs).
 *
 * Line-oriented (no YAML round-trip) so we preserve operator comments
 * and formatting. The new entry is inserted at the end of the `keys:`
 * block so existing entries' lines are byte-identical between base and
 * head (the bootstrap whitelist demands deep equality on each existing
 * entry's parsed form).
 */
function appendServerEntryToManifest(
  existingText: string,
  entry: { name: string; fingerprint: string },
): string {
  const parsed = parseManifest(existingText);
  if (parsed) {
    // Idempotency: server entry already present?
    const byFp = parsed.entries.find((e) => e.fingerprint === entry.fingerprint);
    if (byFp) {
      if (byFp.capabilities.includes("server")) {
        // Server entry already bound to this fingerprint — nothing to do.
        return existingText;
      }
      console.error(
        `warning: manifest already binds fingerprint ${entry.fingerprint} ` +
          `to "${byFp.name}" with capabilities [${byFp.capabilities.join(", ")}]. ` +
          `Refusing to add a duplicate "${entry.name}" entry. Hand-edit if the binding is wrong.`,
      );
      return existingText;
    }
    const byName = parsed.entries.find((e) => e.name === entry.name);
    if (byName) {
      console.error(
        `warning: manifest already has an entry named "${entry.name}" with ` +
          `fingerprint ${byName.fingerprint} (server returned ${entry.fingerprint}). ` +
          `Leaving the existing entry in place. Hand-edit if you want to swap servers.`,
      );
      return existingText;
    }
  }

  // Append. Preserve the input's trailing-newline convention: if the
  // input ends with "\n" we append starting on the next line; otherwise
  // we add a newline first so we don't run two YAML keys together.
  const trailing = existingText.endsWith("\n") ? "" : "\n";
  const block = [
    `  ${entry.name}:`,
    `    fingerprint: ${entry.fingerprint}`,
    `    capabilities: [server]`,
    `    role_source: server`,
    "",
  ].join("\n");
  return existingText + trailing + block;
}

/** Resolve --server flag, then ~/.stamp/server.yml, else throw with a
 *  message that names both sources so the operator knows what to do. */
function resolveServerForMigration(flag: string | undefined): ServerConfig {
  if (flag !== undefined && flag !== "") {
    return parseServerFlag(flag);
  }
  const loaded = loadServerConfig();
  if (loaded) return loaded;
  throw new Error(
    `no stamp server configured for --migrate-to-server-attested. Either:\n` +
      `  - pass --server <host:port> on the command line, or\n` +
      `  - run \`stamp server config --server <host:port>\` to persist the\n` +
      `    endpoint at ~/.stamp/server.yml.`,
  );
}

/** Best-effort: find the first branch name listed under `branches:` in
 *  the input YAML text. Prefers `main` if present; otherwise returns
 *  whichever branch is listed first. Returns null when no branch exists. */
function detectDefaultBranch(configText: string): string | null {
  const lines = configText.split("\n");
  let branchesIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s*#/.test(l)) continue;
    if (/^branches\s*:\s*(#.*)?$/.test(l)) {
      branchesIdx = i;
      break;
    }
  }
  if (branchesIdx < 0) return null;
  const found: string[] = [];
  let baseIndent = -1;
  for (let i = branchesIdx + 1; i < lines.length; i++) {
    const l = lines[i]!;
    const t = l.trim();
    if (t === "" || t.startsWith("#")) continue;
    let indent = 0;
    while (indent < l.length && l[indent] === " ") indent++;
    if (baseIndent < 0) baseIndent = indent;
    if (indent < baseIndent) break;
    if (indent === baseIndent) {
      const m = t.match(/^([A-Za-z0-9._/-]+)\s*:/);
      if (m) found.push(m[1]!);
    }
  }
  if (found.length === 0) return null;
  if (found.includes("main")) return "main";
  return found[0]!;
}

/** Enumerate `.stamp/reviewers/*.md` files. Returns absolute paths;
 *  empty array if the directory is missing. */
function listReviewerPromptFiles(reviewersDir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(reviewersDir);
  } catch {
    return [];
  }
  return entries
    .filter((f) => f.endsWith(".md"))
    .map((f) => join(reviewersDir, f));
}

/** 1-based index selection mirror of the interactive prompt. */
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

/** Prompt the operator to select which detected keys gain `admin`. */
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

/** Parse manifest.yml for existing entries whose `capabilities` list
 *  contains `admin`. Used for the idempotent-re-run path. */
function readExistingAdminFingerprints(manifestPath: string): Set<string> {
  const out = new Set<string>();
  let text: string;
  try {
    text = readFileSync(manifestPath, "utf8");
  } catch {
    return out;
  }
  const lines = text.split("\n");
  let currentFingerprint: string | null = null;
  let currentCaps: string[] = [];
  for (const line of lines) {
    const fpMatch = line.match(/^\s+fingerprint:\s*(sha256:[0-9a-f]{64})\b/);
    if (fpMatch) {
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
  cfgRewrite: ReturnType<typeof rewriteConfigForMigration>;
  detected: DetectedKey[];
  adminFingerprints: Set<string>;
  server: ServerConfig;
  serverFingerprint: string;
  defaultBranch: string;
  reviewServerUrl: string;
  reviewerFilesToDelete: string[];
  verifyWorkflowExists: boolean;
  verifyWorkflowPath: string;
  minimumSignatures: number;
}

function printDryRun(s: DryRunSnapshot): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log("dry-run: --migrate-to-server-attested (Shape 4 one-PR)");
  console.log(bar);
  console.log();
  console.log(
    `Server:           ${s.server.user}@${s.server.host}:${s.server.port}`,
  );
  console.log(
    `  pubkey:         <fetched at real-run via SSH; offline in dry-run>`,
  );
  console.log(
    `  fingerprint:    ${s.serverFingerprint}`,
  );
  console.log(`Default branch:   ${s.defaultBranch}`);
  console.log(`review_server:    ${s.reviewServerUrl}`);
  console.log(`min_signatures:   ${s.minimumSignatures}`);
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
    if (s.cfgRewrite.reviewServerBranchAdded) {
      console.log(
        `  - Add review_server to branch "${s.cfgRewrite.reviewServerBranchAdded}".`,
      );
    }
    if (s.cfgRewrite.reviewersRewrittenTo.length > 0) {
      console.log(
        `  - Rewrite reviewer entries to {} form: ${s.cfgRewrite.reviewersRewrittenTo.join(", ")}`,
      );
    }
    if (s.cfgRewrite.commentedBlocks.length > 0) {
      console.log(
        `  - Comment out: ${s.cfgRewrite.commentedBlocks.map((b) => `\`${b}:\``).join(", ")}`,
      );
    }
    if (s.cfgRewrite.pathRulesAppended) {
      console.log(
        `  - Append path_rules block (min_sigs=${s.minimumSignatures}):`,
      );
      console.log(
        indent(renderPathRulesBlock(s.minimumSignatures), "      "),
      );
    }
  } else {
    console.log(`Would leave ${relative(s.repoRoot, s.cfgPath)} unchanged.`);
  }

  console.log();
  if (s.reviewerFilesToDelete.length > 0) {
    console.log(`Would delete ${s.reviewerFilesToDelete.length} reviewer prompt file(s):`);
    for (const f of s.reviewerFilesToDelete) {
      console.log(`  - ${relative(s.repoRoot, f)}`);
    }
  } else {
    console.log("No .stamp/reviewers/*.md files present — nothing to delete.");
  }

  console.log();
  if (s.verifyWorkflowExists) {
    console.log(
      `Would leave existing ${relative(s.repoRoot, s.verifyWorkflowPath)} in place.`,
    );
  } else {
    console.log(`Would write ${relative(s.repoRoot, s.verifyWorkflowPath)}.`);
  }

  for (const w of s.cfgRewrite.warnings) {
    console.error(`warning: ${w}`);
  }

  console.log();
  console.log(bar);
  console.log("end dry-run");
  console.log(bar);
}

function indent(text: string, prefix: string): string {
  return text
    .split("\n")
    .map((l) => (l.length > 0 ? prefix + l : l))
    .join("\n");
}
