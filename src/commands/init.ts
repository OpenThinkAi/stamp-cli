import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureAgentsMd } from "../lib/agentsMd.js";
import {
  DEFAULT_CONFIG,
  DEFAULT_PRODUCT_PROMPT,
  DEFAULT_SECURITY_PROMPT,
  DEFAULT_STANDARDS_PROMPT,
  EXAMPLE_REVIEWER_PROMPT,
  MINIMAL_CONFIG,
  stringifyConfig,
} from "../lib/config.js";
import { openDb } from "../lib/db.js";
import {
  ensureUserKeypair,
  publicKeyFingerprintFilename,
} from "../lib/keys.js";
import {
  ensureDir,
  findRepoRoot,
  stampConfigDir,
  stampConfigFile,
  stampReviewersDir,
  stampStateDbPath,
  stampTrustedKeysDir,
} from "../lib/paths.js";

export interface InitOptions {
  /**
   * When true, scaffold a single placeholder `example` reviewer and require
   * only it. When false (default), scaffold three starter reviewers
   * (security / standards / product) and require all three.
   */
  minimal?: boolean;
  /**
   * When false, skip creating or updating AGENTS.md at the repo root.
   * Default true (writes/refreshes the marker-delimited stamp section so a
   * future agent dropped into the repo sees the gate model). Opt-out for
   * projects that maintain their own AGENTS.md discipline.
   */
  agentsMd?: boolean;
}

export function runInit(opts: InitOptions = {}): void {
  const repoRoot = findRepoRoot();
  const configDir = stampConfigDir(repoRoot);
  const configFile = stampConfigFile(repoRoot);
  const reviewersDir = stampReviewersDir(repoRoot);
  const trustedKeysDir = stampTrustedKeysDir(repoRoot);
  const stateDbPath = stampStateDbPath(repoRoot);

  const alreadyHasConfig = existsSync(configFile);

  ensureDir(configDir);
  ensureDir(reviewersDir);
  ensureDir(trustedKeysDir);

  if (!alreadyHasConfig) {
    if (opts.minimal) {
      writeFileSync(configFile, stringifyConfig(MINIMAL_CONFIG));
      writeFileSync(join(reviewersDir, "example.md"), EXAMPLE_REVIEWER_PROMPT);
    } else {
      writeFileSync(configFile, stringifyConfig(DEFAULT_CONFIG));
      writeFileSync(
        join(reviewersDir, "security.md"),
        DEFAULT_SECURITY_PROMPT,
      );
      writeFileSync(
        join(reviewersDir, "standards.md"),
        DEFAULT_STANDARDS_PROMPT,
      );
      writeFileSync(
        join(reviewersDir, "product.md"),
        DEFAULT_PRODUCT_PROMPT,
      );
    }
  }

  const { keypair, created: keyCreated } = ensureUserKeypair();

  const pubKeyPath = join(
    trustedKeysDir,
    publicKeyFingerprintFilename(keypair.fingerprint),
  );
  const keyDeposited = !existsSync(pubKeyPath);
  if (keyDeposited) {
    writeFileSync(pubKeyPath, keypair.publicKeyPem);
  }

  const dbExisted = existsSync(stateDbPath);
  const db = openDb(stateDbPath);
  db.close();

  // Ensure AGENTS.md carries the stamp guidance section unless the operator
  // opted out with --no-agents-md. Default-on because cloned repos hit
  // `stamp init` to set up their local keypair + state DB; that's also when
  // an agent first lands here, so it's the right moment to make the gate
  // visible. Marker-delimited write is non-destructive; user content outside
  // the markers is preserved.
  const agentsMdAction =
    opts.agentsMd === false ? "skipped" : ensureAgentsMd(repoRoot);

  const mode = alreadyHasConfig ? "sync" : "scaffold";
  console.log(
    mode === "scaffold"
      ? `stamp initialized (scaffolded fresh repo${opts.minimal ? " — minimal mode, single placeholder reviewer" : " with three starter reviewers"}).\n`
      : "stamp initialized (synced to existing .stamp/ config).\n",
  );
  console.log(`  repo root:   ${repoRoot}`);
  console.log(
    `  config:      ${configFile}${alreadyHasConfig ? " (existing)" : " (created)"}`,
  );
  console.log(`  trust store: ${trustedKeysDir}/`);
  console.log(
    `  state db:    ${stateDbPath}${dbExisted ? " (existing)" : " (created)"}`,
  );
  console.log(
    `  your key:    ${keypair.fingerprint} ${keyCreated ? "(generated)" : "(existing)"}`,
  );
  if (agentsMdAction !== "unchanged" && agentsMdAction !== "skipped") {
    console.log(`  AGENTS.md:   ${agentsMdAction} at repo root (with stamp-protected-repo guidance)`);
  }
  console.log();

  if (mode === "scaffold") {
    console.log("Next steps:");
    if (opts.minimal) {
      console.log(
        "  1. Replace .stamp/reviewers/example.md with your own reviewer prompt.",
      );
      console.log("  2. Or add more reviewers: `stamp reviewers add <name>`.");
    } else {
      console.log(
        "  1. Read the scaffolded prompts in .stamp/reviewers/ — they're",
      );
      console.log(
        "     starting points calibrated for generic TS/JS projects; customize",
      );
      console.log("     for your codebase. See docs/personas.md for guidance.");
      console.log(
        "  2. Optionally add `required_checks` to .stamp/config.yml (e.g.",
      );
      console.log(`     \`npm run build\`, \`npm run typecheck\`).`);
    }
    console.log("  3. Commit the .stamp/ directory.");
    console.log(
      "  4. Share your public key (in .stamp/trusted-keys/) with any other",
    );
    console.log("     machines that will push to this repo.");
  } else if (keyDeposited) {
    console.log(
      `Your public key was deposited at ${pubKeyPath}.`,
    );
    console.log(
      `Commit + push it so the remote will accept merges signed by this machine.`,
    );
  } else {
    console.log(
      "Your key is already in .stamp/trusted-keys/. You're ready to review + merge.",
    );
  }
}
