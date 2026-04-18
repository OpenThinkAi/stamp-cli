import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  DEFAULT_CONFIG,
  EXAMPLE_REVIEWER_PROMPT,
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

export function runInit(): void {
  const repoRoot = findRepoRoot();
  const configDir = stampConfigDir(repoRoot);
  const configFile = stampConfigFile(repoRoot);
  const reviewersDir = stampReviewersDir(repoRoot);
  const trustedKeysDir = stampTrustedKeysDir(repoRoot);

  if (existsSync(configFile)) {
    console.error(`error: ${configFile} already exists. Repo is already initialized.`);
    process.exit(1);
  }

  ensureDir(configDir);
  ensureDir(reviewersDir);
  ensureDir(trustedKeysDir);

  writeFileSync(configFile, stringifyConfig(DEFAULT_CONFIG));
  writeFileSync(join(reviewersDir, "example.md"), EXAMPLE_REVIEWER_PROMPT);

  const { keypair, created } = ensureUserKeypair();

  const pubKeyPath = join(
    trustedKeysDir,
    publicKeyFingerprintFilename(keypair.fingerprint),
  );
  writeFileSync(pubKeyPath, keypair.publicKeyPem);

  const db = openDb(stampStateDbPath(repoRoot));
  db.close();

  console.log("stamp initialized.\n");
  console.log(`  repo root:   ${repoRoot}`);
  console.log(`  config:      ${configFile}`);
  console.log(`  reviewers:   ${reviewersDir}/example.md`);
  console.log(`  trust store: ${trustedKeysDir}/`);
  console.log(`  state db:    ${stampStateDbPath(repoRoot)}`);
  console.log(
    `  your key:    ${keypair.fingerprint} ${created ? "(generated)" : "(existing)"}`,
  );
  console.log();
  console.log("Next steps:");
  console.log("  1. Edit .stamp/config.yml to define your branch rules and reviewers");
  console.log("  2. Write reviewer prompts in .stamp/reviewers/*.md");
  console.log("  3. Commit the .stamp/ directory to your repo");
  console.log("  4. Share your public key file (in .stamp/trusted-keys/) with other");
  console.log("     machines that will push to this repo");
}
