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
  const stateDbPath = stampStateDbPath(repoRoot);

  const alreadyHasConfig = existsSync(configFile);

  ensureDir(configDir);
  ensureDir(reviewersDir);
  ensureDir(trustedKeysDir);

  if (!alreadyHasConfig) {
    writeFileSync(configFile, stringifyConfig(DEFAULT_CONFIG));
    writeFileSync(join(reviewersDir, "example.md"), EXAMPLE_REVIEWER_PROMPT);
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

  const mode = alreadyHasConfig ? "sync" : "scaffold";
  console.log(
    mode === "scaffold"
      ? "stamp initialized (scaffolded fresh repo).\n"
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
  console.log();

  if (mode === "scaffold") {
    console.log("Next steps:");
    console.log("  1. Edit .stamp/config.yml to define branch rules and reviewers");
    console.log("  2. Write reviewer prompts in .stamp/reviewers/*.md");
    console.log("  3. Commit the .stamp/ directory");
    console.log(
      "  4. Share your public key (in .stamp/trusted-keys/) with any other",
    );
    console.log("     machines that will push to this repo");
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
