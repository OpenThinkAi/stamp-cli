import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import {
  ensureUserKeypair,
  fingerprintFromPem,
  generateKeypair,
  loadUserKeypair,
  publicKeyFingerprintFilename,
  saveUserKeypair,
} from "../lib/keys.js";
import {
  findRepoRoot,
  stampTrustedKeysDir,
  userKeysDir,
} from "../lib/paths.js";

export function keysGenerate(): void {
  const existing = loadUserKeypair();
  if (existing) {
    console.log(
      `keypair already exists at ${userKeysDir()}/ (fingerprint: ${existing.fingerprint})`,
    );
    console.log(
      `if you want a new one, remove the existing files first: rm ${userKeysDir()}/ed25519{,.pub}`,
    );
    return;
  }
  const kp = generateKeypair();
  saveUserKeypair(kp);
  console.log(`generated new Ed25519 keypair at ${userKeysDir()}/`);
  console.log(`fingerprint: ${kp.fingerprint}`);
  console.log();
  console.log("Copy the public key into each repo's .stamp/trusted-keys/:");
  console.log(`  stamp keys trust ${userKeysDir()}/ed25519.pub`);
}

export function keysList(): void {
  const local = loadUserKeypair();
  console.log(`local keypair: ${userKeysDir()}/`);
  if (local) {
    console.log(`  ${local.fingerprint}`);
  } else {
    console.log("  (none — run `stamp keys generate` or `stamp init`)");
  }

  console.log();
  try {
    const repoRoot = findRepoRoot();
    const trustedDir = stampTrustedKeysDir(repoRoot);
    console.log(`repo trusted keys: ${trustedDir}/`);
    if (!existsSync(trustedDir)) {
      console.log("  (directory does not exist — run `stamp init`)");
      return;
    }
    const pubFiles = readdirSync(trustedDir).filter((f) => f.endsWith(".pub"));
    if (pubFiles.length === 0) {
      console.log("  (none)");
      return;
    }
    for (const file of pubFiles.sort()) {
      try {
        const pem = readFileSync(join(trustedDir, file), "utf8");
        const fp = fingerprintFromPem(pem);
        const marker = local && fp === local.fingerprint ? " (you)" : "";
        console.log(`  ${fp}${marker}  [${file}]`);
      } catch {
        console.log(`  [unreadable] ${file}`);
      }
    }
  } catch {
    console.log("repo trusted keys: (not inside a git repo)");
  }
}

export function keysExport(): void {
  const { keypair } = ensureUserKeypair();
  process.stdout.write(keypair.publicKeyPem);
}

export function keysTrust(pubFile: string): void {
  const repoRoot = findRepoRoot();
  const trustedDir = stampTrustedKeysDir(repoRoot);
  if (!existsSync(trustedDir)) {
    throw new Error(
      `no ${trustedDir} — run \`stamp init\` first to create the trust store`,
    );
  }
  if (!existsSync(pubFile)) {
    throw new Error(`public key file not found: ${pubFile}`);
  }
  const pem = readFileSync(pubFile, "utf8");
  let fingerprint: string;
  try {
    fingerprint = fingerprintFromPem(pem);
  } catch (err) {
    throw new Error(
      `${pubFile} is not a valid public key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const filename = publicKeyFingerprintFilename(fingerprint);
  const dest = join(trustedDir, filename);
  if (existsSync(dest)) {
    console.log(`${fingerprint} is already trusted (${basename(dest)})`);
    return;
  }
  writeFileSync(dest, pem);
  console.log(`trusted ${fingerprint}`);
  console.log(`  → ${dest}`);
  console.log();
  console.log("Don't forget to commit this file so other pushers' verifications succeed.");
}
