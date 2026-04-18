import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
} from "node:crypto";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureDir, isFile, userKeysDir } from "./paths.js";

export interface Keypair {
  privateKeyPem: string;
  publicKeyPem: string;
  fingerprint: string; // "sha256:<hex>"
}

const PRIVATE_KEY_FILE = "ed25519";
const PUBLIC_KEY_FILE = "ed25519.pub";

export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
  const publicKeyPem = publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;
  return {
    privateKeyPem,
    publicKeyPem,
    fingerprint: fingerprintFromPem(publicKeyPem),
  };
}

export function fingerprintFromPem(publicKeyPem: string): string {
  const pub = createPublicKey(publicKeyPem);
  const raw = pub.export({ type: "spki", format: "der" }) as Buffer;
  const hash = createHash("sha256").update(raw).digest("hex");
  return `sha256:${hash}`;
}

export function loadUserKeypair(): Keypair | null {
  const dir = userKeysDir();
  const privPath = join(dir, PRIVATE_KEY_FILE);
  const pubPath = join(dir, PUBLIC_KEY_FILE);
  if (!isFile(privPath) || !isFile(pubPath)) return null;
  const privateKeyPem = readFileSync(privPath, "utf8");
  const publicKeyPem = readFileSync(pubPath, "utf8");
  return {
    privateKeyPem,
    publicKeyPem,
    fingerprint: fingerprintFromPem(publicKeyPem),
  };
}

export function saveUserKeypair(kp: Keypair): void {
  const dir = userKeysDir();
  ensureDir(dir, 0o700);
  chmodSync(dir, 0o700);
  const privPath = join(dir, PRIVATE_KEY_FILE);
  const pubPath = join(dir, PUBLIC_KEY_FILE);
  writeFileSync(privPath, kp.privateKeyPem, { mode: 0o600 });
  writeFileSync(pubPath, kp.publicKeyPem, { mode: 0o644 });
}

export function ensureUserKeypair(): {
  keypair: Keypair;
  created: boolean;
} {
  const existing = loadUserKeypair();
  if (existing) return { keypair: existing, created: false };
  const kp = generateKeypair();
  saveUserKeypair(kp);
  return { keypair: kp, created: true };
}

export function publicKeyFingerprintFilename(fingerprint: string): string {
  // "sha256:abc..." -> "sha256_abc....pub" (colons are valid on unix but messy)
  return fingerprint.replace(":", "_") + ".pub";
}

export function publicKeyFromObject(obj: KeyObject): string {
  return obj.export({ type: "spki", format: "pem" }) as string;
}
