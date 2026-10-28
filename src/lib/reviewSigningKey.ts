/**
 * Server-side Ed25519 review-signing key bootstrap (AGT-327 / M2).
 *
 * This module is the load-bearing source of truth for stamp-server's
 * review-signing key: the private key whose signatures over each
 * approval payload prove the verdict came from a real LLM call made
 * BY THE SERVER against the canonical reviewer prompt. The operator
 * cannot forge this signature — that's the entire point of the
 * server-attested reviews design (see
 * `docs/plans/server-attested-reviews.md`, "Trust model" / "Server
 * deployment artifact"). Idempotency is therefore non-negotiable:
 * every restart must reuse the same key, otherwise the fingerprint
 * the operator committed to `.stamp/trusted-keys/manifest.yml` stops
 * matching and every prior attestation chain breaks at verify time.
 *
 * Lifecycle:
 *
 *   1. Container boots, entrypoint resolves the key path (env override
 *      `REVIEW_SIGNING_KEY_PATH` or the default
 *      `$STAMP_STATE_DIR/review-signing-key.pem`).
 *   2. `ensureReviewSigningKey({ path })` is invoked.
 *      - File absent → generate a fresh Ed25519 keypair, write the
 *        private half mode 0600 + public half mode 0644, return with
 *        `created: true`.
 *      - File present, regular file owned by the loading process
 *        (root in the container), mode 0600, readable → load + return
 *        with `created: false`. Same fingerprint as the previous boot.
 *      - File present but wrong owner / mode, a symlink, or unreadable
 *        → throw a structured
 *        error. The caller (bootstrap script) must abort startup;
 *        silently re-generating would rotate the server's identity
 *        without operator consent.
 *
 * What this module does NOT do:
 *
 * - Print to stderr / advertise the fingerprint. The bootstrap script
 *   wraps that; this module is plain library code with no side effects
 *   on stdio so it stays unit-testable.
 * - Resolve the path. Path resolution (the env-var override, the
 *   default-state-dir fallback) lives in the bootstrap script — this
 *   module takes an absolute path and operates on it.
 * - Consult `ANTHROPIC_API_KEY` or any other env var. The capability
 *   gate lives at the script layer; if review capability is disabled,
 *   the bootstrap script simply doesn't call into here.
 * - Validate that the path lives inside `$STATE_DIR`. Operators may
 *   legitimately override `REVIEW_SIGNING_KEY_PATH` to a mount of
 *   their choice (e.g. a secrets manager fuse mount).
 *
 * Companion to `src/lib/keys.ts`'s `ensureUserKeypair` (operator-side
 * signing key). That module manages keys at well-known paths under
 * `~/.stamp/keys/`; this one is path-driven so the server-side
 * deployment can pin the location via env without monkey-patching
 * resolution code.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
} from "node:crypto";
import {
  chmodSync,
  chownSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import { fingerprintFromPem } from "./keys.js";

/**
 * The required mode bits on the private key file. Standard
 * owner-only-read posture for any long-lived signing key on a shared
 * filesystem; matches the mode the operator's `~/.stamp/keys/ed25519`
 * file uses (see `saveUserKeypair`). OpenSSH-strict-perms semantics
 * apply by analogy: any group or other bits on a private key are a
 * misconfiguration the bootstrap MUST refuse to silently accept.
 */
export const REQUIRED_PRIVATE_KEY_MODE = 0o600;

/** Public-half mode. Matches the user-keypair posture; nothing reads
 *  the .pub file with strict-perms expectations, but uniform mode keeps
 *  operator mental-model simple. */
export const PUBLIC_KEY_MODE = 0o644;

/**
 * AGT-2263: the private key must be a regular file (never a symlink)
 * owned by the uid of the process loading it, with mode exactly 0600.
 *
 * In the container the only loaders are root — the boot-time bootstrap
 * (`stamp-bootstrap-review-key`) and the sudo-invoked signing helper
 * (`stamp-sign-approval`) — so this pins the key to root:root 0600 and
 * a git-owned key fails the load (and therefore the boot) loudly. The
 * git user never opens the file: `stamp-review` signs through the
 * helper. Expressing the rule as "owned by the loader" rather than
 * "owned by uid 0" keeps the module usable in tests and dev, where the
 * loader is an ordinary user.
 *
 * Refusing (rather than auto-chmod/chown) is deliberate: a wrong owner
 * or mode usually means a backup restore that dropped perms or another
 * process touching the file. The one sanctioned repair — the legacy
 * git-owned key left by pre-AGT-2263 images' boot-time `chown -R` — is
 * done explicitly, and logged, by the bootstrap script before it calls
 * in here.
 */
export function assertPrivateKeyPosture(
  privateKeyPath: string,
  st: Stats,
): void {
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} is not a regular file ` +
        `(symlinks are refused). Refusing to load.`,
    );
  }
  const expectedUid = process.getuid?.();
  if (expectedUid !== undefined && st.uid !== expectedUid) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} is owned by uid ${st.uid}; ` +
        `required uid ${expectedUid} (the process loading it — root on stamp-server). ` +
        `Refusing to load. Fix with: chown root:root ${privateKeyPath}`,
    );
  }
  const mode = st.mode & 0o777;
  if (mode !== REQUIRED_PRIVATE_KEY_MODE) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} has mode 0${mode.toString(8).padStart(3, "0")}; ` +
        `required 0${REQUIRED_PRIVATE_KEY_MODE.toString(8).padStart(3, "0")} (owner read+write, no group/other access). ` +
        `Refusing to load. Fix with: chmod 600 ${privateKeyPath}`,
    );
  }
}

/**
 * Read the PUBLIC half of the review-signing key (the `.pub` sibling)
 * and its fingerprint. This is what the git-user side (`stamp-review`)
 * uses to learn `server_key_id` and to check the signing helper's
 * output: it never touches the private key (AGT-2263). The `.pub` is
 * root-owned 0644, world-readable by design.
 */
export function readReviewSigningPublicKey(opts: {
  privateKeyPath: string;
}): { publicKeyPath: string; publicKeyPem: string; fingerprint: string } {
  const publicKeyPath = publicKeyPathFor(opts.privateKeyPath);
  let publicKeyPem: string;
  try {
    publicKeyPem = readFileSync(publicKeyPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ReviewSigningKeyError(
        `review-signing public key not found at ${publicKeyPath}. ` +
          `The server's bootstrap step (stamp-bootstrap-review-key) writes ` +
          `it on every boot. Check that ANTHROPIC_API_KEY is set on the ` +
          `server (so bootstrap runs) and that REVIEW_SIGNING_KEY_PATH / ` +
          `STAMP_STATE_DIR points at the persistent volume.`,
      );
    }
    throw new ReviewSigningKeyError(
      `review-signing public key at ${publicKeyPath} could not be read: ${(err as Error).message}`,
    );
  }
  let fingerprint: string;
  try {
    const pub = createPublicKey({ key: publicKeyPem, format: "pem" });
    if (pub.asymmetricKeyType !== "ed25519") {
      throw new Error(`expected ed25519, got ${pub.asymmetricKeyType ?? "<unknown>"}`);
    }
    fingerprint = fingerprintFromPem(publicKeyPem);
  } catch (err) {
    throw new ReviewSigningKeyError(
      `review-signing public key at ${publicKeyPath} is not a valid Ed25519 SPKI PEM: ${(err as Error).message}`,
    );
  }
  return { publicKeyPath, publicKeyPem, fingerprint };
}

/** Suffix swap for the public key path. The private key lives at
 *  `<base>.pem`; the public key lives at `<base>.pub`. This is the
 *  convention the design doc bakes in ("$STATE_DIR/review-signing-key.pem"
 *  + the public half fetched via SSH verb). */
export function publicKeyPathFor(privateKeyPath: string): string {
  // Replace a trailing .pem (case-sensitive) with .pub. If the operator
  // points REVIEW_SIGNING_KEY_PATH at something without a .pem suffix,
  // append .pub so we still produce a sibling file rather than
  // accidentally overwriting the private key.
  if (privateKeyPath.endsWith(".pem")) {
    return privateKeyPath.slice(0, -".pem".length) + ".pub";
  }
  return privateKeyPath + ".pub";
}

export interface ReviewSigningKeyResult {
  /** Absolute path of the private key file on disk. Echoed back so the
   *  caller doesn't have to track it separately when printing
   *  diagnostics. */
  privateKeyPath: string;
  /** Absolute path of the sibling public key file. */
  publicKeyPath: string;
  /** Private key as a Node `KeyObject` rather than a raw PEM string.
   *  This is the load-bearing security property of the return shape:
   *  `JSON.stringify` on a `KeyObject` produces `{}` by design, so a
   *  future caller that accidentally serializes the whole result
   *  (structured logging, error contexts, `JSON.stringify(result)`)
   *  cannot leak the private material. Signing call sites use
   *  `crypto.sign(null, data, privateKey)` directly against this
   *  object; callers that need PEM bytes for disk writes have the
   *  paths and can read from disk explicitly. */
  privateKey: KeyObject;
  /** PEM-encoded public key (spki). Safe to log/serialize. */
  publicKeyPem: string;
  /** `sha256:<hex>` over the SPKI DER bytes — matches `fingerprintFromPem`
   *  output so the same string round-trips into
   *  `.stamp/trusted-keys/manifest.yml` and `attestationV4.server_key_id`. */
  fingerprint: string;
  /** `true` on the boot that minted the key; `false` on every
   *  subsequent boot that reused it. Drives the loud first-boot
   *  fingerprint advertisement in the bootstrap script. */
  created: boolean;
}

/**
 * Error class for fatal bootstrap conditions. The bootstrap script
 * catches this specifically and converts it into a non-zero exit with
 * the operator-readable message — distinct from generic Node EACCES/
 * ENOENT errors which usually indicate orchestration bugs (volume not
 * mounted yet, etc.) and should bubble with their original stack.
 */
export class ReviewSigningKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReviewSigningKeyError";
  }
}

/**
 * Ensure a review-signing keypair exists at `privateKeyPath`, generating
 * one on first call and reusing it on subsequent calls. See the module
 * docstring for the full lifecycle contract.
 *
 * Throws `ReviewSigningKeyError` on conditions where silent recovery
 * would compromise the trust model:
 *   - Existing private key has group/other permission bits set, is
 *     owned by another uid, or is a symlink (AGT-2263)
 *   - Existing private key file is unreadable
 *   - Existing private key parses but the public key derivation fails
 *
 * Generic FS errors (write failure, parent dir not writable, etc.) bubble
 * with their original error so platform misconfiguration surfaces
 * clearly rather than getting wrapped into an opaque domain error.
 */
export function ensureReviewSigningKey(opts: {
  privateKeyPath: string;
}): ReviewSigningKeyResult {
  const privateKeyPath = opts.privateKeyPath;
  const publicKeyPath = publicKeyPathFor(privateKeyPath);

  // Look for an existing private key first. The presence-or-absence
  // check is done via statSync (rather than readFileSync + ENOENT
  // catch) so we can also inspect the mode before reading the bytes —
  // a wrong-mode file should abort before we even open it.
  let existingStat: Stats;
  try {
    existingStat = lstatSync(privateKeyPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // First-boot path: mint a new key.
      return mintNewKey(privateKeyPath, publicKeyPath);
    }
    // Any other stat error (EACCES on the parent dir, EIO, etc.) is
    // an environment problem the operator needs to see verbatim.
    throw err;
  }

  // File exists — verify mode before reading.
  //
  // statSync's mode field is the full st_mode, including the file-type
  // bits in the high half. Mask to the low 9 bits (rwxrwxrwx) for the
  // permission compare. Anything other than exactly 0600 (owner rw,
  // no group, no other) is a refusal: a 0640 file leaks the key to
  // any group member, a 0644 file leaks it world-wide. We refuse
  // rather than auto-chmod because the wrong mode is often a sign
  // that someone restored from a backup that didn't preserve perms,
  // or that an unrelated process is touching the file — either way,
  // failing loud is correct.
  assertPrivateKeyPosture(privateKeyPath, existingStat);

  // Mode looks right — read and parse. We materialize the PEM as a
  // string only as long as it takes to construct the KeyObject, then
  // discard it: the public return surface holds the opaque
  // KeyObject (non-serializable, can't accidentally leak via
  // JSON.stringify) and the derived public-half PEM (safe to log).
  // A caller that wants to sign feeds the KeyObject directly to
  // crypto.sign(null, data, privateKey).
  let privateKey: KeyObject;
  let publicKeyPem: string;
  let fingerprint: string;
  try {
    const privateKeyPem = readFileSync(privateKeyPath, "utf8");
    privateKey = createPrivateKey({ key: privateKeyPem, format: "pem" });
  } catch (err) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} could not be loaded: ${(err as Error).message}`,
    );
  }

  // Re-derive the public half from the private key rather than reading
  // the .pub file. The .pub file is a convenience for the SSH verb that
  // serves the pubkey; the signing identity is whatever the private key
  // says it is. If a future operator deletes the .pub file by accident
  // we still want the server to come up.
  try {
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `expected asymmetricKeyType=ed25519, got ${privateKey.asymmetricKeyType ?? "<unknown>"}`,
      );
    }
    publicKeyPem = exportPublicPem(privateKey);
    fingerprint = fingerprintFromPem(publicKeyPem);
  } catch (err) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} could not be parsed as an Ed25519 private key: ` +
        `${(err as Error).message}`,
    );
  }

  // Re-write the public key file if it's missing OR out of sync with
  // the private key. Out-of-sync is the more interesting case: an
  // operator who manually swaps the private key (e.g. for rotation
  // ahead of the dedicated rotate command) would leave stale public
  // bytes on disk otherwise, and the SSH pubkey verb would then serve
  // a fingerprint that doesn't match what the server is actually
  // signing with. Idempotent on the common path (read existing,
  // compare, no-op).
  try {
    const existingPub = readFileSync(publicKeyPath, "utf8");
    if (existingPub !== publicKeyPem) {
      writeFileSync(publicKeyPath, publicKeyPem, { mode: PUBLIC_KEY_MODE });
      chmodSync(publicKeyPath, PUBLIC_KEY_MODE);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      writeFileSync(publicKeyPath, publicKeyPem, { mode: PUBLIC_KEY_MODE });
      chmodSync(publicKeyPath, PUBLIC_KEY_MODE);
    } else {
      throw err;
    }
  }

  return {
    privateKeyPath,
    publicKeyPath,
    privateKey,
    publicKeyPem,
    fingerprint,
    created: false,
  };
}

/** Helper: derive the SPKI PEM bytes for the public half of a private
 *  key object. `createPublicKey` accepts a private `KeyObject` and
 *  returns the corresponding public `KeyObject`; `.export({type:"spki",
 *  format:"pem"})` produces the PEM bytes. Public PEM is the form the
 *  rest of the codebase uses for `fingerprintFromPem` + the .pub
 *  sibling file. */
function exportPublicPem(privateKey: KeyObject): string {
  const publicKeyObj = createPublicKey(privateKey);
  return publicKeyObj.export({ type: "spki", format: "pem" }) as string;
}

/**
 * Load an existing review-signing keypair from `privateKeyPath`. Unlike
 * `ensureReviewSigningKey`, this is the runtime-request path — if the
 * key file is absent we THROW (`ReviewSigningKeyError`) rather than
 * minting a fresh one. Auto-minting on every review request would let
 * a transient FS hiccup (volume not yet mounted, key file unlinked by
 * a misconfigured tool) silently rotate the server's identity mid-flight,
 * which is the exact failure mode the trust model exists to prevent.
 *
 * The bootstrap script (`src/server/bootstrap-review-key.ts`) is the
 * ONLY caller permitted to mint — it runs once per container boot, as
 * root, before sshd accepts connections. The only other caller is the
 * root signing helper (`src/server/sign-approval.ts`, AGT-2263), which
 * the git-user review pipeline invokes through one sudoers rule; the
 * pipeline itself never loads the private key. Every loader MUST use
 * this function so the "key is stable across boots" invariant is
 * structural rather than convention.
 *
 * Mode + parse validation are the same as `ensureReviewSigningKey`: a
 * wrong-mode or unparseable file throws. The realistic load-time failure
 * mode is "file went missing" — likely a deployment misconfiguration the
 * operator needs to see verbatim.
 */
export function loadReviewSigningKey(opts: {
  privateKeyPath: string;
}): ReviewSigningKeyResult {
  const privateKeyPath = opts.privateKeyPath;
  const publicKeyPath = publicKeyPathFor(privateKeyPath);

  let existingStat: Stats;
  try {
    existingStat = lstatSync(privateKeyPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ReviewSigningKeyError(
        `review-signing key not found at ${privateKeyPath}. ` +
          `The server's bootstrap step (stamp-bootstrap-review-key) is ` +
          `expected to mint this on first boot. Check that ` +
          `ANTHROPIC_API_KEY is set on the server (so bootstrap runs) ` +
          `and that REVIEW_SIGNING_KEY_PATH / STAMP_STATE_DIR points at ` +
          `a writable volume that persists across restarts.`,
      );
    }
    throw err;
  }

  assertPrivateKeyPosture(privateKeyPath, existingStat);

  let privateKey: KeyObject;
  let publicKeyPem: string;
  let fingerprint: string;
  try {
    const privateKeyPem = readFileSync(privateKeyPath, "utf8");
    privateKey = createPrivateKey({ key: privateKeyPem, format: "pem" });
  } catch (err) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} could not be loaded: ${(err as Error).message}`,
    );
  }

  try {
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `expected asymmetricKeyType=ed25519, got ${privateKey.asymmetricKeyType ?? "<unknown>"}`,
      );
    }
    publicKeyPem = exportPublicPem(privateKey);
    fingerprint = fingerprintFromPem(publicKeyPem);
  } catch (err) {
    throw new ReviewSigningKeyError(
      `review-signing key at ${privateKeyPath} could not be parsed as an Ed25519 private key: ` +
        `${(err as Error).message}`,
    );
  }

  return {
    privateKeyPath,
    publicKeyPath,
    privateKey,
    publicKeyPem,
    fingerprint,
    created: false,
  };
}

/**
 * Resolve the absolute path to the review-signing private key from env
 * variables, mirroring the precedence the bootstrap script uses:
 *
 *   1. `REVIEW_SIGNING_KEY_PATH` (explicit override)
 *   2. `$STAMP_STATE_DIR/review-signing-key.pem`
 *   3. `/srv/git/.stamp-state/review-signing-key.pem` (container default)
 *
 * Kept here (not duplicated in bootstrap-review-key.ts) so that the
 * pipeline at request time and the bootstrap at boot time always agree
 * on which file is "the" signing key. A future move (e.g. to a secrets-
 * manager mount) only needs to update one resolver.
 */
export function resolveReviewSigningKeyPath(): string {
  const override = process.env["REVIEW_SIGNING_KEY_PATH"];
  if (override && override.length > 0) return override;
  const stateDir = process.env["STAMP_STATE_DIR"] ?? "/srv/git/.stamp-state";
  return stateDir.replace(/\/+$/, "") + "/review-signing-key.pem";
}

/**
 * First-boot path. Creates the parent directory if missing (so a fresh
 * volume that hasn't seen `mkdir -p $STAMP_STATE_DIR` yet still works,
 * though entrypoint.sh does that anyway), then writes both halves of a
 * fresh Ed25519 keypair with the correct modes. Two chmod calls per
 * file rather than relying on writeFileSync's `mode` option alone:
 * Node's writeFileSync honors `mode` only on file CREATION, not on
 * write to an existing file, and a chmod after the write is the
 * canonical defensive pattern.
 */
function mintNewKey(
  privateKeyPath: string,
  publicKeyPath: string,
): ReviewSigningKeyResult {
  // Ensure the parent directory exists. Mode 0700 is conservative —
  // the parent is typically `$STAMP_STATE_DIR` which entrypoint.sh
  // already sets up with broader bits for the git user, so this is
  // really just a safety net for `mkdir -p` semantics when the
  // bootstrap is invoked outside the container (tests, dev).
  const parent = dirname(privateKeyPath);
  mkdirSync(parent, { recursive: true, mode: 0o700 });

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // PEM serialization is needed once for the on-disk write; after that
  // the PEM string goes out of scope and only the KeyObject is held
  // on the returned result. Mirrors the load path's "materialize
  // briefly, then drop" pattern so accidental serialization of the
  // result can't leak the private bytes.
  const privateKeyPem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
  const publicKeyPem = publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;

  writeFileSync(privateKeyPath, privateKeyPem, {
    mode: REQUIRED_PRIVATE_KEY_MODE,
  });
  chmodSync(privateKeyPath, REQUIRED_PRIVATE_KEY_MODE);

  writeFileSync(publicKeyPath, publicKeyPem, { mode: PUBLIC_KEY_MODE });
  chmodSync(publicKeyPath, PUBLIC_KEY_MODE);

  return {
    privateKeyPath,
    publicKeyPath,
    privateKey,
    publicKeyPem,
    fingerprint: fingerprintFromPem(publicKeyPem),
    created: true,
  };
}

/**
 * AGT-2263 upgrade path. Images before AGT-2263 ran `chown -R git:git
 * /srv/git` on every boot, which left the review-signing key (and its
 * `.pub`) owned by the git user. The new posture is root:root, and
 * `assertPrivateKeyPosture` refuses anything else — so the bootstrap,
 * running as root, first re-owns files in exactly that legacy state:
 * a regular file (never a symlink — lchown semantics are not relied on,
 * the file is skipped) owned by the git user's uid. Any other foreign
 * owner is left alone and fails the boot loudly.
 *
 * Returns the paths it re-owned so the caller can log them. `chown` is
 * injectable for tests (only root can really chown to 0).
 */
export function reownLegacyGitOwnedKeyFiles(opts: {
  privateKeyPath: string;
  gitUid: number;
  chown?: (path: string, uid: number, gid: number) => void;
}): string[] {
  const chown = opts.chown ?? chownSync;
  const reowned: string[] = [];
  if (opts.gitUid === 0) return reowned;
  for (const p of [opts.privateKeyPath, publicKeyPathFor(opts.privateKeyPath)]) {
    let st: Stats;
    try {
      st = lstatSync(p);
    } catch {
      continue;
    }
    if (!st.isFile() || st.isSymbolicLink()) continue;
    if (st.uid !== opts.gitUid) continue;
    chown(p, 0, 0);
    reowned.push(p);
  }
  return reowned;
}

/** uid of the `git` account from /etc/passwd, or null if absent. */
export function lookupGitUid(passwdPath = "/etc/passwd"): number | null {
  let text: string;
  try {
    text = readFileSync(passwdPath, "utf8");
  } catch {
    return null;
  }
  for (const line of text.split("\n")) {
    const f = line.split(":");
    if (f[0] === "git" && f.length >= 3) {
      const uid = Number(f[2]);
      return Number.isInteger(uid) ? uid : null;
    }
  }
  return null;
}
