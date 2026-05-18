/**
 * Unit tests for the review-signing-key bootstrap library
 * (`src/lib/reviewSigningKey.ts`).
 *
 * The module is the load-bearing implementation of AGT-327: first-boot
 * generation, idempotent reuse, wrong-mode refusal. The library is
 * tested at the API surface (no process-spawning) so we can exercise
 * the exact edge cases the design contract names without paying tsx
 * startup cost per case. End-to-end behavior of the entrypoint script
 * lives in `serverBootstrapReviewKey.test.ts`.
 *
 * Properties covered:
 *
 *   - First call on an empty directory generates an Ed25519 keypair
 *     with the .pem and .pub files at the expected paths, mode 0600
 *     and 0644 respectively, returning created=true.
 *   - Second call against the same path reuses the existing key —
 *     created=false, same fingerprint as the first call.
 *   - Third+ calls remain idempotent (no accumulated state).
 *   - A wrong-mode private key (0640 / 0644 / 0700) throws
 *     ReviewSigningKeyError with a chmod hint, does NOT regenerate.
 *   - A missing parent directory is created with mode 0700.
 *   - A stale .pub file (left over from a prior key pair) is
 *     rewritten to match the current private key — keeps the SSH
 *     verb's pubkey output in lockstep with what the server is
 *     actually signing with.
 *   - A missing .pub file (sibling deleted while .pem survived) is
 *     re-derived from the private key on the next call.
 *   - publicKeyPathFor() swaps a .pem suffix to .pub and appends
 *     .pub when the input doesn't end in .pem (avoids accidentally
 *     overwriting the private key).
 */

import { strict as assert } from "node:assert";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { fingerprintFromPem } from "../src/lib/keys.ts";
import {
  ensureReviewSigningKey,
  loadReviewSigningKey,
  publicKeyPathFor,
  resolveReviewSigningKeyPath,
  ReviewSigningKeyError,
} from "../src/lib/reviewSigningKey.ts";

function tmpDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-review-key-"));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

describe("publicKeyPathFor", () => {
  it("swaps trailing .pem with .pub", () => {
    assert.equal(
      publicKeyPathFor("/srv/git/.stamp-state/review-signing-key.pem"),
      "/srv/git/.stamp-state/review-signing-key.pub",
    );
  });

  it("appends .pub when input lacks a .pem suffix", () => {
    // Operator override pointing at a file without an extension — we
    // must NOT silently overwrite the private key, so append rather
    // than mutate.
    assert.equal(
      publicKeyPathFor("/var/secrets/server-key"),
      "/var/secrets/server-key.pub",
    );
  });

  it("does not strip .pem in the middle of the path", () => {
    // .pem appears in a directory name; only the trailing component
    // ending in .pem should be treated as a suffix.
    assert.equal(
      publicKeyPathFor("/srv/.pem-mounts/review.bin"),
      "/srv/.pem-mounts/review.bin.pub",
    );
  });
});

describe("ensureReviewSigningKey — first-boot generation", () => {
  it("mints a fresh Ed25519 keypair when the file does not exist", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const pubPath = path.join(t.dir, "review-signing-key.pub");

      assert.equal(existsSync(keyPath), false, "precondition: no key yet");

      const result = ensureReviewSigningKey({ privateKeyPath: keyPath });

      assert.equal(result.created, true);
      assert.equal(result.privateKeyPath, keyPath);
      assert.equal(result.publicKeyPath, pubPath);
      assert.match(result.fingerprint, /^sha256:[0-9a-f]{64}$/);

      // Disk state.
      assert.equal(existsSync(keyPath), true);
      assert.equal(existsSync(pubPath), true);

      // Mode checks. On many CI/dev shells the umask filters mode bits
      // on writeFileSync's first write — the bootstrap module follows
      // up with an explicit chmod which is what we're verifying here.
      assert.equal(statSync(keyPath).mode & 0o777, 0o600);
      assert.equal(statSync(pubPath).mode & 0o777, 0o644);

      // Content checks. The .pub file content matches the returned
      // PEM, and the fingerprint round-trips through fingerprintFromPem
      // against the returned public key. We deliberately do NOT assert
      // on a private-key string field — `result.privateKey` is a
      // KeyObject (not a PEM string) so it can't accidentally leak via
      // JSON.stringify. Verify the on-disk private PEM separately by
      // shape; the round-trip "load + reuse" tests below cover that
      // the saved bytes round-trip into an equivalent fingerprint.
      assert.equal(readFileSync(pubPath, "utf8"), result.publicKeyPem);
      assert.equal(
        fingerprintFromPem(result.publicKeyPem),
        result.fingerprint,
      );
      const onDiskPriv = readFileSync(keyPath, "utf8");
      assert.match(onDiskPriv, /-----BEGIN PRIVATE KEY-----/);
      assert.match(onDiskPriv, /-----END PRIVATE KEY-----/);

      // Security property check: result.privateKey is a KeyObject that
      // JSON.stringify renders as `{}` — accidental serialization of
      // the whole result cannot leak the key material. This is what
      // security review (#753) explicitly asked for.
      assert.equal(JSON.stringify(result.privateKey), "{}");
      assert.equal(result.privateKey.type, "private");
      assert.equal(result.privateKey.asymmetricKeyType, "ed25519");
    } finally {
      t.cleanup();
    }
  });

  it("creates the parent directory if missing", () => {
    const t = tmpDir();
    try {
      // Nest two levels deep — neither parent exists yet.
      const keyPath = path.join(t.dir, "nested", "deeper", "key.pem");
      const result = ensureReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(result.created, true);
      assert.equal(existsSync(keyPath), true);
    } finally {
      t.cleanup();
    }
  });
});

describe("ensureReviewSigningKey — idempotent reuse", () => {
  it("returns the existing key on the second call", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");

      const first = ensureReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(first.created, true);

      const second = ensureReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(second.created, false);
      assert.equal(second.fingerprint, first.fingerprint);
      assert.equal(second.publicKeyPem, first.publicKeyPem);
      // Private-key identity: the KeyObjects on either side both
      // derive (or originate from) the same on-disk PEM, so their
      // public halves agree. Comparing KeyObjects directly via === is
      // not meaningful (different references); the fingerprint
      // equality above is the load-bearing assertion.
    } finally {
      t.cleanup();
    }
  });

  it("remains idempotent across many calls", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");

      const first = ensureReviewSigningKey({ privateKeyPath: keyPath });
      for (let i = 0; i < 5; i++) {
        const r = ensureReviewSigningKey({ privateKeyPath: keyPath });
        assert.equal(r.created, false);
        assert.equal(r.fingerprint, first.fingerprint);
      }
    } finally {
      t.cleanup();
    }
  });

  it("re-derives the public key file if it has been deleted", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const pubPath = path.join(t.dir, "review-signing-key.pub");

      const first = ensureReviewSigningKey({ privateKeyPath: keyPath });
      rmSync(pubPath);
      assert.equal(existsSync(pubPath), false);

      const second = ensureReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(second.created, false);
      assert.equal(existsSync(pubPath), true);
      assert.equal(readFileSync(pubPath, "utf8"), first.publicKeyPem);
    } finally {
      t.cleanup();
    }
  });

  it("rewrites a stale .pub file that doesn't match the private key", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const pubPath = path.join(t.dir, "review-signing-key.pub");

      const first = ensureReviewSigningKey({ privateKeyPath: keyPath });

      // Corrupt the .pub file with unrelated bytes — simulates a
      // botched manual rotation where someone replaced the .pem but
      // left a stale .pub on disk. Idempotency must self-heal this so
      // the SSH pubkey verb keeps serving truth.
      writeFileSync(pubPath, "-----BEGIN BOGUS-----\nstale\n-----END BOGUS-----\n");

      const second = ensureReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(second.created, false);
      assert.equal(readFileSync(pubPath, "utf8"), first.publicKeyPem);
    } finally {
      t.cleanup();
    }
  });
});

describe("ensureReviewSigningKey — wrong-mode refusal", () => {
  // Wrong-mode permutations the test should reject. Group-read (0640)
  // and world-read (0644) are the cases that actually leak the key;
  // owner-rwx (0700) is a less severe but still incorrect mode that
  // the function refuses on principle (the contract is "exactly 0600",
  // not "no group/other read").
  const wrongModes = [0o640, 0o644, 0o660, 0o664, 0o700, 0o755];

  for (const mode of wrongModes) {
    it(`throws ReviewSigningKeyError when the private key is mode 0${mode.toString(8)}`, () => {
      const t = tmpDir();
      try {
        const keyPath = path.join(t.dir, "review-signing-key.pem");
        // Seed a key file at the target path, then chmod to the wrong
        // mode. Generating via the function first guarantees the file
        // contains a valid Ed25519 key — we want the mode check to
        // fire BEFORE the parse path, so the test must use a real key
        // to prove the mode check is what's failing (a corrupt-bytes
        // file would also throw, but for the wrong reason).
        ensureReviewSigningKey({ privateKeyPath: keyPath });
        chmodSync(keyPath, mode);

        assert.throws(
          () => ensureReviewSigningKey({ privateKeyPath: keyPath }),
          (err: Error) => {
            assert.ok(
              err instanceof ReviewSigningKeyError,
              `expected ReviewSigningKeyError, got ${err.constructor.name}: ${err.message}`,
            );
            assert.match(err.message, /has mode/);
            assert.match(err.message, /chmod 600/);
            return true;
          },
        );

        // Verify NO regeneration happened — same file content, same
        // wrong mode preserved.
        assert.equal(statSync(keyPath).mode & 0o777, mode);
      } finally {
        t.cleanup();
      }
    });
  }

  it("does not throw for mode 0600 (the required mode)", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      ensureReviewSigningKey({ privateKeyPath: keyPath });
      // First-call writeFileSync may produce 0600 already; assert
      // it's there and re-call to confirm no throw.
      assert.equal(statSync(keyPath).mode & 0o777, 0o600);
      const r = ensureReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(r.created, false);
    } finally {
      t.cleanup();
    }
  });

  it("throws ReviewSigningKeyError when the file is not a valid Ed25519 private key", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      mkdirSync(t.dir, { recursive: true });
      writeFileSync(keyPath, "not a pem at all\n", { mode: 0o600 });

      assert.throws(
        () => ensureReviewSigningKey({ privateKeyPath: keyPath }),
        (err: Error) => {
          assert.ok(err instanceof ReviewSigningKeyError);
          // Either "could not be loaded" (createPrivateKey blew up
          // on malformed bytes) or "could not be parsed" (createPrivateKey
          // succeeded but produced a non-Ed25519 key, which the
          // post-parse asymmetricKeyType guard rejects). Both are
          // valid failure paths for an invalid file.
          assert.match(err.message, /could not be (loaded|parsed)/);
          return true;
        },
      );
    } finally {
      t.cleanup();
    }
  });
});

// ─── AGT-331: loadReviewSigningKey ─────────────────────────────────

describe("loadReviewSigningKey", () => {
  it("loads an existing key without mutating disk", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const minted = ensureReviewSigningKey({ privateKeyPath: keyPath });
      const beforePrivateBytes = readFileSync(keyPath, "utf8");
      const beforePublicBytes = readFileSync(minted.publicKeyPath, "utf8");

      const loaded = loadReviewSigningKey({ privateKeyPath: keyPath });
      assert.equal(loaded.fingerprint, minted.fingerprint);
      assert.equal(loaded.publicKeyPem, minted.publicKeyPem);
      assert.equal(loaded.created, false);

      // Loader must be read-only — production servers mount the key as
      // read-only via secrets-manager, and a load-time rewrite would
      // fail the deployment.
      assert.equal(readFileSync(keyPath, "utf8"), beforePrivateBytes);
      assert.equal(readFileSync(minted.publicKeyPath, "utf8"), beforePublicBytes);
    } finally {
      t.cleanup();
    }
  });

  it("throws ReviewSigningKeyError with operator-actionable prose when the key is absent", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "no-such-key.pem");
      assert.throws(
        () => loadReviewSigningKey({ privateKeyPath: keyPath }),
        (err: Error) => {
          assert.ok(err instanceof ReviewSigningKeyError);
          assert.match(err.message, /review-signing key not found/);
          // The message names the bootstrap step and STAMP_STATE_DIR so
          // operators know where to look — this is the load-bearing
          // operator-facing surface.
          assert.match(err.message, /stamp-bootstrap-review-key/);
          assert.match(err.message, /REVIEW_SIGNING_KEY_PATH|STAMP_STATE_DIR/);
          return true;
        },
      );
    } finally {
      t.cleanup();
    }
  });

  it("refuses to load a wrong-mode key (refuses to auto-chmod)", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      ensureReviewSigningKey({ privateKeyPath: keyPath });
      // Simulate a wrong-mode key restored from backup.
      chmodSync(keyPath, 0o640);
      assert.throws(
        () => loadReviewSigningKey({ privateKeyPath: keyPath }),
        (err: Error) => {
          assert.ok(err instanceof ReviewSigningKeyError);
          assert.match(err.message, /mode 0640/);
          assert.match(err.message, /required 0600/);
          return true;
        },
      );
    } finally {
      t.cleanup();
    }
  });

  it("never mints — distinct from ensureReviewSigningKey", () => {
    // Belt-and-suspenders: confirm the load path doesn't fall back to
    // mint-on-missing semantics. Without this guard, a future refactor
    // that accidentally aliased the two functions would silently rotate
    // server identity on every restart.
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      assert.equal(existsSync(keyPath), false);
      assert.throws(() => loadReviewSigningKey({ privateKeyPath: keyPath }));
      assert.equal(existsSync(keyPath), false, "loader minted a key it shouldn't have");
    } finally {
      t.cleanup();
    }
  });
});

describe("resolveReviewSigningKeyPath", () => {
  it("honors REVIEW_SIGNING_KEY_PATH when set", () => {
    const saved = process.env.REVIEW_SIGNING_KEY_PATH;
    try {
      process.env.REVIEW_SIGNING_KEY_PATH = "/opt/secrets/custom-key.pem";
      assert.equal(resolveReviewSigningKeyPath(), "/opt/secrets/custom-key.pem");
    } finally {
      if (saved === undefined) delete process.env.REVIEW_SIGNING_KEY_PATH;
      else process.env.REVIEW_SIGNING_KEY_PATH = saved;
    }
  });

  it("falls back to STAMP_STATE_DIR/review-signing-key.pem when override unset", () => {
    const savedKey = process.env.REVIEW_SIGNING_KEY_PATH;
    const savedDir = process.env.STAMP_STATE_DIR;
    try {
      delete process.env.REVIEW_SIGNING_KEY_PATH;
      process.env.STAMP_STATE_DIR = "/tmp/custom-state-dir";
      assert.equal(
        resolveReviewSigningKeyPath(),
        "/tmp/custom-state-dir/review-signing-key.pem",
      );
    } finally {
      if (savedKey === undefined) delete process.env.REVIEW_SIGNING_KEY_PATH;
      else process.env.REVIEW_SIGNING_KEY_PATH = savedKey;
      if (savedDir === undefined) delete process.env.STAMP_STATE_DIR;
      else process.env.STAMP_STATE_DIR = savedDir;
    }
  });

  it("strips trailing slashes on STAMP_STATE_DIR", () => {
    const savedKey = process.env.REVIEW_SIGNING_KEY_PATH;
    const savedDir = process.env.STAMP_STATE_DIR;
    try {
      delete process.env.REVIEW_SIGNING_KEY_PATH;
      process.env.STAMP_STATE_DIR = "/tmp/custom-state-dir///";
      assert.equal(
        resolveReviewSigningKeyPath(),
        "/tmp/custom-state-dir/review-signing-key.pem",
      );
    } finally {
      if (savedKey === undefined) delete process.env.REVIEW_SIGNING_KEY_PATH;
      else process.env.REVIEW_SIGNING_KEY_PATH = savedKey;
      if (savedDir === undefined) delete process.env.STAMP_STATE_DIR;
      else process.env.STAMP_STATE_DIR = savedDir;
    }
  });

  it("falls back to /srv/git/.stamp-state/review-signing-key.pem when no env is set", () => {
    const savedKey = process.env.REVIEW_SIGNING_KEY_PATH;
    const savedDir = process.env.STAMP_STATE_DIR;
    try {
      delete process.env.REVIEW_SIGNING_KEY_PATH;
      delete process.env.STAMP_STATE_DIR;
      assert.equal(
        resolveReviewSigningKeyPath(),
        "/srv/git/.stamp-state/review-signing-key.pem",
      );
    } finally {
      if (savedKey === undefined) delete process.env.REVIEW_SIGNING_KEY_PATH;
      else process.env.REVIEW_SIGNING_KEY_PATH = savedKey;
      if (savedDir === undefined) delete process.env.STAMP_STATE_DIR;
      else process.env.STAMP_STATE_DIR = savedDir;
    }
  });
});
