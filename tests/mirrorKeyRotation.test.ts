/**
 * AGT-2242 (oaudit medium): `stamp provision --migrate-bypass` used to
 * delete the registered `stamp-mirror` deploy key and register whatever
 * pubkey the stamp server reported whenever the two differed. The deploy
 * key is a Ruleset bypass actor, so a substituted server-side key (git-shell
 * escape → overwrite the per-repo key file) became a GitHub bypass actor at
 * the next routine post-restart reconciliation.
 *
 * The decision is now made by the pure `decideMirrorKeyAction`: a mismatch
 * is refused unless `--replace-key` AND a matching `--expect-fingerprint`
 * approve it. Fingerprints are pinned against `ssh-keygen -lf` output for
 * the fixture keys below.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  decideMirrorKeyAction,
  validateExpectFingerprint,
} from "../src/lib/mirrorKeyRotation.ts";
import { runProvision } from "../src/commands/provision.ts";

// Fixture keypairs generated with `ssh-keygen -t ed25519`; fingerprints
// copied from `ssh-keygen -lf <file>.pub`.
const KEY_A =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG7dDFbtb238XC6DTDp10UOM172xJFsGVnwz90ssvnaa a@b";
const KEY_A_NO_COMMENT =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG7dDFbtb238XC6DTDp10UOM172xJFsGVnwz90ssvnaa";
const FP_A = "SHA256:5AUk9oSTwNmfPy/ZpJ8VQ9TL9u7oZW6NgZ8rvnKAEVc";
const KEY_B =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRdiShXZt0UBg8jmX0QEbmqPfUJjcGYJkrCf3n4Plc8";
const FP_B = "SHA256:lCvIO91U4QBhoBdXrkeVo0yIf5PDMQO+GGwMsuDAdZE";

const base = { owner: "acme", repo: "widgets" };

describe("decideMirrorKeyAction", () => {
  it("registers the server key when no stamp-mirror key exists", () => {
    const d = decideMirrorKeyAction({
      ...base,
      existingRegistered: false,
      existingBody: null,
      serverPubkey: KEY_B,
    });
    assert.deepEqual(d, { action: "register", fingerprint: FP_B });
  });

  it("is a no-op when the registered key matches (comment differences ignored)", () => {
    // GitHub returns the key without its comment; the server may include one.
    const d = decideMirrorKeyAction({
      ...base,
      existingRegistered: true,
      existingBody: KEY_A_NO_COMMENT,
      serverPubkey: KEY_A,
    });
    assert.deepEqual(d, { action: "reuse", fingerprint: FP_A });
  });

  it("REFUSES a mismatched server key by default and prints both fingerprints", () => {
    // The regression: this used to return "delete + re-register".
    assert.throws(
      () =>
        decideMirrorKeyAction({
          ...base,
          existingRegistered: true,
          existingBody: KEY_A,
          serverPubkey: KEY_B,
        }),
      (err: Error) => {
        assert.match(err.message, /Refusing to replace it automatically/);
        assert.ok(err.message.includes(FP_A), "old fingerprint shown");
        assert.ok(err.message.includes(FP_B), "new fingerprint shown");
        assert.match(err.message, /--replace-key --expect-fingerprint/);
        return true;
      },
    );
  });

  it("refuses when the registered key body is unreadable (never treated as safe to overwrite)", () => {
    assert.throws(
      () =>
        decideMirrorKeyAction({
          ...base,
          existingRegistered: true,
          existingBody: null,
          serverPubkey: KEY_B,
        }),
      /Refusing to replace it automatically[\s\S]*\(unreadable\)/,
    );
  });

  it("refuses --replace-key without --expect-fingerprint", () => {
    assert.throws(
      () =>
        decideMirrorKeyAction({
          ...base,
          existingRegistered: true,
          existingBody: KEY_A,
          serverPubkey: KEY_B,
          replaceKey: true,
        }),
      /--replace-key requires --expect-fingerprint/,
    );
  });

  it("refuses --replace-key when the server key does not match the pinned fingerprint", () => {
    // Attacker-substituted key: operator verified FP_A out-of-band, server
    // now reports KEY_B.
    assert.throws(
      () =>
        decideMirrorKeyAction({
          ...base,
          existingRegistered: true,
          existingBody: KEY_A_NO_COMMENT,
          serverPubkey: KEY_B,
          replaceKey: true,
          expectFingerprint: FP_A,
        }),
      /has fingerprint SHA256:lCvI[\s\S]*Refusing to register it/,
    );
  });

  it("replaces only with --replace-key AND a matching --expect-fingerprint", () => {
    const d = decideMirrorKeyAction({
      ...base,
      existingRegistered: true,
      existingBody: KEY_A_NO_COMMENT,
      serverPubkey: KEY_B,
      replaceKey: true,
      expectFingerprint: FP_B,
    });
    assert.deepEqual(d, {
      action: "replace",
      oldFingerprint: FP_A,
      fingerprint: FP_B,
    });
  });

  it("checks --expect-fingerprint on first registration too", () => {
    assert.throws(
      () =>
        decideMirrorKeyAction({
          ...base,
          existingRegistered: false,
          existingBody: null,
          serverPubkey: KEY_B,
          expectFingerprint: FP_A,
        }),
      /Refusing to register it/,
    );
    assert.deepEqual(
      decideMirrorKeyAction({
        ...base,
        existingRegistered: false,
        existingBody: null,
        serverPubkey: KEY_B,
        expectFingerprint: FP_B,
      }),
      { action: "register", fingerprint: FP_B },
    );
  });

  it("rejects a malformed server pubkey", () => {
    assert.throws(
      () =>
        decideMirrorKeyAction({
          ...base,
          existingRegistered: false,
          existingBody: null,
          serverPubkey: "not a key",
        }),
      /not a valid OpenSSH public key/,
    );
  });
});

describe("validateExpectFingerprint", () => {
  it("accepts ssh-keygen -lf output's fingerprint token", () => {
    assert.equal(validateExpectFingerprint(FP_A), FP_A);
    assert.equal(validateExpectFingerprint(`  ${FP_A}\n`), FP_A);
  });

  it("rejects other shapes", () => {
    for (const bad of ["", "5AUk9oSTwNmfPy/ZpJ8VQ9TL9u7oZW6NgZ8rvnKAEVc", "sha256:abc", "MD5:aa:bb", `${FP_A}x`]) {
      assert.throws(() => validateExpectFingerprint(bad), /--expect-fingerprint must be/);
    }
  });
});

describe("runProvision flag validation (AGT-2242)", () => {
  it("rejects --replace-key / --expect-fingerprint without --migrate-bypass", async () => {
    await assert.rejects(
      runProvision({ name: "x", replaceKey: true, expectFingerprint: FP_A }),
      /only meaningful with --migrate-bypass/,
    );
    await assert.rejects(
      runProvision({ name: "x", expectFingerprint: FP_A }),
      /only meaningful with --migrate-bypass/,
    );
  });

  it("rejects --replace-key without --expect-fingerprint before any remote work", async () => {
    await assert.rejects(
      runProvision({ name: "", migrateBypass: true, replaceKey: true }),
      /--replace-key requires --expect-fingerprint/,
    );
  });

  it("rejects a malformed --expect-fingerprint up front", async () => {
    await assert.rejects(
      runProvision({ name: "", migrateBypass: true, expectFingerprint: "nope" }),
      /--expect-fingerprint must be/,
    );
  });
});
