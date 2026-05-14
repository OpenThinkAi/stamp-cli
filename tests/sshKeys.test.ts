/**
 * SSH pubkey parsing + fingerprint regression tests. The fingerprint format
 * is load-bearing: the AuthorizedKeysCommand resolver looks users up by the
 * exact string sshd emits via %f. If the format ever drifts from sshd's
 * own, every connection silently misses the DB and falls back to the
 * legacy AuthorizedKeysFile — a regression that would be invisible in
 * normal operation (legacy path still works) but break the entire phase 2+
 * onboarding surface.
 *
 * Fingerprints below were computed externally with `ssh-keygen -lf` against
 * the corresponding pubkey to lock the format. Any change to
 * sshFingerprintFromBlob must keep these tests green.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  parseSshPubkey,
  parseSshPubkeyList,
  sshFingerprintFromBlob,
} from "../src/lib/sshKeys.ts";

// Real ed25519 pubkey + its ssh-keygen-computed SHA256 fingerprint. Pinned
// here so a drift in our fingerprint impl is loud, not silent.
const ED25519_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b tester@example";
const ED25519_FINGERPRINT = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

describe("parseSshPubkey", () => {
  it("parses an ed25519 line into algo / blob / comment / fingerprint", () => {
    const pk = parseSshPubkey(ED25519_LINE);
    assert.equal(pk.algorithm, "ssh-ed25519");
    assert.equal(pk.comment, "tester@example");
    assert.equal(pk.fingerprint, ED25519_FINGERPRINT);
    assert.equal(pk.full, ED25519_LINE);
    assert.ok(pk.keyBlob.length > 0);
  });

  it("preserves the original line verbatim in `full`", () => {
    // Leading/trailing whitespace gets trimmed; internal whitespace is
    // collapsed by the split but `full` is the trimmed original, not a
    // re-join.
    const pk = parseSshPubkey(`  ${ED25519_LINE}\n`);
    assert.equal(pk.full, ED25519_LINE);
  });

  it("allows an empty comment", () => {
    const noComment = ED25519_LINE.split(" ").slice(0, 2).join(" ");
    const pk = parseSshPubkey(noComment);
    assert.equal(pk.comment, "");
    assert.equal(pk.fingerprint, ED25519_FINGERPRINT);
  });

  it("rejects an empty line", () => {
    assert.throws(() => parseSshPubkey(""), /empty/);
    assert.throws(() => parseSshPubkey("   "), /empty/);
  });

  it("rejects a comment line", () => {
    assert.throws(
      () => parseSshPubkey("# this is a comment"),
      /comment/,
    );
  });

  it("rejects an unsupported algorithm", () => {
    assert.throws(
      () => parseSshPubkey("ssh-dss AAAA dsa-is-deprecated"),
      /unsupported/,
    );
  });

  it("rejects a missing base64 blob", () => {
    assert.throws(() => parseSshPubkey("ssh-ed25519"), /at least/);
  });

  it("rejects a malformed base64 blob with stray chars", () => {
    // A pubkey line with a literal " character in the base64 — Buffer.from
    // would silently strip it, producing a fingerprint that mismatches
    // sshd's view. We catch that mismatch in parse.
    const bad = `ssh-ed25519 AAAAC3"NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka tester@example`;
    assert.throws(() => parseSshPubkey(bad), /trailing junk/);
  });
});

describe("sshFingerprintFromBlob", () => {
  it("reproduces the OpenSSH SHA256:<base64> format with no padding", () => {
    const pk = parseSshPubkey(ED25519_LINE);
    const fp = sshFingerprintFromBlob(pk.keyBlob);
    assert.equal(fp, ED25519_FINGERPRINT);
    assert.ok(fp.startsWith("SHA256:"));
    // No base64 padding
    assert.ok(!fp.includes("="));
  });
});

describe("parseSshPubkeyList", () => {
  it("parses multi-line input, dropping blanks and comments", () => {
    const blob = [
      "# leading comment",
      "",
      ED25519_LINE,
      "   ",
      "# another comment",
    ].join("\n");
    const { pubkeys, errors } = parseSshPubkeyList(blob);
    assert.equal(pubkeys.length, 1);
    assert.equal(errors.length, 0);
    assert.equal(pubkeys[0]?.fingerprint, ED25519_FINGERPRINT);
  });

  it("reports parse errors with line numbers, continues past bad lines", () => {
    const blob = [
      "ssh-dss AAAA bad-algo",
      ED25519_LINE,
      "garbage no-base64",
    ].join("\n");
    const { pubkeys, errors } = parseSshPubkeyList(blob);
    assert.equal(pubkeys.length, 1);
    assert.equal(errors.length, 2);
    assert.equal(errors[0]?.lineNumber, 1);
    assert.match(errors[0]?.error ?? "", /unsupported/);
    assert.equal(errors[1]?.lineNumber, 3);
  });
});
