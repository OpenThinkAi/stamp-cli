/**
 * AGT-2249: peer-watch.log keeps routing metadata, not other authors' PR
 * content, and is owner-only on disk.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { appendTriplet, summarizeEventPayload } from "../src/lib/peerWatchLog.ts";

const EVENT = {
  repo: "acme/widget",
  patch_id: "a".repeat(40),
  base_sha: "b".repeat(40),
  head_sha: "c".repeat(40),
  requested_by_fp: "sha256:" + "d".repeat(64),
  pr_url: "https://github.com/acme/widget/pull/7",
  title: "Rotate the prod database password",
  body: "Private details about the incident",
  paths_changed: ["infra/secrets.tf", "README.md"],
  pubkey: "-----BEGIN PUBLIC KEY-----\nMCow...\n-----END PUBLIC KEY-----\n",
  signature: "c2ln",
};

describe("summarizeEventPayload", () => {
  it("keeps routing fields and replaces content with hashes and counts", () => {
    const s = summarizeEventPayload(EVENT);
    for (const k of ["repo", "patch_id", "base_sha", "head_sha", "requested_by_fp", "pr_url"]) {
      assert.equal(s[k], (EVENT as Record<string, unknown>)[k], `${k} should be kept`);
    }
    for (const k of ["title", "body", "paths_changed", "pubkey", "signature"]) {
      assert.ok(!(k in s), `${k} must not be logged`);
    }
    assert.match(String(s["title_sha256"]), /^[0-9a-f]{64}$/);
    assert.equal(s["title_length"], EVENT.title.length);
    assert.equal(s["paths_changed_count"], 2);
    assert.match(String(s["paths_changed_sha256"]), /^[0-9a-f]{64}$/);
  });
});

describe("appendTriplet privacy", () => {
  it("writes no PR content and creates the log 0600", () => {
    const dir = mkdtempSync(join(tmpdir(), "peer-watch-priv-"));
    const logPath = join(dir, "peer-watch.log");
    try {
      appendTriplet({
        ts: "2026-10-28T00:00:00.000Z",
        repo: EVENT.repo,
        pr_url: EVENT.pr_url,
        rules_hash: "abc",
        event_payload: EVENT,
        decision: { claim_seat: "skip", post_mode: "draft", prompt: "default" },
        _logPathForTest: logPath,
      });
      const text = readFileSync(logPath, "utf8");
      assert.doesNotMatch(text, /Rotate the prod database password/);
      assert.doesNotMatch(text, /Private details/);
      assert.doesNotMatch(text, /infra\/secrets\.tf/);
      assert.match(text, /acme\/widget\/pull\/7/);
      assert.equal(statSync(logPath).mode & 0o777, 0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("tightens a pre-existing world-readable log to 0600", () => {
    const dir = mkdtempSync(join(tmpdir(), "peer-watch-priv-"));
    const logPath = join(dir, "peer-watch.log");
    try {
      writeFileSync(logPath, "", { mode: 0o644 });
      appendTriplet({
        ts: "2026-10-28T00:00:00.000Z",
        repo: "acme/widget",
        pr_url: EVENT.pr_url,
        rules_hash: "abc",
        event_payload: {},
        decision: { claim_seat: "skip", post_mode: "draft", prompt: "default" },
        _logPathForTest: logPath,
      });
      assert.equal(statSync(logPath).mode & 0o777, 0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
