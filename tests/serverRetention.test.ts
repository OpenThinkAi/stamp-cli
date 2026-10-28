/**
 * AGT-2249 (folds AGT-2255, AGT-2258): server-side retention for the
 * shared users.db — delivered peer events lose their PR content, old peer
 * events/patches and cached server verdicts (reviewer prose) are deleted,
 * each on a configurable TTL.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import type { DatabaseSync } from "node:sqlite";

import {
  appendEvent,
  findCachedServerVerdict,
  findPatch,
  insertPatch,
  openServerDb,
  recordServerVerdict,
  resolveRetentionDays,
  resolveServerRetentionPolicy,
  sweepServerRetention,
} from "../src/lib/serverDb.ts";

const DAY_MS = 86_400_000;
const NOW = Date.UTC(2026, 9, 28, 12, 0, 0);

function payload(patch: string) {
  return {
    repo: "acme/widget",
    patch_id: patch,
    base_sha: "b".repeat(40),
    head_sha: "c".repeat(40),
    requested_by_fp: "sha256:" + "d".repeat(64),
    paths_changed: ["src/secret-plan.ts"],
    title: "Add the secret plan",
    body: "Long PR body quoting private details",
    pr_url: "https://github.com/acme/widget/pull/7",
    pubkey: "-----BEGIN PUBLIC KEY-----\n...",
    signature: "sig",
  };
}

function eventPayloads(db: DatabaseSync): Array<Record<string, unknown>> {
  const rows = db.prepare(`SELECT payload FROM peer_review_events ORDER BY id`).all() as Array<{
    payload: string;
  }>;
  return rows.map((r) => JSON.parse(r.payload) as Record<string, unknown>);
}

describe("sweepServerRetention", () => {
  let dir: string;
  let db: DatabaseSync;
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), "stamp-retention-"));
    db = openServerDb({ path: path.join(dir, "users.db"), skipChmod: true });
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const policy = { peerEventRetentionDays: 30, verdictRetentionDays: 30 };

  it("drops PR content from events older than an hour, keeps routing fields, leaves fresh events whole", () => {
    insertPatch(db, { ...payload("p1"), pr_url: "https://github.com/acme/widget/pull/7" }, NOW - 2 * 3600_000);
    appendEvent(db, "p1", "pr-opened", "sha256:x", payload("p1"), NOW - 2 * 3600_000);
    appendEvent(db, "p1", "pr-opened", "sha256:x", payload("p1"), NOW - 60_000);

    const r = sweepServerRetention(db, policy, NOW);
    assert.equal(r.eventsScrubbed, 1);
    const [old, fresh] = eventPayloads(db);
    for (const k of ["title", "body", "paths_changed", "pubkey", "signature"]) {
      assert.ok(!(k in old!), `${k} must be scrubbed from a delivered event`);
    }
    assert.equal(old!["repo"], "acme/widget");
    assert.equal(old!["patch_id"], "p1");
    assert.equal(old!["pr_url"], "https://github.com/acme/widget/pull/7");
    assert.equal(fresh!["title"], "Add the secret plan", "an undelivered-window event keeps its content");

    // Idempotent: a second pass scrubs nothing new.
    assert.equal(sweepServerRetention(db, policy, NOW).eventsScrubbed, 0);
  });

  it("deletes events and patches past the event retention", () => {
    insertPatch(db, payload("old"), NOW - 40 * DAY_MS);
    appendEvent(db, "old", "pr-opened", "sha256:x", payload("old"), NOW - 40 * DAY_MS);
    insertPatch(db, payload("new"), NOW - 1 * DAY_MS);
    appendEvent(db, "new", "pr-opened", "sha256:x", payload("new"), NOW - 1 * DAY_MS);

    const r = sweepServerRetention(db, policy, NOW);
    assert.equal(r.eventsDeleted, 1);
    assert.equal(r.patchesDeleted, 1);
    assert.equal(findPatch(db, "old"), null);
    assert.ok(findPatch(db, "new"));
  });

  it("deletes cached server verdicts (prose) past the verdict retention", () => {
    recordServerVerdict(db, "security", "d-old", "p", "approved", "quotes src/x.ts:1");
    recordServerVerdict(db, "security", "d-new", "p", "approved", "fresh");
    db.prepare(`UPDATE server_verdicts SET created_at = ? WHERE diff_sha256 = 'd-old'`).run(
      Math.floor((NOW - 31 * DAY_MS) / 1000),
    );
    db.prepare(`UPDATE server_verdicts SET created_at = ? WHERE diff_sha256 = 'd-new'`).run(
      Math.floor((NOW - DAY_MS) / 1000),
    );

    const r = sweepServerRetention(db, policy, NOW);
    assert.equal(r.verdictsDeleted, 1);
    assert.equal(findCachedServerVerdict(db, "security", "d-old", "p"), null);
    assert.ok(findCachedServerVerdict(db, "security", "d-new", "p"));
  });

  it("keeps everything when retention is disabled (null), but still scrubs delivered content", () => {
    insertPatch(db, payload("old"), NOW - 400 * DAY_MS);
    appendEvent(db, "old", "pr-opened", "sha256:x", payload("old"), NOW - 400 * DAY_MS);
    recordServerVerdict(db, "security", "d", "p", "approved", "prose");
    db.prepare(`UPDATE server_verdicts SET created_at = 0`).run();

    const r = sweepServerRetention(db, { peerEventRetentionDays: null, verdictRetentionDays: null }, NOW);
    assert.equal(r.eventsDeleted, 0);
    assert.equal(r.verdictsDeleted, 0);
    assert.equal(r.eventsScrubbed, 1);
    assert.ok(findPatch(db, "old"));
  });
});

describe("retention env resolution", () => {
  const names = ["STAMP_PEER_EVENT_RETENTION_DAYS", "STAMP_SERVER_VERDICT_RETENTION_DAYS"];
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const n of names) saved[n] = process.env[n];
  });
  afterEach(() => {
    for (const n of names) {
      if (saved[n] === undefined) delete process.env[n];
      else process.env[n] = saved[n];
    }
  });

  it("defaults both to 30 days", () => {
    for (const n of names) delete process.env[n];
    assert.deepEqual(resolveServerRetentionPolicy(), {
      peerEventRetentionDays: 30,
      verdictRetentionDays: 30,
    });
  });

  it("honours an override, treats '0' as keep-forever, and ignores typos", () => {
    process.env["STAMP_PEER_EVENT_RETENTION_DAYS"] = "7";
    process.env["STAMP_SERVER_VERDICT_RETENTION_DAYS"] = "0";
    assert.deepEqual(resolveServerRetentionPolicy(), {
      peerEventRetentionDays: 7,
      verdictRetentionDays: null,
    });
    process.env["X_RET"] = "seven";
    assert.equal(resolveRetentionDays("X_RET", 30), 30);
    process.env["X_RET"] = "-3";
    assert.equal(resolveRetentionDays("X_RET", 30), 30);
    delete process.env["X_RET"];
  });
});
