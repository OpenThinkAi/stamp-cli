/**
 * peer-events-delivery — tests for the peer-events poll worker in
 * `src/server/http-server.ts` and the DB helpers in `src/lib/serverDb.ts`.
 *
 * Coverage:
 *   - `findPeerReviewEventsAfter` / `maxPeerReviewEventId` return correct rows/ids.
 *   - Worker: SSE client for org X receives events for org X created after the
 *     start cursor, does NOT receive org Y events, does NOT replay pre-cursor
 *     history, cursor advances, LIMIT respected.
 *   - Flag-off (STAMP_PEER_REVIEWS_ENABLED != "1") → worker does not start.
 *   - STAMP_PEER_EVENTS_POLL_INTERVAL_SEC=0 → worker does not start.
 *   - `resolvePeerEventsPollIntervalSec` parsing contract.
 *
 * Driving model: same as `promptsPoll.test.ts` — we drive
 * `__runPeerEventsPollTickForTests()` directly rather than fake-timer
 * choreography. The `__getPeerEventsPollStateForTests()` seam lets us assert
 * armed/cursor/tickCount without touching module-private state.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import type { ServerResponse } from "node:http";

import {
  appendEvent,
  findPeerReviewEventsAfter,
  insertPatch,
  maxPeerReviewEventId,
  openServerDb,
} from "../src/lib/serverDb.ts";

import {
  __clearSseConnectionsForTests,
  __getPeerEventsPollStateForTests,
  __resetPeerEventsPollStateForTests,
  __runPeerEventsPollTickForTests,
  DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC,
  resolvePeerEventsPollIntervalSec,
  startPeerEventsPollWorker,
  stopPeerEventsPollWorker,
} from "../src/server/http-server.ts";

// ─── env-cleanup helpers ─────────────────────────────────────────────

const PEER_ENV_KEYS = [
  "STAMP_PEER_REVIEWS_ENABLED",
  "STAMP_PEER_EVENTS_POLL_INTERVAL_SEC",
  "STAMP_SERVER_DB_PATH",
] as const;

function snapshotEnv(): Record<string, string | undefined> {
  const snap: Record<string, string | undefined> = {};
  for (const k of PEER_ENV_KEYS) snap[k] = process.env[k];
  return snap;
}

function restoreEnv(snap: Record<string, string | undefined>): void {
  for (const k of PEER_ENV_KEYS) {
    if (snap[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = snap[k];
    }
  }
}

// ─── tmpdir + DB fixture ─────────────────────────────────────────────

function tmpDb(): { dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-peerpoll-"));
  const dbPath = path.join(dir, "users.db");
  return {
    dbPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Insert a patch + one event row. Returns the event row id. */
function seedPatchAndEvent(
  dbPath: string,
  opts: {
    patchId: string;
    repo: string;
    eventType?: string;
    actorFp?: string;
    payload?: object;
  },
): number {
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    // Insert parent patch (ignore dup patch_id — subsequent calls for same patch).
    try {
      insertPatch(db, {
        patch_id: opts.patchId,
        requested_by_fp: opts.actorFp ?? "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: opts.repo,
      });
    } catch {
      // patch already exists from a prior seed call — that's fine.
    }
    // Need to insert user to satisfy DB constraints? No — peer_review_patches
    // has no FK to users; actor_fp is just a text column.
    appendEvent(
      db,
      opts.patchId,
      opts.eventType ?? "pr-opened",
      opts.actorFp ?? "SHA256:actor",
      opts.payload ?? { title: "test" },
    );
    // Get the max id (the row we just inserted).
    const row = db.prepare("SELECT MAX(id) AS id FROM peer_review_events").get() as { id: number };
    return row.id;
  } finally {
    db.close();
  }
}

// ─── Fake SSE client ─────────────────────────────────────────────────
//
/** Minimal mock of ServerResponse for SSE frame capture. */
function makeFakeRes(): { res: ServerResponse; frames: string[] } {
  const frames: string[] = [];
  const res = {
    write: (chunk: string) => {
      frames.push(chunk);
      return true;
    },
    end: () => { /* noop */ },
    on: () => res,
  } as unknown as ServerResponse;
  return { res, frames };
}

// `__injectSseConnectionForTests` injects a fake client into the module-private
// `sseConnections` map without needing a real HTTP server + auth round-trip.
import {
  __injectSseConnectionForTests,
} from "../src/server/http-server.ts";

// ─── serverDb helpers tests ─────────────────────────────────────────

describe("findPeerReviewEventsAfter / maxPeerReviewEventId (serverDb)", () => {
  it("maxPeerReviewEventId returns 0 on empty table", () => {
    const { dbPath, cleanup } = tmpDb();
    try {
      const db = openServerDb({ path: dbPath, skipChmod: true });
      try {
        assert.equal(maxPeerReviewEventId(db), 0);
      } finally {
        db.close();
      }
    } finally {
      cleanup();
    }
  });

  it("maxPeerReviewEventId returns the highest id after inserts", () => {
    const { dbPath, cleanup } = tmpDb();
    try {
      const id1 = seedPatchAndEvent(dbPath, { patchId: "p1", repo: "org/repo1" });
      const id2 = seedPatchAndEvent(dbPath, { patchId: "p2", repo: "org/repo2" });
      const db = openServerDb({ path: dbPath, skipChmod: true });
      try {
        const max = maxPeerReviewEventId(db);
        assert.ok(max >= id2, `max (${max}) should be >= id of last insert (${id2})`);
        assert.ok(max >= id1);
      } finally {
        db.close();
      }
    } finally {
      cleanup();
    }
  });

  it("findPeerReviewEventsAfter returns rows with id > afterId", () => {
    const { dbPath, cleanup } = tmpDb();
    try {
      const id1 = seedPatchAndEvent(dbPath, { patchId: "p1", repo: "acme/widget" });
      const id2 = seedPatchAndEvent(dbPath, { patchId: "p1", repo: "acme/widget", eventType: "re-review-requested" });

      const db = openServerDb({ path: dbPath, skipChmod: true });
      try {
        const after0 = findPeerReviewEventsAfter(db, 0);
        assert.ok(after0.length >= 2, "should return both rows when afterId=0");

        const afterId1 = findPeerReviewEventsAfter(db, id1);
        assert.ok(afterId1.every((r) => r.id > id1), "all returned rows must have id > afterId");
        // id2 should be in the result; id1 should not.
        assert.ok(afterId1.some((r) => r.id === id2), "id2 must be in results");
        assert.ok(!afterId1.some((r) => r.id === id1), "id1 must NOT be in results");

        const afterId2 = findPeerReviewEventsAfter(db, id2);
        assert.equal(afterId2.length, 0, "no rows after the last id");
      } finally {
        db.close();
      }
    } finally {
      cleanup();
    }
  });

  it("findPeerReviewEventsAfter joins repo from peer_review_patches", () => {
    const { dbPath, cleanup } = tmpDb();
    try {
      seedPatchAndEvent(dbPath, { patchId: "p-repo", repo: "myorg/myrepo" });
      const db = openServerDb({ path: dbPath, skipChmod: true });
      try {
        const rows = findPeerReviewEventsAfter(db, 0);
        assert.ok(rows.length > 0, "should have at least one row");
        assert.equal(rows[0]?.repo, "myorg/myrepo", "repo must be joined from patch");
      } finally {
        db.close();
      }
    } finally {
      cleanup();
    }
  });

  it("findPeerReviewEventsAfter respects LIMIT", () => {
    const { dbPath, cleanup } = tmpDb();
    try {
      // Seed 5 events on the same patch.
      for (let i = 0; i < 5; i++) {
        seedPatchAndEvent(dbPath, { patchId: "p-limit", repo: "acme/big" });
      }
      const db = openServerDb({ path: dbPath, skipChmod: true });
      try {
        const rows = findPeerReviewEventsAfter(db, 0, 3);
        assert.equal(rows.length, 3, "LIMIT=3 must return at most 3 rows");
      } finally {
        db.close();
      }
    } finally {
      cleanup();
    }
  });

  it("findPeerReviewEventsAfter returns rows in ascending id order", () => {
    const { dbPath, cleanup } = tmpDb();
    try {
      seedPatchAndEvent(dbPath, { patchId: "p-ord", repo: "org/x" });
      seedPatchAndEvent(dbPath, { patchId: "p-ord", repo: "org/x" });
      seedPatchAndEvent(dbPath, { patchId: "p-ord", repo: "org/x" });
      const db = openServerDb({ path: dbPath, skipChmod: true });
      try {
        const rows = findPeerReviewEventsAfter(db, 0);
        const ids = rows.map((r) => r.id);
        for (let i = 1; i < ids.length; i++) {
          assert.ok((ids[i] ?? 0) > (ids[i - 1] ?? 0), "rows must be ascending by id");
        }
      } finally {
        db.close();
      }
    } finally {
      cleanup();
    }
  });
});

// ─── Poll worker tests ───────────────────────────────────────────────

describe("resolvePeerEventsPollIntervalSec", () => {
  let envSnap: Record<string, string | undefined>;
  beforeEach(() => { envSnap = snapshotEnv(); });
  afterEach(() => { restoreEnv(envSnap); });

  it("returns the default when env is unset", () => {
    delete process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"];
    assert.equal(resolvePeerEventsPollIntervalSec(), DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC);
  });

  it("returns 0 for the literal '0' opt-out", () => {
    process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"] = "0";
    assert.equal(resolvePeerEventsPollIntervalSec(), 0);
  });

  it("returns the default for a non-integer value", () => {
    process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"] = "abc";
    assert.equal(resolvePeerEventsPollIntervalSec(), DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC);
  });

  it("returns the parsed value for a valid positive integer", () => {
    process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"] = "10";
    assert.equal(resolvePeerEventsPollIntervalSec(), 10);
  });

  it("falls back to default for a negative integer", () => {
    process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"] = "-5";
    assert.equal(resolvePeerEventsPollIntervalSec(), DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC);
  });
});

describe("startPeerEventsPollWorker — flag-off cases", () => {
  let envSnap: Record<string, string | undefined>;
  beforeEach(() => {
    envSnap = snapshotEnv();
    __resetPeerEventsPollStateForTests();
    __clearSseConnectionsForTests();
  });
  afterEach(() => {
    __resetPeerEventsPollStateForTests();
    __clearSseConnectionsForTests();
    restoreEnv(envSnap);
  });

  it("does not start when STAMP_PEER_REVIEWS_ENABLED is not '1'", () => {
    delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    startPeerEventsPollWorker();
    const state = __getPeerEventsPollStateForTests();
    assert.equal(state.armed, false, "worker must not arm when feature flag is off");
  });

  it("does not start when STAMP_PEER_EVENTS_POLL_INTERVAL_SEC=0", () => {
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"] = "0";
    const { dbPath, cleanup } = tmpDb();
    try {
      process.env["STAMP_SERVER_DB_PATH"] = dbPath;
      startPeerEventsPollWorker();
      const state = __getPeerEventsPollStateForTests();
      assert.equal(state.armed, false, "worker must not arm when interval is 0");
    } finally {
      cleanup();
    }
  });
});

describe("peer-events poll worker — tick delivery", () => {
  let envSnap: Record<string, string | undefined>;
  let dbFixture: { dbPath: string; cleanup: () => void };

  beforeEach(() => {
    envSnap = snapshotEnv();
    __resetPeerEventsPollStateForTests();
    __clearSseConnectionsForTests();
    dbFixture = tmpDb();
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    process.env["STAMP_SERVER_DB_PATH"] = dbFixture.dbPath;
  });

  afterEach(() => {
    __resetPeerEventsPollStateForTests();
    __clearSseConnectionsForTests();
    dbFixture.cleanup();
    restoreEnv(envSnap);
  });

  it("delivers events for org X to a client subscribed to org X", () => {
    const { dbPath } = dbFixture;
    // Seed one event for org "acme".
    seedPatchAndEvent(dbPath, { patchId: "px-1", repo: "acme/widget" });

    // Inject a fake SSE client subscribed to "acme".
    const { res, frames } = makeFakeRes();
    __injectSseConnectionForTests("fp-acme", { res, orgs: ["acme"] });

    // Run one tick (cursor is 0 → picks up all rows).
    __runPeerEventsPollTickForTests();

    assert.ok(frames.length > 0, "client should have received at least one frame");
    const frame = frames[0] ?? "";
    assert.ok(frame.startsWith("data:"), "frame must be a data: SSE frame");
    const parsed = JSON.parse(frame.replace(/^data: /, "").trim()) as { event_type: string };
    assert.equal(parsed.event_type, "pr-opened");
  });

  it("does NOT deliver org Y events to a client subscribed only to org X", () => {
    const { dbPath } = dbFixture;
    // Seed event for "other-org".
    seedPatchAndEvent(dbPath, { patchId: "py-1", repo: "other-org/repo" });

    const { res, frames } = makeFakeRes();
    __injectSseConnectionForTests("fp-x-only", { res, orgs: ["acme"] });

    __runPeerEventsPollTickForTests();

    assert.equal(frames.length, 0, "client subscribed to 'acme' must not receive 'other-org' events");
  });

  it("does NOT replay history older than the start cursor", () => {
    const { dbPath } = dbFixture;
    // Seed event BEFORE we set the cursor.
    const oldId = seedPatchAndEvent(dbPath, { patchId: "hist-1", repo: "acme/old" });

    // Manually set cursor to oldId (simulating worker started after this row).
    const state = __getPeerEventsPollStateForTests();
    // We need to set cursor; use reset + set via start-worker mechanism.
    // Actually the simplest approach: use __resetPeerEventsPollStateForTests to
    // clear, then manually set cursor by running startPeerEventsPollWorker
    // (which reads MAX(id) and sets cursor = that).
    __resetPeerEventsPollStateForTests();

    // Now start the worker — cursor will be set to MAX(id) = oldId.
    startPeerEventsPollWorker();
    const stateAfterStart = __getPeerEventsPollStateForTests();
    assert.ok(
      stateAfterStart.cursor >= oldId,
      `cursor (${stateAfterStart.cursor}) must be >= oldId (${oldId}) after start`,
    );
    stopPeerEventsPollWorker();

    // Inject a fake SSE client.
    const { res, frames } = makeFakeRes();
    __injectSseConnectionForTests("fp-hist", { res, orgs: ["acme"] });

    // Run a tick — should NOT deliver the old event.
    __runPeerEventsPollTickForTests();

    assert.equal(frames.length, 0, "no frames should be delivered for pre-cursor history");
  });

  it("advances cursor after delivering events", () => {
    const { dbPath } = dbFixture;
    // Seed two events.
    const id1 = seedPatchAndEvent(dbPath, { patchId: "adv-1", repo: "acme/r" });
    const id2 = seedPatchAndEvent(dbPath, { patchId: "adv-1", repo: "acme/r", eventType: "re-review-requested" });

    const { res } = makeFakeRes();
    __injectSseConnectionForTests("fp-adv", { res, orgs: ["acme"] });

    __runPeerEventsPollTickForTests();

    const state = __getPeerEventsPollStateForTests();
    assert.ok(
      state.cursor >= id2,
      `cursor (${state.cursor}) must advance to at least id2 (${id2})`,
    );
    assert.ok(state.cursor >= id1);
  });

  it("cursor advances, so a second tick does not re-deliver the same events", () => {
    const { dbPath } = dbFixture;
    seedPatchAndEvent(dbPath, { patchId: "nodup-1", repo: "acme/r" });

    const { res, frames } = makeFakeRes();
    __injectSseConnectionForTests("fp-nodup", { res, orgs: ["acme"] });

    __runPeerEventsPollTickForTests();
    const framesAfterFirst = frames.length;
    assert.ok(framesAfterFirst > 0, "first tick should deliver the event");

    // Run a second tick — no new rows, cursor already advanced.
    __runPeerEventsPollTickForTests();
    assert.equal(
      frames.length,
      framesAfterFirst,
      "second tick must not re-deliver already-seen events",
    );
  });

  it("tickCount increments on each tick", () => {
    __runPeerEventsPollTickForTests();
    __runPeerEventsPollTickForTests();
    assert.equal(__getPeerEventsPollStateForTests().tickCount, 2);
  });

  it("delivers only to clients whose orgs include the event org (multi-client)", () => {
    const { dbPath } = dbFixture;
    seedPatchAndEvent(dbPath, { patchId: "multi-1", repo: "acme/r" });

    const { res: resAcme, frames: framesAcme } = makeFakeRes();
    const { res: resOther, frames: framesOther } = makeFakeRes();

    __injectSseConnectionForTests("fp-acme-multi", { res: resAcme, orgs: ["acme"] });
    __injectSseConnectionForTests("fp-other-multi", { res: resOther, orgs: ["other"] });

    __runPeerEventsPollTickForTests();

    assert.ok(framesAcme.length > 0, "acme client must receive the event");
    assert.equal(framesOther.length, 0, "other client must NOT receive the acme event");
  });
});
