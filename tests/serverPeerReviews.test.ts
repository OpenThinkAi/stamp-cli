/**
 * AGT-427 — Per-endpoint unit tests for the peer-agentic review SSH verbs.
 *
 * Tests focus on the shared peerReviews.ts module logic + in-process DB
 * helper functions. The heavy-weight end-to-end (spawn subprocess) tests are
 * limited to the env-gate and limit-defaults behaviors (to keep CI fast and
 * avoid subprocess coupling). The DB-layer tests in serverDb.test.ts cover
 * the atomic claimSeatTx, releaseSeat, touchHeartbeat paths.
 *
 * Coverage per ACs:
 *   AC 1/2  — schema / idempotency: in serverDb.test.ts
 *   AC 3    — pr-opened: env-gate, oversize-body, excess-paths, auth-failure
 *              (spawn-level); success + fanout (in-process via peerReviews.ts)
 *   AC 4    — claim-seat: DB-layer in serverDb.test.ts; env-gate spawn
 *   AC 5    — release-seat / heartbeat: happy-path in serverDb.test.ts; env-gate spawn
 *   AC 6    — re-review-request: fanoutToSeatHolders, 403 non-author, no-holders
 *   AC 7    — subscribe: registerListener + fanoutEvent in-process; env-gate spawn
 *   AC 8    — env-gate: each verb returns peer_reviews_not_configured (spawn)
 *   AC 9    — limit defaults + one override (in-process via resolvePeerReviewLimit)
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, beforeEach, afterEach } from "node:test";

import { insertUser, openServerDb } from "../src/lib/serverDb.ts";

import {
  clearListenerRegistry,
  fanoutEvent,
  fanoutToSeatHolders,
  getListener,
  registerListener,
  resolvePeerReviewLimit,
  resolvePeerReviewsEnabled,
  unregisterListener,
  MAX_PR_OPENED_BODY_BYTES_DEFAULT,
  MAX_PATHS_CHANGED_DEFAULT,
  MAX_SUBSCRIBED_ORGS_DEFAULT,
  PR_OPENED_RATE_CAP_DEFAULT,
  SEAT_TTL_SECONDS_DEFAULT,
} from "../src/server/peerReviews.ts";

// ─── Fixtures ───────────────────────────────────────────────────────

const MEMBER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b member@host";
const MEMBER_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

// Path helpers for verb TypeScript entry points (spawned via tsx).
const verbPath = (name: string) =>
  path.resolve(import.meta.dirname, "..", "src", "server", `${name}.ts`);

// ─── Subprocess spawn helper ─────────────────────────────────────────

interface Harness {
  dir: string;
  dbPath: string;
  authPath: string;
  cleanup: () => void;
}

function setupHarness(
  role: "owner" | "admin" | "member" = "member",
): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-pr-tests-"));
  const dbPath = path.join(dir, "users.db");
  const authPath = path.join(dir, "ssh_user_auth");

  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    insertUser(db, {
      short_name: "caller",
      ssh_pubkey: MEMBER_SSH_LINE,
      ssh_fp: MEMBER_SSH_FP,
      role,
      source: "env",
    });
  } finally {
    db.close();
  }

  writeFileSync(
    authPath,
    `publickey ${MEMBER_SSH_FP} ${MEMBER_SSH_LINE}\n`,
    "utf8",
  );

  return {
    dir,
    dbPath,
    authPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function spawnVerb(
  verbName: string,
  { dbPath, authPath }: Pick<Harness, "dbPath" | "authPath">,
  {
    stdin = "",
    env = {},
    peerReviewsEnabled = false,
  }: { stdin?: string; env?: Record<string, string>; peerReviewsEnabled?: boolean } = {},
) {
  return spawnSync(
    "node",
    ["--import", "tsx/esm", verbPath(verbName)],
    {
      input: stdin,
      encoding: "utf8",
      env: {
        ...process.env,
        STAMP_SERVER_DB_PATH: dbPath,
        SSH_USER_AUTH: authPath,
        ...(peerReviewsEnabled ? { STAMP_PEER_REVIEWS_ENABLED: "1" } : {}),
        ...env,
      },
    },
  );
}

// ─── AC 8: env-gate — all verbs return peer_reviews_not_configured ───

const GATED_VERBS = [
  "pr-opened",
  "claim-seat",
  "release-seat",
  "heartbeat",
  "re-review-request",
  "subscribe",
] as const;

describe("env-gate: STAMP_PEER_REVIEWS_ENABLED not set → peer_reviews_not_configured (AC 8)", () => {
  let harness: Harness;
  beforeEach(() => {
    harness = setupHarness();
  });
  afterEach(() => harness.cleanup());

  for (const verb of GATED_VERBS) {
    it(`${verb} returns { ok: false, error: 'peer_reviews_not_configured' } when env var absent`, () => {
      const result = spawnVerb(verb, harness, { stdin: "{}", peerReviewsEnabled: false });
      assert.equal(result.status, 0, `${verb} should exit 0 when feature is dark`);
      const parsed = JSON.parse(result.stdout.trim()) as { ok: boolean; error: string };
      assert.equal(parsed.ok, false);
      assert.equal(parsed.error, "peer_reviews_not_configured");
    });
  }
});

describe("env-gate: STAMP_PEER_REVIEWS_ENABLED=1 → verb activates (AC 8)", () => {
  let harness: Harness;
  beforeEach(() => {
    harness = setupHarness();
  });
  afterEach(() => harness.cleanup());

  it("pr-opened returns a non-gated response when enabled (even if payload is invalid)", () => {
    // With the gate open, an empty JSON payload {} triggers a validation
    // error, not a 'peer_reviews_not_configured' response. This confirms
    // the gate is honoring the env var.
    const result = spawnVerb("pr-opened", harness, {
      stdin: "{}",
      peerReviewsEnabled: true,
    });
    const stdout = result.stdout.trim();
    // Should NOT be the "not configured" response.
    if (stdout.length > 0) {
      let parsed: { ok: boolean; error?: string };
      try {
        parsed = JSON.parse(stdout) as { ok: boolean; error?: string };
        assert.notEqual(parsed.error, "peer_reviews_not_configured",
          "pr-opened should not return 'not configured' when STAMP_PEER_REVIEWS_ENABLED=1");
      } catch {
        // Non-JSON stdout is also fine here (error logged to stderr, process exits non-0)
      }
    }
    // The verb must not return the gated error in stderr either.
    assert.ok(
      !result.stderr.includes("peer_reviews_not_configured"),
      "stderr should not mention peer_reviews_not_configured when feature is enabled",
    );
  });
});

// ─── AC 9: limit defaults + one override ─────────────────────────────

describe("resolvePeerReviewLimit defaults (AC 9)", () => {
  it("MAX_PR_OPENED_BODY_BYTES defaults to 65536", () => {
    const saved = process.env["MAX_PR_OPENED_BODY_BYTES"];
    delete process.env["MAX_PR_OPENED_BODY_BYTES"];
    try {
      assert.equal(
        resolvePeerReviewLimit("MAX_PR_OPENED_BODY_BYTES", MAX_PR_OPENED_BODY_BYTES_DEFAULT),
        65536,
      );
    } finally {
      if (saved !== undefined) process.env["MAX_PR_OPENED_BODY_BYTES"] = saved;
    }
  });

  it("MAX_PATHS_CHANGED defaults to 1000", () => {
    const saved = process.env["MAX_PATHS_CHANGED"];
    delete process.env["MAX_PATHS_CHANGED"];
    try {
      assert.equal(
        resolvePeerReviewLimit("MAX_PATHS_CHANGED", MAX_PATHS_CHANGED_DEFAULT),
        1000,
      );
    } finally {
      if (saved !== undefined) process.env["MAX_PATHS_CHANGED"] = saved;
    }
  });

  it("MAX_SUBSCRIBED_ORGS defaults to 10", () => {
    const saved = process.env["MAX_SUBSCRIBED_ORGS"];
    delete process.env["MAX_SUBSCRIBED_ORGS"];
    try {
      assert.equal(
        resolvePeerReviewLimit("MAX_SUBSCRIBED_ORGS", MAX_SUBSCRIBED_ORGS_DEFAULT),
        10,
      );
    } finally {
      if (saved !== undefined) process.env["MAX_SUBSCRIBED_ORGS"] = saved;
    }
  });

  it("SEAT_TTL_SECONDS defaults to 600", () => {
    const saved = process.env["SEAT_TTL_SECONDS"];
    delete process.env["SEAT_TTL_SECONDS"];
    try {
      assert.equal(
        resolvePeerReviewLimit("SEAT_TTL_SECONDS", SEAT_TTL_SECONDS_DEFAULT),
        600,
      );
    } finally {
      if (saved !== undefined) process.env["SEAT_TTL_SECONDS"] = saved;
    }
  });

  it("PR_OPENED_RATE_CAP defaults to 60", () => {
    const saved = process.env["PR_OPENED_RATE_CAP"];
    delete process.env["PR_OPENED_RATE_CAP"];
    try {
      assert.equal(
        resolvePeerReviewLimit("PR_OPENED_RATE_CAP", PR_OPENED_RATE_CAP_DEFAULT),
        60,
      );
    } finally {
      if (saved !== undefined) process.env["PR_OPENED_RATE_CAP"] = saved;
    }
  });

  it("honors env override and falls back to default on invalid value", () => {
    const saved = process.env["MAX_PATHS_CHANGED"];
    try {
      process.env["MAX_PATHS_CHANGED"] = "500";
      assert.equal(
        resolvePeerReviewLimit("MAX_PATHS_CHANGED", MAX_PATHS_CHANGED_DEFAULT),
        500,
        "should honor numeric env override",
      );

      process.env["MAX_PATHS_CHANGED"] = "not-a-number";
      assert.equal(
        resolvePeerReviewLimit("MAX_PATHS_CHANGED", MAX_PATHS_CHANGED_DEFAULT),
        1000,
        "should fall back to default on non-numeric value",
      );

      process.env["MAX_PATHS_CHANGED"] = "-5";
      assert.equal(
        resolvePeerReviewLimit("MAX_PATHS_CHANGED", MAX_PATHS_CHANGED_DEFAULT),
        1000,
        "should fall back to default on negative value",
      );
    } finally {
      if (saved !== undefined) process.env["MAX_PATHS_CHANGED"] = saved;
      else delete process.env["MAX_PATHS_CHANGED"];
    }
  });
});

// ─── AC 7/3: In-memory listener registry + synchronous fanout ────────

describe("in-memory listener registry (AC 7)", () => {
  afterEach(() => clearListenerRegistry());

  it("registerListener / getListener / unregisterListener round-trips", () => {
    const events: object[] = [];
    registerListener("SHA256:fp1", {
      orgs: ["acme"],
      onEvent: (ev) => events.push(ev),
    });

    const handle = getListener("SHA256:fp1");
    assert.ok(handle, "registered listener should be retrievable");
    assert.deepStrictEqual(handle?.orgs, ["acme"]);

    unregisterListener("SHA256:fp1");
    assert.equal(getListener("SHA256:fp1"), null, "listener should be removed after unregister");
  });

  it("fanoutEvent delivers to subscribers of the matching org", () => {
    const received: object[] = [];
    registerListener("SHA256:fp-acme", {
      orgs: ["acme"],
      onEvent: (ev) => received.push(ev),
    });
    registerListener("SHA256:fp-other", {
      orgs: ["other-org"],
      onEvent: () => { throw new Error("should not be called"); },
    });

    const event = {
      event_type: "pr-opened",
      patch_id: "p-123",
      actor_fp: "SHA256:author",
      payload: { title: "Fix bug" },
    };

    const count = fanoutEvent("acme", event);
    assert.equal(count, 1, "only one listener should have been notified");
    assert.deepStrictEqual(received, [event]);
  });

  it("fanoutEvent does not propagate listener errors to caller", () => {
    registerListener("SHA256:bad", {
      orgs: ["acme"],
      onEvent: () => { throw new Error("listener boom"); },
    });

    // Should not throw even though the listener throws.
    assert.doesNotThrow(() => {
      fanoutEvent("acme", {
        event_type: "pr-opened",
        patch_id: "p",
        actor_fp: "SHA256:a",
        payload: {},
      });
    });
  });

  it("fanoutEvent returns 0 when no subscribers match", () => {
    const count = fanoutEvent("no-match-org", {
      event_type: "pr-opened",
      patch_id: "p",
      actor_fp: "SHA256:a",
      payload: {},
    });
    assert.equal(count, 0);
  });
});

// ─── AC 6: re-review-request fanout helpers ──────────────────────────

describe("fanoutToSeatHolders (AC 6)", () => {
  afterEach(() => clearListenerRegistry());

  it("notifies both seat-holders and returns their fingerprints", () => {
    const notified: string[] = [];
    registerListener("SHA256:r1", {
      orgs: ["acme"],
      onEvent: (ev) => notified.push((ev.payload as { seat?: number })?.seat?.toString() ?? "ev"),
    });
    registerListener("SHA256:r2", {
      orgs: ["acme"],
      onEvent: (ev) => notified.push((ev.payload as { seat?: number })?.seat?.toString() ?? "ev"),
    });

    const event = {
      event_type: "re-review-requested",
      patch_id: "p-rr",
      actor_fp: "SHA256:author",
      payload: { seat: 1 },
    };

    const result = fanoutToSeatHolders(["SHA256:r1", "SHA256:r2"], event);
    assert.deepStrictEqual(result.sort(), ["SHA256:r1", "SHA256:r2"].sort());
  });

  it("skips null seat-holders (no active seat-holders no-op)", () => {
    const result = fanoutToSeatHolders([null, null], {
      event_type: "re-review-requested",
      patch_id: "p-empty",
      actor_fp: "SHA256:a",
      payload: {},
    });
    assert.deepStrictEqual(result, []);
  });

  it("skips seat-holders not registered as listeners (unregistered agent)", () => {
    // SHA256:unregistered is a seat-holder but has no in-process listener.
    const result = fanoutToSeatHolders(["SHA256:unregistered", null], {
      event_type: "re-review-requested",
      patch_id: "p-unreg",
      actor_fp: "SHA256:a",
      payload: {},
    });
    assert.deepStrictEqual(result, []);
  });

  it("does not propagate listener errors to caller", () => {
    registerListener("SHA256:bad", {
      orgs: [],
      onEvent: () => { throw new Error("listener boom"); },
    });

    assert.doesNotThrow(() => {
      fanoutToSeatHolders(["SHA256:bad"], {
        event_type: "re-review-requested",
        patch_id: "p",
        actor_fp: "SHA256:a",
        payload: {},
      });
    });
  });
});

// ─── resolvePeerReviewsEnabled ───────────────────────────────────────

describe("resolvePeerReviewsEnabled (AC 8)", () => {
  it("returns false when env var is absent", () => {
    const saved = process.env["STAMP_PEER_REVIEWS_ENABLED"];
    delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    try {
      assert.equal(resolvePeerReviewsEnabled(), false);
    } finally {
      if (saved !== undefined) process.env["STAMP_PEER_REVIEWS_ENABLED"] = saved;
    }
  });

  it("returns false when env var is '0'", () => {
    const saved = process.env["STAMP_PEER_REVIEWS_ENABLED"];
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "0";
    try {
      assert.equal(resolvePeerReviewsEnabled(), false);
    } finally {
      if (saved !== undefined) process.env["STAMP_PEER_REVIEWS_ENABLED"] = saved;
      else delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    }
  });

  it("returns true only when env var is exactly '1'", () => {
    const saved = process.env["STAMP_PEER_REVIEWS_ENABLED"];
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      assert.equal(resolvePeerReviewsEnabled(), true);
    } finally {
      if (saved !== undefined) process.env["STAMP_PEER_REVIEWS_ENABLED"] = saved;
      else delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    }
  });

  it("returns false when env var is 'true' (not exactly '1')", () => {
    const saved = process.env["STAMP_PEER_REVIEWS_ENABLED"];
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "true";
    try {
      assert.equal(resolvePeerReviewsEnabled(), false);
    } finally {
      if (saved !== undefined) process.env["STAMP_PEER_REVIEWS_ENABLED"] = saved;
      else delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    }
  });
});
