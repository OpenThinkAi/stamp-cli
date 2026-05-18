/**
 * End-to-end tests for the SSH-invoked stamp-review wrapper (AGT-328
 * scaffold).
 *
 * Identical harness pattern to `tests/serverMintInvite.test.ts`: spawn
 * the unbundled TS via tsx, point STAMP_SERVER_DB_PATH + SSH_USER_AUTH
 * at a tmp fixture, exercise the wrapper as a black box.
 *
 * Scope: parse, auth, size cap, diff-sha256 cross-check, and the
 * response shape from design.md. The pipeline body is intentionally a
 * placeholder (see `src/server/reviewPipeline.ts`) so these tests
 * assert SHAPE — not LLM behavior. AGT-330 / AGT-331 add tests for the
 * real signature + LLM call.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { insertUser, openServerDb } from "../src/lib/serverDb.ts";

const STAMP_REVIEW_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "stamp-review.ts",
);

// Re-uses tests/sshKeys.test.ts fixture so the fingerprint is known.
const MEMBER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b member@host";
const MEMBER_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

// Full-shape SHAs the parser will accept.
const BASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const HEAD_SHA = "fedcba9876543210fedcba9876543210fedcba98";

interface Harness {
  dbPath: string;
  authPath: string;
  cleanup: () => void;
}

function setup(callerRole: "owner" | "admin" | "member" | "none"): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-review-"));
  const dbPath = path.join(dir, "users.db");
  const authPath = path.join(dir, "ssh_user_auth");

  if (callerRole !== "none") {
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      insertUser(db, {
        short_name: "caller",
        ssh_pubkey: MEMBER_SSH_LINE,
        ssh_fp: MEMBER_SSH_FP,
        role: callerRole,
        source: "env",
      });
    } finally {
      db.close();
    }
  }

  writeFileSync(authPath, `publickey ${MEMBER_SSH_LINE}\n`, { mode: 0o600 });

  return {
    dbPath,
    authPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

interface RunResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

function runStampReview(
  harness: Harness,
  args: string[],
  opts: { stdin?: Buffer; envOverrides?: Record<string, string | undefined> } = {},
): RunResult {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    STAMP_SERVER_DB_PATH: harness.dbPath,
    SSH_USER_AUTH: harness.authPath,
  };
  if (opts.envOverrides) {
    for (const [k, v] of Object.entries(opts.envOverrides)) {
      if (v === undefined) {
        delete env[k];
      } else {
        env[k] = v;
      }
    }
  }
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", STAMP_REVIEW_TS, ...args],
    {
      env,
      input: opts.stdin ?? Buffer.alloc(0),
      encoding: "utf8",
    },
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

/** Build the full happy-path argv for a given diff. */
function argvFor(diff: Buffer, overrides: Partial<Record<string, string>> = {}): string[] {
  const diffSha = createHash("sha256").update(diff).digest("hex");
  const merged: Record<string, string> = {
    "--reviewer": "security",
    "--org": "acme",
    "--repo": "widget-co",
    "--base-sha": BASE_SHA,
    "--head-sha": HEAD_SHA,
    "--diff-sha256": diffSha,
    ...overrides,
  };
  const out: string[] = [];
  for (const [k, v] of Object.entries(merged)) out.push(k, v);
  return out;
}

describe("stamp-review — success path (scaffold response shape)", () => {
  it("returns a structurally-valid JSON response on stdout", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("diff --git a/foo b/foo\n");
      const r = runStampReview(h, argvFor(diff), { stdin: diff });
      assert.equal(r.status, 0, `stderr=${r.stderr}\nstdout=${r.stdout}`);

      const payload = JSON.parse(r.stdout) as Record<string, unknown>;
      // Top-level shape from design.md
      assert.ok(typeof payload.verdict === "string", "verdict is string");
      assert.ok(typeof payload.prose === "string", "prose is string");
      assert.ok(typeof payload.signature === "string", "signature is string");
      assert.ok(payload.approval && typeof payload.approval === "object", "approval is object");

      // The approval body: ApprovalV4 shape, with values populated
      // from the request and PLACEHOLDER markers for the LLM/signing
      // bits that land in AGT-330/331.
      const approval = payload.approval as Record<string, unknown>;
      assert.equal(approval.reviewer, "security");
      assert.equal(approval.base_sha, BASE_SHA);
      assert.equal(approval.head_sha, HEAD_SHA);
      assert.equal(
        approval.diff_sha256,
        createHash("sha256").update(diff).digest("hex"),
      );
      assert.ok(/^[0-9a-f]{64}$/.test(approval.prompt_sha256 as string), "prompt_sha256 is bare hex");
      assert.match(
        approval.trusted_keys_snapshot_sha256 as string,
        /^sha256:[0-9a-f]{64}$/,
        "trusted_keys_snapshot_sha256 carries sha256: prefix",
      );
      assert.match(
        approval.server_key_id as string,
        /^sha256:[0-9a-f]{64}$/,
        "server_key_id carries sha256: prefix",
      );
      assert.match(
        approval.issued_at as string,
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
        "issued_at is ISO-8601 UTC, second precision",
      );

      // Verdict must be one of the three legal values, and the
      // top-level mirror equals the approval body's value.
      assert.ok(
        approval.verdict === "approved" ||
          approval.verdict === "changes_requested" ||
          approval.verdict === "denied",
      );
      assert.equal(payload.verdict, approval.verdict);
    } finally {
      h.cleanup();
    }
  });

  it("accepts owner and admin callers (not just member)", () => {
    for (const role of ["owner", "admin"] as const) {
      const h = setup(role);
      try {
        const diff = Buffer.from(`role=${role}\n`);
        const r = runStampReview(h, argvFor(diff), { stdin: diff });
        assert.equal(r.status, 0, `role=${role} stderr=${r.stderr}`);
      } finally {
        h.cleanup();
      }
    }
  });
});

describe("stamp-review — authorization", () => {
  it("refuses when SSH_USER_AUTH is unset (no ExposeAuthInfo)", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff), {
        stdin: diff,
        envOverrides: { SSH_USER_AUTH: undefined },
      });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /authenticated identity/);
    } finally {
      h.cleanup();
    }
  });

  it("refuses when the caller's SSH key isn't in the DB", () => {
    const h = setup("none");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff), { stdin: diff });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /not in the membership DB/);
    } finally {
      h.cleanup();
    }
  });

  // The Role union (and the DB's CHECK constraint) currently covers
  // {owner, admin, member} — every legal value is also an allowed
  // value. We therefore can't write a "role below member is rejected"
  // E2E test today without bypassing the DB schema. The structural
  // gate is the `ALLOWED_ROLES` Set in stamp-review.ts; a future Role
  // expansion that adds e.g. `viewer` will trip the existing test
  // surface immediately (an inserted viewer would not match the Set
  // and the verb would exit 3). Documented here so a future agent
  // adding a new Role variant remembers to add the regression test.
});

describe("stamp-review — help", () => {
  it("prints usage to stdout and exits 0 on --help", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, ["--help"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stdout, /^usage: stamp-review --reviewer/);
      // stderr may carry Node's "experimental SQLite" warning, but
      // must not carry an `error:` line from the verb itself.
      assert.doesNotMatch(r.stderr, /^error:/m);
    } finally {
      h.cleanup();
    }
  });

  it("prints usage to stdout and exits 0 on -h", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, ["-h"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stdout, /^usage: stamp-review --reviewer/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-review — request validation", () => {
  it("rejects missing required flags with a usage error", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, ["--reviewer", "security"], {
        stdin: Buffer.alloc(0),
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /missing required flag/);
      assert.match(r.stderr, /--org/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects an unknown flag", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, [...argvFor(Buffer.from("x")), "--nope", "1"], {
        stdin: Buffer.from("x"),
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /unknown flag/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed --base-sha (short hex)", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff, { "--base-sha": "deadbeef" }), {
        stdin: diff,
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /--base-sha/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed --reviewer shape", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff, { "--reviewer": "has spaces" }), {
        stdin: diff,
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /--reviewer/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a --diff-sha256 that doesn't match the streamed bytes", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("actual content");
      const wrongSha = "f".repeat(64);
      const r = runStampReview(h, argvFor(diff, { "--diff-sha256": wrongSha }), {
        stdin: diff,
      });
      assert.equal(r.status, 4);
      assert.match(r.stderr, /diff content sha256 mismatch/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects diff content larger than MAX_DIFF_BYTES (env override)", () => {
    const h = setup("member");
    try {
      // Cap = 16 bytes; stdin = 100 bytes. The streaming reader should
      // abort as soon as cumulative bytes exceed 16, well before
      // reaching the diff-sha cross-check.
      const diff = Buffer.alloc(100, 0x61); // 'a' x 100
      const r = runStampReview(h, argvFor(diff), {
        stdin: diff,
        envOverrides: { MAX_DIFF_BYTES: "16" },
      });
      assert.equal(r.status, 4);
      assert.match(r.stderr, /exceeds MAX_DIFF_BYTES/);
    } finally {
      h.cleanup();
    }
  });
});
