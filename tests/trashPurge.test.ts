/**
 * AGT-423 — trash-retention purge + sweep.
 *
 * Covers the pure age math, the destructive purgeTrash with its containment
 * checks (shape + symlink-escape), the env TTL resolver, the in-process
 * sweep-worker tick, and the soft-delete persistence reminder.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  computeTrashEntriesToPurge,
  parseTrashTimestamp,
  purgeTrash,
  resolveTrashTtlDays,
} from "../src/server/trashPurge.ts";
import {
  __runTrashSweepTickForTests,
  __getTrashSweepTickCountForTests,
  __resetTrashSweepStateForTests,
} from "../src/server/http-server.ts";
import { formatDeletePersistenceReminder } from "../src/commands/serverRepo.ts";

const NOW = Date.parse("2026-05-24T00:00:00Z");
const OLD = "20200101T000000Z-old.git"; // ~6 years before NOW
const RECENT = "20260523T120000Z-recent.git"; // ~12h before NOW
const fresh = (name = "fresh") => {
  const d = new Date(NOW).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  return `${d}-${name}.git`; // exactly NOW
};

describe("parseTrashTimestamp (AGT-423)", () => {
  it("parses a valid trash entry name to epoch ms", () => {
    assert.equal(
      parseTrashTimestamp("20260524T143000Z-myrepo.git"),
      Date.parse("2026-05-24T14:30:00Z"),
    );
  });
  it("returns null for names that don't match the trash shape", () => {
    for (const n of [
      "myrepo.git", // no timestamp
      "2026-05-24-myrepo.git", // wrong format
      "20260524T143000Z-bad name.git", // space in name
      "notes.txt",
      "20260524T143000Z-.git", // empty name
    ]) {
      assert.equal(parseTrashTimestamp(n), null, n);
    }
  });
});

describe("computeTrashEntriesToPurge (AGT-423)", () => {
  it("returns entries older than now - ttlDays, retains newer", () => {
    const out = computeTrashEntriesToPurge([OLD, RECENT], NOW, 30);
    assert.deepEqual(out, [OLD]);
  });
  it("skips unparseable names (never purges them)", () => {
    const out = computeTrashEntriesToPurge([OLD, "manual-notes.txt"], NOW, 30);
    assert.deepEqual(out, [OLD]);
  });
  it("ttlDays=0 purges everything with a past timestamp", () => {
    const out = computeTrashEntriesToPurge([OLD, RECENT], NOW, 0);
    assert.deepEqual(out.sort(), [OLD, RECENT].sort());
  });
});

describe("purgeTrash (real fs, with containment)", () => {
  let tmp: string;
  let trash: string;
  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(path.join(os.tmpdir(), "stamp-trash-")));
    trash = path.join(tmp, ".trash");
    mkdirSync(trash);
  });
  afterEach(() => rmSync(tmp, { recursive: true, force: true }));

  const mkEntry = (name: string) => {
    mkdirSync(path.join(trash, name));
    writeFileSync(path.join(trash, name, "HEAD"), "ref: x\n");
  };

  it("removes old entries, keeps recent ones", () => {
    mkEntry(OLD);
    mkEntry(RECENT);
    const r = purgeTrash(trash, 30, NOW);
    assert.deepEqual(r.purged, [OLD]);
    assert.equal(existsSync(path.join(trash, OLD)), false);
    assert.equal(existsSync(path.join(trash, RECENT)), true);
  });

  it("skips a non-trash-shaped dir (never deletes operator files)", () => {
    mkdirSync(path.join(trash, "manual-backup"));
    mkEntry(OLD);
    const r = purgeTrash(trash, 30, NOW);
    assert.deepEqual(r.purged, [OLD]);
    assert.equal(existsSync(path.join(trash, "manual-backup")), true);
  });

  it("refuses to follow a symlink escaping the trash dir (containment)", () => {
    // An old-timestamped entry that is actually a symlink to a dir OUTSIDE
    // the trash dir must NOT be followed/deleted.
    const outside = path.join(tmp, "precious");
    mkdirSync(outside);
    writeFileSync(path.join(outside, "keep.txt"), "do not delete");
    symlinkSync(outside, path.join(trash, OLD));
    const r = purgeTrash(trash, 30, NOW);
    assert.deepEqual(r.purged, []);
    assert.deepEqual(r.skipped, [OLD]);
    assert.equal(existsSync(path.join(outside, "keep.txt")), true);
  });

  it("no-ops on a missing trash dir", () => {
    const r = purgeTrash(path.join(tmp, "does-not-exist"), 30, NOW);
    assert.deepEqual(r, { purged: [], skipped: [] });
  });
});

describe("resolveTrashTtlDays (AGT-423)", () => {
  let saved: string | undefined;
  beforeEach(() => {
    saved = process.env["STAMP_TRASH_TTL_DAYS"];
  });
  afterEach(() => {
    if (saved === undefined) delete process.env["STAMP_TRASH_TTL_DAYS"];
    else process.env["STAMP_TRASH_TTL_DAYS"] = saved;
  });
  it("defaults to 30", () => {
    delete process.env["STAMP_TRASH_TTL_DAYS"];
    assert.equal(resolveTrashTtlDays(), 30);
  });
  it("honors a positive integer and falls back on a bad value", () => {
    process.env["STAMP_TRASH_TTL_DAYS"] = "7";
    assert.equal(resolveTrashTtlDays(), 7);
    process.env["STAMP_TRASH_TTL_DAYS"] = "garbage";
    assert.equal(resolveTrashTtlDays(), 30);
  });
});

describe("trash-sweep worker tick (AGT-423)", () => {
  let tmp: string;
  let savedDir: string | undefined;
  let savedTtl: string | undefined;
  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(path.join(os.tmpdir(), "stamp-sweep-")));
    savedDir = process.env["STAMP_TRASH_DIR"];
    savedTtl = process.env["STAMP_TRASH_TTL_DAYS"];
    __resetTrashSweepStateForTests();
  });
  afterEach(() => {
    if (savedDir === undefined) delete process.env["STAMP_TRASH_DIR"];
    else process.env["STAMP_TRASH_DIR"] = savedDir;
    if (savedTtl === undefined) delete process.env["STAMP_TRASH_TTL_DAYS"];
    else process.env["STAMP_TRASH_TTL_DAYS"] = savedTtl;
    __resetTrashSweepStateForTests();
    rmSync(tmp, { recursive: true, force: true });
  });

  it("a tick purges trash older than the TTL and bumps the tick count", () => {
    const trash = path.join(tmp, ".trash");
    mkdirSync(trash);
    // OLD is 2020; with a 30d TTL it's well past the cutoff (uses real now).
    mkdirSync(path.join(trash, OLD));
    mkdirSync(path.join(trash, fresh())); // ~now → kept
    process.env["STAMP_TRASH_DIR"] = trash;
    process.env["STAMP_TRASH_TTL_DAYS"] = "30";

    __runTrashSweepTickForTests();

    assert.equal(__getTrashSweepTickCountForTests(), 1);
    assert.equal(existsSync(path.join(trash, OLD)), false);
    assert.equal(existsSync(path.join(trash, fresh())), true);
  });
});

describe("formatDeletePersistenceReminder (AGT-423)", () => {
  it("warns that soft-delete is not erasure and names the purge escape", () => {
    const lines = formatDeletePersistenceReminder();
    const joined = lines.join("\n");
    for (const line of lines) assert.match(line, /^warning: /);
    assert.match(joined, /NOT erasure/);
    assert.match(joined, /STAMP_TRASH_TTL_DAYS/);
    assert.match(joined, /purge --older-than 0d/);
  });
});
