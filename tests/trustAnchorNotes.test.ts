/**
 * Unit tests for the trust-anchor notes-ref read/write helpers (AGT-337).
 *
 * Round-trip a signature through write → read → parse, exercise the
 * malformed-input fail-closed paths, and confirm duplicate-signer
 * detection in the in-memory appender. The git-notes I/O is the
 * smallest surface that can plausibly go wrong, so we test it
 * end-to-end against a real temp repo rather than mocking the git CLI.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  commitExists,
  emptyNote,
  firstParent,
  listChangedFiles,
  listNotes,
  noteWithAppendedSignature,
  parseNote,
  readNote,
  resolveCommitSha,
  serializeNote,
  TRUST_ANCHOR_NOTES_REF,
  type TrustAnchorNote,
  writeNote,
} from "../src/lib/trustAnchorNotes.ts";

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function setupRepoWithStampCommit(): { repo: string; headSha: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-notes-"));
  const repo = path.join(root, "repo");
  mkdirSync(repo, { recursive: true });
  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  writeFileSync(path.join(repo, ".stamp", "reviewers", "security.md"), "x");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add stamp reviewer"]);

  const headSha = git(repo, ["rev-parse", "HEAD"]).trim();
  return {
    repo,
    headSha,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

describe("trustAnchorNotes — serialize / parse round-trip", () => {
  it("round-trips a note with one signature", () => {
    const note: TrustAnchorNote = {
      version: 1,
      head_sha: "a".repeat(40),
      base_sha: "b".repeat(40),
      diff_sha256: "c".repeat(64),
      target_branch: "main",
      signatures: [
        { signer_key_id: "sha256:" + "d".repeat(64), signature: "ZmFrZQ==" },
      ],
    };
    const raw = serializeNote(note);
    const parsed = parseNote(raw);
    assert.ok(parsed, "round-trip must succeed");
    assert.deepEqual(parsed, note);
  });

  it("returns null on malformed JSON", () => {
    assert.equal(parseNote("not json"), null);
  });

  it("returns null on an array at the top level", () => {
    assert.equal(parseNote("[1,2,3]"), null);
  });

  it("returns null when version is missing", () => {
    assert.equal(
      parseNote(
        JSON.stringify({
          head_sha: "a",
          base_sha: "b",
          diff_sha256: "c",
          target_branch: "main",
          signatures: [],
        }),
      ),
      null,
    );
  });

  it("returns null when a signature entry is missing signer_key_id", () => {
    assert.equal(
      parseNote(
        JSON.stringify({
          version: 1,
          head_sha: "a",
          base_sha: "b",
          diff_sha256: "c",
          target_branch: "main",
          signatures: [{ signature: "x" }],
        }),
      ),
      null,
    );
  });

  it("returns null on oversized input (>64KB)", () => {
    const big = "x".repeat(65 * 1024);
    assert.equal(parseNote(big), null);
  });
});

describe("trustAnchorNotes — append semantics", () => {
  it("appends a fresh signer", () => {
    const empty = emptyNote({
      head_sha: "h",
      base_sha: "b",
      diff_sha256: "d",
      target_branch: "main",
    });
    const { note, alreadyPresent } = noteWithAppendedSignature(empty, {
      signer_key_id: "sha256:aa",
      signature: "zz",
    });
    assert.equal(alreadyPresent, false);
    assert.equal(note.signatures.length, 1);
    assert.equal(note.signatures[0]!.signer_key_id, "sha256:aa");
  });

  it("flags a duplicate signer without mutating the note", () => {
    const start: TrustAnchorNote = {
      ...emptyNote({ head_sha: "h", base_sha: "b", diff_sha256: "d", target_branch: "main" }),
      signatures: [{ signer_key_id: "sha256:aa", signature: "first" }],
    };
    const { note, alreadyPresent } = noteWithAppendedSignature(start, {
      signer_key_id: "sha256:aa",
      signature: "second",
    });
    assert.equal(alreadyPresent, true);
    assert.equal(note.signatures.length, 1);
    assert.equal(note.signatures[0]!.signature, "first");
  });
});

describe("trustAnchorNotes — git I/O round-trip", () => {
  it("writes a note and reads it back exactly", () => {
    const h = setupRepoWithStampCommit();
    try {
      const note: TrustAnchorNote = {
        version: 1,
        head_sha: h.headSha,
        base_sha: "b".repeat(40),
        diff_sha256: "c".repeat(64),
        target_branch: "main",
        signatures: [
          { signer_key_id: "sha256:" + "d".repeat(64), signature: "ZmFrZQ==" },
        ],
      };
      writeNote(h.repo, h.headSha, note);
      const back = readNote(h.repo, h.headSha);
      assert.ok(back);
      assert.deepEqual(back, note);
    } finally {
      h.cleanup();
    }
  });

  it("readNote returns null when no note is recorded", () => {
    const h = setupRepoWithStampCommit();
    try {
      assert.equal(readNote(h.repo, h.headSha), null);
    } finally {
      h.cleanup();
    }
  });

  it("overwrites an existing note on a second writeNote (force semantics)", () => {
    const h = setupRepoWithStampCommit();
    try {
      const first: TrustAnchorNote = {
        version: 1,
        head_sha: h.headSha,
        base_sha: "b",
        diff_sha256: "c",
        target_branch: "main",
        signatures: [{ signer_key_id: "sha256:1", signature: "first" }],
      };
      const second: TrustAnchorNote = {
        ...first,
        signatures: [
          ...first.signatures,
          { signer_key_id: "sha256:2", signature: "second" },
        ],
      };
      writeNote(h.repo, h.headSha, first);
      writeNote(h.repo, h.headSha, second);
      const back = readNote(h.repo, h.headSha);
      assert.ok(back);
      assert.equal(back.signatures.length, 2);
      assert.equal(back.signatures[1]!.signature, "second");
    } finally {
      h.cleanup();
    }
  });

  it("listNotes enumerates every commit that has a note", () => {
    const h = setupRepoWithStampCommit();
    try {
      // No notes yet → empty list (ref doesn't exist).
      assert.deepEqual(listNotes(h.repo), []);

      // Add a note on the current commit.
      const note: TrustAnchorNote = {
        version: 1,
        head_sha: h.headSha,
        base_sha: "b",
        diff_sha256: "c",
        target_branch: "main",
        signatures: [{ signer_key_id: "sha256:1", signature: "a" }],
      };
      writeNote(h.repo, h.headSha, note);

      const listed = listNotes(h.repo);
      assert.equal(listed.length, 1);
      assert.equal(listed[0]!.sha, h.headSha);
      assert.equal(listed[0]!.note.signatures.length, 1);
    } finally {
      h.cleanup();
    }
  });

  it("notes-ref is named refs/notes/stamp-trust-anchor-sigs", () => {
    assert.equal(TRUST_ANCHOR_NOTES_REF, "refs/notes/stamp-trust-anchor-sigs");
  });
});

describe("trustAnchorNotes — git helpers (commitExists, resolveCommitSha, firstParent, listChangedFiles)", () => {
  it("commitExists is true for the HEAD commit and false for nonsense", () => {
    const h = setupRepoWithStampCommit();
    try {
      assert.equal(commitExists(h.repo, h.headSha), true);
      assert.equal(commitExists(h.repo, "0".repeat(40)), false);
    } finally {
      h.cleanup();
    }
  });

  it("resolveCommitSha returns full SHA from an abbreviated rev", () => {
    const h = setupRepoWithStampCommit();
    try {
      const abbrev = h.headSha.slice(0, 8);
      assert.equal(resolveCommitSha(h.repo, abbrev), h.headSha);
    } finally {
      h.cleanup();
    }
  });

  it("resolveCommitSha throws on an unknown rev", () => {
    const h = setupRepoWithStampCommit();
    try {
      assert.throws(() => resolveCommitSha(h.repo, "definitely-not-a-rev"));
    } finally {
      h.cleanup();
    }
  });

  it("firstParent walks the parent chain and returns null at the root", () => {
    const h = setupRepoWithStampCommit();
    try {
      const parent = firstParent(h.repo, h.headSha);
      assert.ok(parent, "second commit must have a parent");
      const grand = firstParent(h.repo, parent!);
      assert.equal(grand, null, "first commit is the root");
    } finally {
      h.cleanup();
    }
  });

  it("listChangedFiles returns the files added between two commits", () => {
    const h = setupRepoWithStampCommit();
    try {
      const parent = firstParent(h.repo, h.headSha)!;
      const files = listChangedFiles(h.repo, parent, h.headSha);
      assert.ok(files);
      assert.deepEqual(files, [".stamp/reviewers/security.md"]);
    } finally {
      h.cleanup();
    }
  });
});
