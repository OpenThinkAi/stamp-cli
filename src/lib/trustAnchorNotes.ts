/**
 * Trust-anchor multi-sig collection storage (AGT-337).
 *
 * Admins counter-sign a pending `.stamp/**`-touching commit by appending
 * their Ed25519 signature to a git notes-ref keyed by the commit SHA.
 * `stamp merge` reads from the same notes-ref at merge time and folds the
 * collected signatures into the v4 envelope's
 * `trust_anchor_signatures[]`.
 *
 * --- Why git notes (vs. commit trailers) ---
 *
 * The alternative — appending each signer's signature as a commit trailer
 * via `git commit --amend` — would mutate the commit SHA on each
 * counter-sign. That breaks the "discover pending commits awaiting
 * counter-signature" UX (each admin would be looking at a different
 * commit hash), compounds badly with `minimum_signatures: 3+`, and forces
 * the second admin to re-sign against the post-first-amend commit SHA.
 *
 * Git notes are *mutable, commit-keyed metadata* that don't change the
 * commit hash. They can be pushed (`git push origin
 * refs/notes/stamp-trust-anchor-sigs`) and pulled (`git fetch origin
 * refs/notes/*:refs/notes/*`) like any other ref — operators coordinate
 * exactly like they coordinate branches today.
 *
 * --- Operational gap acknowledged ---
 *
 * Git does NOT auto-push notes refs with `git push`. The operator
 * collecting signatures must explicitly push the notes-ref:
 *
 *   git push origin refs/notes/stamp-trust-anchor-sigs
 *
 * `stamp admin sign` prints a reminder after each successful sign. This
 * is a documented operational property, not a bug — the same way today
 * operators must explicitly push tags. A future ticket can land
 * auto-push (e.g. via a `git config remote.origin.push +refs/notes/*`
 * post-init step) once the notes-ref shape is settled.
 *
 * --- Payload schema (version 1) ---
 *
 *   {
 *     "version": 1,
 *     "head_sha": "<full SHA>",
 *     "base_sha": "<full SHA>",
 *     "diff_sha256": "<hex>",
 *     "target_branch": "<branch>",
 *     "signatures": [
 *       { "signer_key_id": "sha256:...", "signature": "<base64>" }
 *     ]
 *   }
 *
 * The signatures sign `canonicalSerializePayload({...v4Payload,
 * trust_anchor_signatures: []})` — the SAME bytes the pre-receive
 * verifier checks against (see `verifyV4TrustAnchorSignatures` in
 * `src/hooks/pre-receive.ts`). The note's `head_sha` / `base_sha` /
 * `diff_sha256` / `target_branch` are stored alongside as
 * machine-readable provenance (handy for `stamp admin sign --pending`'s
 * list mode) and are also part of the signed v4-payload bytes via the
 * shared serializer.
 */

import { execFileSync, spawnSync } from "node:child_process";

/** Notes-ref name. Single source of truth — every reader and writer
 *  imports this rather than hard-coding the string. */
export const TRUST_ANCHOR_NOTES_REF = "refs/notes/stamp-trust-anchor-sigs";

/** Bounded read size for a single note. Notes are tiny by design (one
 *  short JSON object); anything orders-of-magnitude larger is either a
 *  bug or an attempt to balloon git's pack. Cheaper to refuse than to
 *  parse. */
export const MAX_NOTE_BYTES = 64 * 1024;

/** Schema version stamped into each note payload. Bump when the field
 *  set changes; readers can either ignore unknown versions or surface
 *  them as "newer stamp wrote this note — upgrade". For now there's
 *  only one version, so this is forward-compat groundwork. */
export const TRUST_ANCHOR_NOTE_VERSION = 1;

/** One signature entry inside the note. Same shape as
 *  `TrustAnchorSignatureV4` in `attestationV4.ts` — kept structurally
 *  identical so `stamp merge` can hand the entries straight to the
 *  envelope's `trust_anchor_signatures` field without remapping. */
export interface TrustAnchorNoteSignature {
  signer_key_id: string;
  signature: string;
}

/** Parsed note payload as read from the notes-ref. */
export interface TrustAnchorNote {
  version: number;
  head_sha: string;
  base_sha: string;
  diff_sha256: string;
  target_branch: string;
  signatures: TrustAnchorNoteSignature[];
}

/** Construct an empty note for a fresh commit. Caller fills in the
 *  first signature via `noteWithAppendedSignature`. */
export function emptyNote(input: {
  head_sha: string;
  base_sha: string;
  diff_sha256: string;
  target_branch: string;
}): TrustAnchorNote {
  return {
    version: TRUST_ANCHOR_NOTE_VERSION,
    head_sha: input.head_sha,
    base_sha: input.base_sha,
    diff_sha256: input.diff_sha256,
    target_branch: input.target_branch,
    signatures: [],
  };
}

/** Return a new note with the given signature appended, refusing to add
 *  a duplicate signer_key_id. Returns `{ note, alreadyPresent: true }`
 *  when the signer has already signed — caller surfaces this as a
 *  clean no-op rather than an error. */
export function noteWithAppendedSignature(
  note: TrustAnchorNote,
  sig: TrustAnchorNoteSignature,
): { note: TrustAnchorNote; alreadyPresent: boolean } {
  for (const existing of note.signatures) {
    if (existing.signer_key_id === sig.signer_key_id) {
      return { note, alreadyPresent: true };
    }
  }
  return {
    note: { ...note, signatures: [...note.signatures, sig] },
    alreadyPresent: false,
  };
}

/** Serialize a note for storage. JSON with stable key ordering and a
 *  trailing newline (matches git's note-blob convention). Not a
 *  signing target — signatures sign the v4-payload bytes, not the
 *  note JSON itself. */
export function serializeNote(note: TrustAnchorNote): string {
  return JSON.stringify(
    {
      version: note.version,
      head_sha: note.head_sha,
      base_sha: note.base_sha,
      diff_sha256: note.diff_sha256,
      target_branch: note.target_branch,
      signatures: note.signatures.map((s) => ({
        signer_key_id: s.signer_key_id,
        signature: s.signature,
      })),
    },
    null,
    2,
  ) + "\n";
}

/** Parse a note blob. Returns null on any structural failure — callers
 *  treat "unparseable note" as "no note recorded" because the verifier
 *  side will independently re-derive trust from the manifest + Ed25519. */
export function parseNote(raw: string): TrustAnchorNote | null {
  if (raw.length === 0 || raw.length > MAX_NOTE_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const o = parsed as Partial<TrustAnchorNote>;
  if (
    typeof o.version !== "number" ||
    typeof o.head_sha !== "string" ||
    typeof o.base_sha !== "string" ||
    typeof o.diff_sha256 !== "string" ||
    typeof o.target_branch !== "string" ||
    !Array.isArray(o.signatures)
  ) {
    return null;
  }
  const sigs: TrustAnchorNoteSignature[] = [];
  for (const s of o.signatures) {
    if (!s || typeof s !== "object") return null;
    const sig = s as Partial<TrustAnchorNoteSignature>;
    if (typeof sig.signer_key_id !== "string" || typeof sig.signature !== "string") {
      return null;
    }
    sigs.push({ signer_key_id: sig.signer_key_id, signature: sig.signature });
  }
  return {
    version: o.version,
    head_sha: o.head_sha,
    base_sha: o.base_sha,
    diff_sha256: o.diff_sha256,
    target_branch: o.target_branch,
    signatures: sigs,
  };
}

// ─── git notes I/O ─────────────────────────────────────────────────

/** Read the note attached to `sha` on `TRUST_ANCHOR_NOTES_REF`. Returns
 *  null when no note is recorded (the dominant first-counter-sign case)
 *  or when the note exists but is unparseable. */
export function readNote(repoRoot: string, sha: string): TrustAnchorNote | null {
  const result = spawnSync(
    "git",
    ["notes", `--ref=${TRUST_ANCHOR_NOTES_REF}`, "show", sha],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  // exit 1 = no note exists for this object. That's the common case
  // before the first signature lands; treat as "no note", not as error.
  if (result.status !== 0) return null;
  const raw = result.stdout?.toString("utf8") ?? "";
  if (raw.length > MAX_NOTE_BYTES) return null;
  return parseNote(raw);
}

/** Write (or overwrite) the note attached to `sha` on
 *  `TRUST_ANCHOR_NOTES_REF`. Uses `git notes add -f` which is the same
 *  primitive `git notes append` ultimately drives — `-f` forces overwrite
 *  with our pre-serialized content so we keep the storage shape in
 *  TypeScript rather than in git's note-merger.
 *
 *  stdin-streams the content so we don't have to thread it through a
 *  tempfile or fight commit-message length limits. */
export function writeNote(
  repoRoot: string,
  sha: string,
  note: TrustAnchorNote,
): void {
  const payload = serializeNote(note);
  const result = spawnSync(
    "git",
    ["notes", `--ref=${TRUST_ANCHOR_NOTES_REF}`, "add", "-f", "-F", "-", sha],
    {
      cwd: repoRoot,
      input: payload,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  if (result.status !== 0) {
    const stderr = result.stderr?.toString("utf8").trim() ?? "";
    throw new Error(
      `git notes add (${TRUST_ANCHOR_NOTES_REF}) failed for ${sha}: ${stderr || "(no stderr)"}`,
    );
  }
}

/** Enumerate (sha, note) pairs for every commit that has a note on the
 *  trust-anchor notes-ref. Used by `stamp admin sign --pending` (no
 *  SHA) to list pending commits awaiting counter-signature. Bounded by
 *  git's own output — typically tiny (one entry per in-flight admin
 *  change). */
export function listNotes(
  repoRoot: string,
): Array<{ sha: string; note: TrustAnchorNote }> {
  const result = spawnSync(
    "git",
    ["notes", `--ref=${TRUST_ANCHOR_NOTES_REF}`, "list"],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  // No notes-ref yet → exit 1 with empty list. Same fail-open posture
  // as readNote.
  if (result.status !== 0) return [];
  const text = result.stdout?.toString("utf8") ?? "";
  const out: Array<{ sha: string; note: TrustAnchorNote }> = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    // `git notes list` prints "<note-blob-sha> <annotated-commit-sha>".
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const annotated = parts[1]!;
    const n = readNote(repoRoot, annotated);
    if (n) out.push({ sha: annotated, note: n });
  }
  return out;
}

/** True when a commit exists in this repo. Cheap wrapper around `git
 *  cat-file -e` — returns false on any non-zero exit (unknown SHA,
 *  ambiguous prefix, etc.). Used by sign-mode to fail fast with an
 *  actionable error before we start computing payloads. */
export function commitExists(repoRoot: string, sha: string): boolean {
  const result = spawnSync(
    "git",
    ["cat-file", "-e", `${sha}^{commit}`],
    { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
  );
  return result.status === 0;
}

/** Resolve a (possibly abbreviated) revision to its full commit SHA.
 *  Throws on failure with a clean message — sign-mode wants this to
 *  bubble up as a CLI error, not silently downgrade. */
export function resolveCommitSha(repoRoot: string, rev: string): string {
  try {
    const out = execFileSync("git", ["rev-parse", "--verify", `${rev}^{commit}`], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return out.trim();
  } catch (err) {
    const stderr = (err as { stderr?: Buffer | string } | null)?.stderr;
    const stderrText =
      typeof stderr === "string" ? stderr : stderr?.toString("utf8") ?? "";
    throw new Error(
      `unable to resolve revision ${JSON.stringify(rev)} to a commit SHA: ${
        stderrText.trim() || (err instanceof Error ? err.message : String(err))
      }`,
    );
  }
}

/** First-parent of `sha`, or null if `sha` has no parent (root commit)
 *  or is unresolvable. Used by `admin sign --pending <sha>` to compute
 *  the base for the diff that admins are gating. */
export function firstParent(repoRoot: string, sha: string): string | null {
  const result = spawnSync(
    "git",
    ["rev-parse", "--verify", `${sha}^1^{commit}`],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  if (result.status !== 0) return null;
  return result.stdout?.toString("utf8").trim() || null;
}

/** Enumerate files changed between `base_sha` and `head_sha` (null-
 *  delimited, like the pre-receive verifier's reader). Returns null if
 *  the diff is unreadable. */
export function listChangedFiles(
  repoRoot: string,
  baseSha: string,
  headSha: string,
): string[] | null {
  const result = spawnSync(
    "git",
    ["diff", "-z", "--name-only", `${baseSha}...${headSha}`],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024 },
  );
  if (result.status !== 0) return null;
  const text = result.stdout?.toString("utf8") ?? "";
  if (text.length === 0) return [];
  // `-z` emits NUL-terminated entries; final NUL produces a trailing empty.
  return text.split("\0").filter((p) => p.length > 0);
}
