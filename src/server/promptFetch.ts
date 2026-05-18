/**
 * Server-side canonical reviewer-prompt fetch — the load-bearing security
 * step of server-attested reviews (stamp 2.x, AGT-329).
 *
 * The trust property of server-attested reviews collapses unless the SERVER
 * (not the client) controls which prompt bytes get fed to the LLM. If the
 * client could supply the prompt the substitution attack returns: an
 * operator passes a permissive prompt to the LLM, but embeds the canonical
 * prompt's hash in the attestation, and the verifier sees a perfectly
 * consistent claim about a real LLM call that bears no relationship to what
 * the model actually read.
 *
 * This module is the choke point. It fetches `.stamp/reviewers/<name>.md`
 * from the server's LOCAL bare repo at the caller's claimed `base_sha` —
 * never from anywhere else, never with any caller-controlled fallback. The
 * AGT-330 SSH-verb handler (and the future HTTP handler) calls this exactly
 * once per review request and pipes the returned bytes directly into the
 * Anthropic system message; the resulting `prompt_sha256` lives inside the
 * `ApprovalV4` body that the server then signs.
 *
 * --- Why no fallback parameter ---
 *
 * The module's surface deliberately offers no way to pass a substitute
 * prompt, an override path, an extra search root, or a "use this if the
 * fetch fails" fallback. Adding any such knob — even one gated behind a
 * dev-only flag — would re-open the substitution attack. The whole point
 * of moving the fetch server-side is that the (org, repo, base_sha,
 * reviewer_name) tuple is the ONLY input that determines what the server
 * reads. Anything else, by construction, is forbidden.
 *
 * If the fetch fails for any reason (no such repo, no such ref, no such
 * file at that ref, ambiguous SHA prefix, git unavailable), this module
 * returns a typed error and the verb handler maps it to a clean SSH
 * response. Falling back to a different prompt — including the prompt at
 * HEAD, the prompt at the caller's claimed head_sha, or the prompt that
 * happened to exist last time we serviced this repo — is forbidden.
 *
 * --- Multi-tenant routing via injected resolver ---
 *
 * Phase 1 stamp-server is single-tenant: bare repos live flat under
 * `/srv/git/<name>.git` (see `server/new-stamp-repo`), with the operator
 * who provisioned the server holding implicit ownership. The `org`
 * argument is plumbed through but `defaultRepoResolver` ignores it.
 *
 * Phase 2 SaaS will host many tenants on one server; the resolver injection
 * point is what lets the same handler serve both deployments without
 * branching on a "single-tenant?" flag. The SaaS resolver will translate
 * (org, repo) → `<state>/<org-id>/<repo>.git` (or whatever path layout the
 * tenancy model lands on) and the rest of this module — git invocation,
 * error mapping, hashing — stays identical.
 *
 * The resolver is a synchronous pure function returning a string path. It
 * MUST NOT do any I/O (no `existsSync`, no network) — keeping it pure
 * means the handler can pre-compute the path for logging before we hit the
 * fetch, and test injection becomes trivial. Existence checks happen via
 * the git invocation itself (an absent repo surfaces as `no_such_repo`).
 *
 * --- Hash convention ---
 *
 * `FetchedPrompt.sha256` is BARE HEX (no `sha256:` prefix), matching
 * `ApprovalV4.prompt_sha256` in `src/lib/attestationV4.ts`. This is the
 * opposite convention from `src/lib/trustedKeysManifest.ts`, which uses
 * `sha256:<hex>` for KEY fingerprints — different field, different
 * convention, do not conflate. The caller folds this value directly into
 * the approval body before canonical serialization + signing.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Resolves an `(org, repo)` pair to the absolute path of the bare git
 * repository on this server's filesystem. Synchronous, pure — no I/O,
 * no async, no thrown errors for "not found" (an absent path surfaces
 * naturally as a `no_such_repo` from the git invocation).
 *
 * Phase 1: `defaultRepoResolver` ignores `org` and maps `repo` to
 * `<baseDir>/<repo>.git`. Phase 2: SaaS deployments inject a tenant-aware
 * resolver that consults the orgs table.
 *
 * Implementations MUST validate inputs that get interpolated into a
 * filesystem path. `defaultRepoResolver` is conservative: it rejects any
 * `repo` containing `/`, `..`, or other shell/path-meta characters. SaaS
 * resolvers must do at least the same.
 */
export type RepoResolver = (org: string, repo: string) => string;

/**
 * The successful fetch result. `bytes` is the raw `.md` file content as
 * Git returned it — no normalization, no trimming, no line-ending fixes.
 * Whatever is in the tree at `base_sha` is what the LLM sees and what
 * the hash binds. `sha256` is bare hex (see file-header doc).
 */
export interface FetchedPrompt {
  kind: "ok";
  bytes: Buffer;
  /** Hex sha256 of `bytes`. Bare — no `sha256:` prefix. Matches the
   *  `ApprovalV4.prompt_sha256` convention in `src/lib/attestationV4.ts`. */
  sha256: string;
}

/**
 * Typed failure mode. Each `kind` maps to a stable client-facing error
 * category; the verb handler in AGT-330 translates these to SSH responses.
 *
 * `detail` is server-side diagnostic surface — log it, do NOT surface it
 * verbatim to the caller (git stderr can leak server filesystem layout or
 * unrelated repo names). The verb handler should respond with a generic
 * "<kind>: not available" message and rely on operator-visible logs for
 * the detail.
 *
 * Categories:
 *   - `no_such_repo`         — resolver returned a path; git couldn't open
 *                              a repository there. Either the repo isn't
 *                              registered, the bare repo got removed, or
 *                              the resolver pointed at a non-git directory.
 *   - `no_such_ref`          — the bare repo exists but does not contain
 *                              the claimed `base_sha`. The caller's
 *                              client DB is out of sync with the server,
 *                              or the caller fabricated a SHA.
 *   - `no_such_file`         — `base_sha` exists; `.stamp/reviewers/<name>.md`
 *                              does not exist in that tree. The reviewer
 *                              wasn't configured at that base, or the
 *                              reviewer name is misspelled.
 *   - `ambiguous_sha`        — caller passed a SHA prefix that matches
 *                              multiple objects. We REQUIRE full 40-char
 *                              SHAs upstream of this module, but git also
 *                              detects this and we surface it cleanly.
 *   - `invalid_input`        — `repo`, `base_sha`, or `reviewer_name`
 *                              failed shape validation. Caller bug or
 *                              attempted injection.
 *   - `git_error`            — git invocation failed for a reason that
 *                              doesn't match any of the above (subprocess
 *                              spawn failure, git binary missing, OOM,
 *                              etc.). Operator-actionable.
 */
export interface PromptFetchError {
  kind:
    | "no_such_repo"
    | "no_such_ref"
    | "no_such_file"
    | "ambiguous_sha"
    | "invalid_input"
    | "git_error";
  detail: string;
}

export type PromptFetchResult = FetchedPrompt | PromptFetchError;

// ─── Input validation ───────────────────────────────────────────────

/** Reviewer-name shape; mirrors `VALID_REVIEWER_NAME` in
 *  `src/commands/reviewers.ts` so a name that round-trips through the
 *  client `reviewers add` UI also round-trips through the server fetch. */
const REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

/** Full 40-char lowercase hex SHA-1. We deliberately reject abbreviated
 *  SHAs and SHA-256 ids: the SSH verb's stdin schema (AGT-330) commits to
 *  the client sending full SHAs, and an abbreviation could otherwise hit
 *  the `ambiguous_sha` path on perfectly innocent inputs. */
const FULL_SHA_RE = /^[0-9a-f]{40}$/;

/** Phase-1 repo-name shape, used by `defaultRepoResolver`. Matches the
 *  shell-level validator in `server/new-stamp-repo` (same characters,
 *  same leading-char constraint). Custom resolvers may apply tighter or
 *  looser rules suited to their tenancy model but must reject path
 *  separators and traversal segments. */
const REPO_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

/** Phase-1 org-name shape. Phase 1 ignores `org` (single-tenant) but we
 *  still validate it so that a hostile or buggy caller can't smuggle path
 *  metacharacters through and surprise a future multi-tenant resolver
 *  that the same code path also invokes. Conservative: same shape as the
 *  repo name. */
const ORG_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

// ─── Public surface ─────────────────────────────────────────────────

/**
 * Build the Phase-1 single-tenant resolver. `baseDir` is the directory
 * holding the bare repos (e.g. `/srv/git`). The resolver ignores `org`
 * and returns `<baseDir>/<repo>.git`. Validates both `org` and `repo`
 * against the conservative Phase-1 shape regexes; throws on shape failure
 * since a shape-invalid input here is a caller bug, not a runtime
 * condition the verb handler should try to recover from.
 *
 * `baseDir` is taken at resolver-construction time, not at each call, so
 * the verb handler can build the resolver once at startup from
 * `serverConfig.repoRootPrefix` and inject it into every request.
 */
export function defaultRepoResolver(baseDir: string): RepoResolver {
  if (!baseDir || typeof baseDir !== "string") {
    throw new Error("defaultRepoResolver: baseDir must be a non-empty string");
  }
  // Strip exactly one trailing slash so `<baseDir>/<repo>.git` doesn't
  // produce `//`. Leave other paths (no trailing slash) untouched.
  const normalized = baseDir.endsWith("/") ? baseDir.slice(0, -1) : baseDir;
  return (org: string, repo: string): string => {
    if (!ORG_NAME_RE.test(org)) {
      throw new Error(
        `defaultRepoResolver: invalid org name '${org}' (must match ${ORG_NAME_RE.source})`,
      );
    }
    if (!REPO_NAME_RE.test(repo)) {
      throw new Error(
        `defaultRepoResolver: invalid repo name '${repo}' (must match ${REPO_NAME_RE.source})`,
      );
    }
    return `${normalized}/${repo}.git`;
  };
}

/**
 * Fetch the canonical reviewer prompt for `(org, repo, baseSha, reviewerName)`
 * from the server's local bare repo. Returns a discriminated-union result:
 * callers branch on `result.kind` — `"ok"` carries the bytes + hash, any
 * other value is a `PromptFetchError`.
 *
 * The flow:
 *   1. Validate `baseSha` and `reviewerName` shape. (The resolver
 *      validates `org` and `repo` per its own contract.)
 *   2. Resolve the bare repo path via the injected resolver.
 *   3. Run `git --git-dir=<bare> show <baseSha>:.stamp/reviewers/<name>.md`,
 *      capturing stdout as raw bytes (NOT utf-8 decoded — the hash binds
 *      to the file bytes verbatim).
 *   4. Hash the bytes with SHA-256 (bare hex).
 *   5. Return `{ kind: "ok", bytes, sha256 }`.
 *
 * Errors from `git show` are mapped to typed `PromptFetchError` kinds by
 * inspecting stderr. We use stderr-text matching (rather than exit code
 * alone) because git uses exit 128 for every "couldn't resolve" case —
 * missing repo, missing ref, missing path, ambiguous SHA — and we want
 * to surface those distinctly so the verb handler can produce useful
 * messages without leaking server internals.
 *
 * Buffered stdout is bounded by `MAX_PROMPT_BYTES`. Reviewer prompts in
 * the wild are kilobytes; the cap defends against a future malicious
 * commit that lands a multi-megabyte file at the prompt path.
 */
export async function fetchCanonicalPrompt(
  resolver: RepoResolver,
  org: string,
  repo: string,
  baseSha: string,
  reviewerName: string,
): Promise<PromptFetchResult> {
  // Shape checks first so an invalid input never reaches git. `repo`/`org`
  // are validated inside the resolver (whose contract owns those fields).
  if (!FULL_SHA_RE.test(baseSha)) {
    return {
      kind: "invalid_input",
      detail: `baseSha must be a full 40-char lowercase hex SHA (got ${JSON.stringify(baseSha)})`,
    };
  }
  if (!REVIEWER_NAME_RE.test(reviewerName)) {
    return {
      kind: "invalid_input",
      detail: `reviewerName must match ${REVIEWER_NAME_RE.source} (got ${JSON.stringify(reviewerName)})`,
    };
  }

  let bareRepoPath: string;
  try {
    bareRepoPath = resolver(org, repo);
  } catch (err) {
    return {
      kind: "invalid_input",
      detail: `resolver rejected (org=${JSON.stringify(org)}, repo=${JSON.stringify(repo)}): ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }

  const promptPath = `.stamp/reviewers/${reviewerName}.md`;
  const spec = `${baseSha}:${promptPath}`;

  // Two-stage fetch so we can map errors to the right typed kind without
  // relying on git's stderr wording for the missing-ref vs missing-file
  // distinction. Stage 1: confirm the commit exists in the bare. Stage 2:
  // read the file at that commit. Each stage produces a distinct
  // classification path:
  //
  //   - Stage 1 ENOENT / "not a git repository" → no_such_repo
  //   - Stage 1 exit != 0 with the ref absent   → no_such_ref
  //   - Stage 1 reports an ambiguous SHA        → ambiguous_sha (defensive;
  //                                                full-SHA validation
  //                                                above already eliminates
  //                                                the realistic case)
  //   - Stage 2 "exists on disk, but not in"
  //     or  "does not exist in"                 → no_such_file
  //   - Stage 2 any other failure               → git_error
  //
  // Without stage 1, `git show <bad-sha>:<path>` reports "exists on disk,
  // but not in '<sha>'" — its sub-process inspected the invoking
  // process's CWD for the path, which collides with our no_such_file
  // signal. Probing existence explicitly via `rev-parse --verify
  // <sha>^{commit}` is the unambiguous test for "is this commit
  // resolvable in this bare repo." See AGT-329 test
  // `no_such_ref: base_sha doesn't exist in the bare repo` for the
  // regression this guards against.
  const refCheck = await runGitShow(
    bareRepoPath,
    ["rev-parse", "--verify", "--end-of-options", `${baseSha}^{commit}`],
  );
  if (!refCheck.ok) {
    return classifyRefCheckError(refCheck.err, bareRepoPath, baseSha, promptPath);
  }

  // `git show <sha>:<path>` is the documented way to read a file at a
  // specific tree. `--git-dir` makes it work against a bare repo without
  // requiring `cd`. `-c core.quotePath=false` neutralizes path-quoting
  // surprises in any future error messages we surface.
  //
  // Buffer output (not utf-8 string) so the SHA-256 we compute binds to
  // the file's exact bytes — prompts could in principle contain
  // non-utf-8 bytes (e.g. an embedded image fence reference) and the
  // verifier rehashes from the bytes of the committed tree, not from a
  // round-trip through a string codec.
  try {
    const { stdout } = await execFileAsync(
      "git",
      [
        "--git-dir",
        bareRepoPath,
        "-c",
        "core.quotePath=false",
        "show",
        spec,
      ],
      {
        encoding: "buffer",
        maxBuffer: MAX_PROMPT_BYTES,
        // No env passthrough beyond what node defaults to; in particular
        // do NOT set GIT_DIR / GIT_WORK_TREE here since `--git-dir` is
        // already explicit on argv.
      },
    );
    const bytes = stdout as Buffer;
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    return { kind: "ok", bytes, sha256 };
  } catch (err) {
    return classifyShowError(err, bareRepoPath, baseSha, promptPath);
  }
}

/** Minimal async git-runner used by the ref-existence probe. Returns a
 *  discriminated union so callers can classify failures explicitly
 *  without try/catch threading. */
async function runGitShow(
  bareRepoPath: string,
  args: string[],
): Promise<{ ok: true } | { ok: false; err: unknown }> {
  try {
    await execFileAsync(
      "git",
      ["--git-dir", bareRepoPath, "-c", "core.quotePath=false", ...args],
      { encoding: "buffer" },
    );
    return { ok: true };
  } catch (err) {
    return { ok: false, err };
  }
}

/** Hard cap on a single fetched prompt. Reviewer prompts are normally a
 *  few KB; a megabyte is already huge. 1 MB gives plenty of headroom for
 *  rich prompts without leaving DoS surface open. Exceeding this on
 *  execFile surfaces as a `git_error` with the `maxBuffer` exceeded
 *  message, which is exactly the failure mode we want — the verb handler
 *  rejects rather than processing a runaway file. */
const MAX_PROMPT_BYTES = 1 * 1024 * 1024;

// ─── Error classification ───────────────────────────────────────────

/** Classify a stage-1 `rev-parse --verify <sha>^{commit}` failure. The
 *  refCheck step exists to give us an unambiguous signal for
 *  no_such_repo / no_such_ref / ambiguous_sha BEFORE we touch the
 *  potentially-confusing `git show` stderr wording (see
 *  `fetchCanonicalPrompt` for the rationale).
 *
 *  Stable across the git versions stamp-server ships (Alpine git 2.40+
 *  and the Debian/Ubuntu builds operators run on bare VPS). If git's
 *  wording shifts in a future release the worst case is reclassification
 *  to `git_error` — still rejected, still logged, never silently approved. */
function classifyRefCheckError(
  err: unknown,
  bareRepoPath: string,
  baseSha: string,
  promptPath: string,
): PromptFetchError {
  const e = err as {
    code?: string | number;
    stderr?: Buffer | string;
    message?: string;
  };
  const stderrText =
    typeof e.stderr === "string"
      ? e.stderr
      : Buffer.isBuffer(e.stderr)
        ? e.stderr.toString("utf8")
        : "";
  const detail = `git --git-dir=${bareRepoPath} rev-parse ${baseSha}^{commit} failed (for prompt path ${promptPath}): ${stderrText.trim() || e.message || String(err)}`;

  // execFile sets err.code = 'ENOENT' when the git BINARY itself is
  // missing (vs. non-zero exit when git ran but couldn't resolve
  // something). Surface as git_error so operators see "is git
  // installed?" rather than a misleading "no such repo."
  if (e.code === "ENOENT") {
    return { kind: "git_error", detail };
  }

  // Git's "not a git repository" wording covers: directory doesn't
  // exist, directory exists but isn't a git repo, directory exists and
  // is a repo but lacks the bits git needs (missing HEAD, etc.). All
  // three collapse to "this repo isn't usable from the server's
  // perspective" — `no_such_repo` is the right category.
  if (
    /not a git repository/i.test(stderrText) ||
    /cannot access/i.test(stderrText) ||
    /unable to access/i.test(stderrText) ||
    /does not exist/i.test(stderrText) && /\.git/.test(stderrText)
  ) {
    return { kind: "no_such_repo", detail };
  }

  // Ambiguous-SHA: a SHA prefix that matches multiple objects. Should
  // not occur with our full-SHA enforcement upstream, but keep the
  // branch live — git might surface this for a full SHA that collides
  // with a tag name.
  if (/short SHA1.*is ambiguous/i.test(stderrText)) {
    return { kind: "ambiguous_sha", detail };
  }
  // "ambiguous argument" is git's catch-all wording for unresolvable
  // refs ("ambiguous argument '<sha>': unknown revision"). The
  // "unknown revision" sub-phrase confirms ref-absent rather than a
  // true collision.
  if (/ambiguous argument/i.test(stderrText) && /unknown revision/i.test(stderrText)) {
    return { kind: "no_such_ref", detail };
  }
  if (/ambiguous argument/i.test(stderrText)) {
    return { kind: "ambiguous_sha", detail };
  }

  // `fatal: bad revision` / `Not a valid object name` / `unknown
  // revision` — the ref didn't resolve to anything. We've already
  // excluded ambiguous-SHA above; what's left is "ref not present in
  // this repo."
  if (
    /bad revision/i.test(stderrText) ||
    /Not a valid object name/i.test(stderrText) ||
    /unknown revision/i.test(stderrText) ||
    /needed a single revision/i.test(stderrText)
  ) {
    return { kind: "no_such_ref", detail };
  }

  return { kind: "git_error", detail };
}

/** Classify a stage-2 `git show <sha>:<path>` failure. Reached only
 *  AFTER `classifyRefCheckError` has confirmed the ref exists, so the
 *  realistic failure mode is "path not in tree." Other failures
 *  (maxBuffer overflow, transient git crash) collapse to `git_error`. */
function classifyShowError(
  err: unknown,
  bareRepoPath: string,
  baseSha: string,
  promptPath: string,
): PromptFetchError {
  const e = err as {
    code?: string | number;
    stderr?: Buffer | string;
    message?: string;
  };
  const stderrText =
    typeof e.stderr === "string"
      ? e.stderr
      : Buffer.isBuffer(e.stderr)
        ? e.stderr.toString("utf8")
        : "";
  const detail = `git --git-dir=${bareRepoPath} show ${baseSha}:${promptPath} failed: ${stderrText.trim() || e.message || String(err)}`;

  if (e.code === "ENOENT") {
    return { kind: "git_error", detail };
  }

  // Path-not-found at a confirmed-resolved ref. Git surfaces this as
  // `fatal: path '<path>' does not exist in '<sha>'` or
  // `fatal: path '<path>' exists on disk, but not in '<sha>'`. Both
  // mean the reviewer file isn't there at this base.
  if (/does not exist in|exists on disk, but not in/i.test(stderrText)) {
    return { kind: "no_such_file", detail };
  }

  // maxBuffer overflow (file too large), git crashed mid-read, etc.
  // The verb handler logs the detail and operators can decide whether
  // to bump MAX_PROMPT_BYTES or treat the oversize file as a config
  // bug.
  return { kind: "git_error", detail };
}
