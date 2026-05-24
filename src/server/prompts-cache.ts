/**
 * Server-side prompts-cache module (AGT-372 — Phase B foundation).
 *
 * Maintains a local git clone of an external "reviewer prompts" repo and
 * resolves `(reviewer, org?, repo?)` → on-disk path. Sits underneath
 * `promptFetch.ts`: `cloneOrFetchPromptsCache` populates the cache directory,
 * `getPromptPath` answers per-request "which file do I read for this reviewer
 * on this repo?", and `defaultPromptCacheResolver` (Phase A, untouched in this
 * ticket) reads the bytes.
 *
 * Phase A's resolver mapped one (reviewer) → one path. Phase B layers a
 * per-repo override on top: `<cacheRoot>/<org>/<repo>/<reviewer>.md` if it
 * exists, else fall through to `<cacheRoot>/<reviewer>.md`. The lookup is the
 * ONLY filesystem I/O in `getPromptPath` (`existsSync`); the actual read still
 * happens in `fetchCanonicalPrompt` via `readFileSync`, where ENOENT surfaces
 * as `no_such_file`.
 *
 * --- Why a local clone, not a HiveDB-style direct-write ---
 *
 * Phase A had HiveDB writing prompt bytes directly into `STAMP_PROMPTS_DIR`.
 * Phase B replaces that channel with "operator pushes to a github prompts
 * repo, github webhook fires, stamp-server pulls from origin." The cache is
 * a real git working tree (not a bare clone) so `getPromptPath` can answer
 * with a normal filesystem path, and `fetchCanonicalPrompt` keeps its
 * `readFileSync` shape unchanged.
 *
 * --- Atomic refresh contract ---
 *
 * Both "clone the cache for the first time" and "rebuild from scratch after
 * a fetch failure" go through the atomic pattern:
 *
 *   1. Remove any stale `<cacheRoot>.tmp` from a previous failed attempt.
 *   2. `git clone <url> <cacheRoot>.tmp` (with deploy key wired via
 *      GIT_SSH_COMMAND if `deployKeyPath` is set).
 *   3. `git -C <cacheRoot>.tmp checkout <ref>` then `git -C <cacheRoot>.tmp
 *      rev-parse HEAD` — proves the ref resolved AND the tree is checked
 *      out, before we commit the swap.
 *   4. If `<cacheRoot>` already exists, rename it to `<cacheRoot>.old`,
 *      then rename `.tmp` → `<cacheRoot>`, then `rm -rf <cacheRoot>.old`.
 *      POSIX guarantees rename is atomic within the same filesystem; the
 *      brief window where neither name exists is bounded by two syscalls.
 *
 * A failure at step 2 or 3 leaves `<cacheRoot>` untouched — the existing
 * (last-known-good) cache stays consistent. The `.tmp` debris is cleaned up
 * at the START of the NEXT call rather than on failure, so debugging a
 * broken fetch can inspect the partial state.
 *
 * The faster in-place path (`git fetch && git reset --hard FETCH_HEAD`
 * inside an already-populated `<cacheRoot>`) is also supported and is the
 * common case for webhook-driven refreshes — but if that path fails for
 * any reason, we fall back to the atomic rebuild rather than leaving a
 * half-fetched tree in place.
 *
 * --- Concurrency model ---
 *
 * Two layers:
 *
 *  1. In-process: a `Map<cacheRoot, Promise<RefreshResult>>` coalesces
 *     concurrent calls from the same Node process. The second caller awaits
 *     the in-flight promise — no parallel `git fetch`, no parallel rename.
 *  2. Cross-process: a sibling lock file at `<cacheRoot>.refresh.lock`
 *     (NOT inside the clone — so the atomic rename doesn't move it) acquired
 *     via `O_CREAT | O_EXCL`. Stale-lock stealing after 5 minutes (mtime)
 *     handles SIGKILL'd processes that didn't release.
 *
 * Webhook bursts (github sometimes fires multiple deliveries within a few
 * hundred ms on a merge) collapse to one fetch; the second caller sees the
 * first's result.
 *
 * --- Deploy-key + known-hosts wiring ---
 *
 * SSH urls (`git@github.com:owner/repo.git`) need a private key on disk
 * (provisioned by the operator into the stamp-server volume — same posture
 * as `stamp-ensure-repo-key`) and a pinned known-hosts file so
 * `StrictHostKeyChecking=yes` doesn't prompt. The known-hosts file ships in
 * the image at `server/github-known-hosts`; we resolve it relative to this
 * module via `import.meta.url` so dev runs and packaged builds both find it.
 * Tests can override via the `GIT_SSH_KNOWN_HOSTS` env var to point at a
 * fixture.
 *
 * HTTPS urls bypass the key entirely — git's TLS does the host
 * verification. `deployKeyPath` is ignored in that case (but a non-existent
 * key path with an HTTPS url is NOT an error — operators may set both env
 * vars and toggle the url without re-deploying).
 */

import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve as pathResolve } from "node:path";

import { REVIEWER_NAME_RE } from "./promptFetch.js";

// ─── Public types ─────────────────────────────────────────────────────

/**
 * Options for `cloneOrFetchPromptsCache`.
 *
 *   - `url`         — github URL of the prompts repo. HTTPS or SSH.
 *   - `ref`         — branch or tag to track (e.g. `"main"`).
 *   - `cacheRoot`   — absolute directory path where the cache lives. The
 *                     parent dir must exist and be writable; the cache dir
 *                     itself is created/replaced by this function.
 *   - `deployKeyPath` — optional path to a private SSH key for SSH URLs.
 *                       Ignored for HTTPS URLs. The corresponding pubkey
 *                       must already be registered as a deploy key on the
 *                       prompts repo.
 */
export interface CloneOrFetchOpts {
  url: string;
  ref: string;
  cacheRoot: string;
  deployKeyPath?: string;
}

/**
 * Returned by `cloneOrFetchPromptsCache`. `commitSha` is the SHA-1 hex of
 * `HEAD` after the refresh — the operator can compare this against the
 * prompts repo's current `<ref>` SHA to detect missed/delayed webhook
 * deliveries. `refreshedAt` is wall-clock ISO-8601 set at completion.
 */
export interface RefreshResult {
  commitSha: string;
  refreshedAt: string;
}

// ─── Constants / shape validation ─────────────────────────────────────

/**
 * Github org/repo slug shape. Stricter than GitHub itself (which allows a
 * leading dot in obscure cases) but matches every name we'd realistically
 * see in a stamp-reviewers-style repo. Reuses the same character class as
 * `REVIEWER_NAME_RE` deliberately — these names get interpolated into a
 * filesystem path, and one canonical "safe slug" definition is easier to
 * reason about than two regexes that almost agree.
 */
const ORG_REPO_SLUG_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}$/;

/**
 * Stale-lock threshold. Five minutes is comfortably longer than any healthy
 * clone (sub-second to a few seconds even on a slow link for the typical
 * stamp-reviewers repo) and short enough that a SIGKILL'd stamp-server
 * recovers without operator intervention by the next webhook.
 */
const LOCK_STALE_MS = 5 * 60 * 1000;

// ─── Resolve the bundled github known-hosts file ──────────────────────

/**
 * Path to `server/github-known-hosts` resolved relative to this module.
 * Used in `GIT_SSH_COMMAND` for SSH clones so `StrictHostKeyChecking=yes`
 * has something to verify against without falling back to the user's
 * `~/.ssh/known_hosts`. Tests override via `GIT_SSH_KNOWN_HOSTS`.
 *
 * Deferred to a function (rather than a module-level constant) so the
 * `import.meta.url` lookup doesn't run at module load. AGT-375's
 * boot-time bootstrap binary consumes this module from a CJS bundle
 * (tsup `format: "cjs"`), where `import.meta.url` is undefined and an
 * eager `fileURLToPath(undefined)` would crash the bundle's entry. The
 * lookup is only ever needed inside `buildGitEnv` for SSH URLs, so
 * deferring is both correct and free; ESM consumers see the identical
 * result the first call computes.
 */
function defaultKnownHostsPath(): string {
  return pathResolve(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "server",
    "github-known-hosts",
  );
}

// ─── In-process coalescing map ────────────────────────────────────────

/**
 * Keyed by `cacheRoot` (the absolute path). Holds the in-flight refresh
 * promise so a second concurrent caller awaits the first's result instead
 * of starting a parallel git operation. Cleared when the promise settles
 * (success or failure) — a failed fetch shouldn't poison subsequent
 * attempts.
 *
 * Map (not Set or WeakMap) because the key is a string and we need to look
 * up by value; Map.delete on settle is the cleanup path.
 */
const inflightRefreshes = new Map<string, Promise<RefreshResult>>();

// ─── Public API ───────────────────────────────────────────────────────

/**
 * Clone (first run) or fetch+checkout (subsequent runs) the prompts repo
 * into `cacheRoot`. Idempotent: an already-populated cache for the same
 * `ref` resolves to `{ commitSha, refreshedAt }` after a fast no-op fetch.
 *
 * Coalesces concurrent callers via an in-process map AND a file-level lock
 * — see module header for the layered concurrency model. Atomic refresh:
 * mid-fetch failures leave `<cacheRoot>` intact.
 *
 * Throws (rather than returning a typed error) on any condition the operator
 * needs to fix synchronously: unreadable known-hosts file, unwritable parent
 * dir, missing deploy key, git not in PATH, git clone/fetch failure that the
 * atomic rebuild also failed to recover from. The caller (webhook route /
 * entrypoint / periodic poll) decides how to surface these.
 */
export async function cloneOrFetchPromptsCache(
  opts: CloneOrFetchOpts,
): Promise<RefreshResult> {
  validateOpts(opts);
  const cacheRoot = pathResolve(opts.cacheRoot);

  // In-process coalescing: if another caller in this process is already
  // refreshing the same cacheRoot, return that promise. The lock file
  // below catches cross-process races; this catches the (much more common)
  // single-process webhook-burst case.
  const existing = inflightRefreshes.get(cacheRoot);
  if (existing) return existing;

  const promise = (async (): Promise<RefreshResult> => {
    const lockPath = `${cacheRoot}.refresh.lock`;
    acquireLock(lockPath);
    try {
      return await refreshInternal({ ...opts, cacheRoot });
    } finally {
      releaseLock(lockPath);
    }
  })();

  inflightRefreshes.set(cacheRoot, promise);
  // Clear the map slot when the promise settles, success or failure, so
  // a subsequent caller after the failure gets to retry rather than
  // re-awaiting a rejected promise.
  promise.finally(() => {
    if (inflightRefreshes.get(cacheRoot) === promise) {
      inflightRefreshes.delete(cacheRoot);
    }
  }).catch(() => {
    // Swallow: the rejection is already surfaced via the returned `promise`.
    // This .catch attaches a no-op handler to the `.finally`'d branch so
    // node doesn't log an unhandled rejection warning from the bookkeeping
    // chain. The real handler is whoever awaited the returned `promise`.
  });

  return promise;
}

/**
 * Resolve the on-disk path for a `(reviewer, org?, repo?)` triple.
 *
 *   - If `org` AND `repo` are both supplied AND
 *     `<cacheRoot>/<org>/<repo>/<reviewer>.md` exists on disk,
 *     return that path (per-repo override).
 *   - Otherwise return `<cacheRoot>/<reviewer>.md` (default fallback).
 *
 * The fallback path is returned EVEN IF IT ALSO DOESN'T EXIST — existence
 * of the default path is `fetchCanonicalPrompt`'s job to check (it surfaces
 * a clean `no_such_file` error). This function only decides which path to
 * try; the read decides whether the prompt is there.
 *
 * All three inputs are validated against the same regex Phase A uses for
 * reviewer names (re-exported as `REVIEWER_NAME_RE` from `promptFetch.ts`).
 * Org/repo names are validated against a slightly broader slug regex that
 * accepts the dot character (github allows `my.org`).
 *
 * Throws on invalid input — by the time we reach the resolver, the SSH
 * verb has already validated the inputs; a violation here is a caller bug,
 * not an attempted injection.
 */
export function getPromptPath(
  cacheRoot: string,
  reviewer: string,
  org?: string,
  repo?: string,
): string {
  if (!cacheRoot || typeof cacheRoot !== "string") {
    throw new Error("getPromptPath: cacheRoot must be a non-empty string");
  }
  if (!REVIEWER_NAME_RE.test(reviewer)) {
    throw new Error(
      `getPromptPath: invalid reviewer name '${reviewer}' (must match ${REVIEWER_NAME_RE.source})`,
    );
  }
  const normalized = cacheRoot.endsWith("/") ? cacheRoot.slice(0, -1) : cacheRoot;

  // Per-repo override path. Only consult if BOTH org and repo are present
  // and both pass slug validation. If either is malformed, we fall through
  // to the default path rather than throwing — a malformed (org,repo) tuple
  // from upstream is more likely to be "this verb call didn't carry repo
  // context" than "an attacker forged a slug." The default-path read will
  // still error cleanly if the prompt isn't there.
  if (org && repo && ORG_REPO_SLUG_RE.test(org) && ORG_REPO_SLUG_RE.test(repo)) {
    const overridePath = `${normalized}/${org}/${repo}/${reviewer}.md`;
    if (existsSync(overridePath)) {
      return overridePath;
    }
  }
  return `${normalized}/${reviewer}.md`;
}

// ─── Internals ────────────────────────────────────────────────────────

/**
 * Permitted shapes for the prompts-cache git URL (AGT-417). Anchored at `^`,
 * so a value can never begin with `-` (the git option-injection class,
 * CVE-2017-1000117 — a `--upload-pack=<cmd>` / `-oProxyCommand=<cmd>` where
 * git expects a URL). The `\S+` tail forbids whitespace; C0 control chars
 * are rejected by a separate `hasControlChars` check in validateOpts (they
 * are not whitespace, so `\S` would otherwise admit them).
 * `file://` is intentionally permitted: it's a non-credential-bearing local
 * scheme and is the transport every offline test fixture uses. `git@host:`
 * is the scp-short SSH form (carries no inline secret — auth is by key).
 */
const GIT_URL_SHAPE_RE =
  /^(https:\/\/|ssh:\/\/|file:\/\/|git@[^\s:]+:)\S+$/;

/**
 * Mask credentials embedded in a URL's userinfo before it reaches a log or
 * error message (AGT-417). `https://x-access-token:<TOKEN>@github.com/...`
 * → `https://***@github.com/...`. Scheme-agnostic; leaves the scp-short
 * `git@host:` form alone (no `://`, no inline secret). Exported so the
 * poll-worker / bootstrap log sites scrub with the same rule.
 */
export function scrubGitUrlCredentials(text: string): string {
  return text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^@\s/]+@/gi, "$1***@");
}

/** True if `s` contains any C0 control character (charcode < 0x20). Used to
 * reject control chars in the git URL — `\S` in GIT_URL_SHAPE_RE rejects
 * whitespace but not controls. Charcode scan avoids embedding control-char
 * escapes in a regex literal. AGT-417. */
function hasControlChars(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) < 0x20) return true;
  }
  return false;
}

/**
 * Build the `git clone` / `git remote set-url` argv with a `--` terminator
 * before the operator-controlled `url` positional, so git can never
 * re-interpret it as an option even if the shape check were bypassed
 * (defense in depth alongside GIT_URL_SHAPE_RE). Exported so the terminator
 * is unit-testable without spawning git. AGT-417.
 */
export function buildCloneArgs(ref: string, url: string, tmpPath: string): string[] {
  return ["clone", "--quiet", "--branch", ref, "--", url, tmpPath];
}
export function buildRemoteSetUrlArgs(url: string): string[] {
  return ["remote", "set-url", "origin", "--", url];
}

function validateOpts(opts: CloneOrFetchOpts): void {
  if (!opts || typeof opts !== "object") {
    throw new Error("cloneOrFetchPromptsCache: opts must be an object");
  }
  if (!opts.url || typeof opts.url !== "string") {
    throw new Error("cloneOrFetchPromptsCache: url is required");
  }
  // Shape-validate the URL: anchored prefix allowlist + no whitespace/control
  // chars. Rejects `-`-leading option-injection payloads up front. AGT-417.
  if (!GIT_URL_SHAPE_RE.test(opts.url) || hasControlChars(opts.url)) {
    throw new Error(
      `cloneOrFetchPromptsCache: url ${JSON.stringify(scrubGitUrlCredentials(opts.url))} ` +
        `is not an accepted git URL shape (must start with https:// , ssh:// , file:// , or git@host: ` +
        `and contain no whitespace or control characters)`,
    );
  }
  if (!opts.ref || typeof opts.ref !== "string") {
    throw new Error("cloneOrFetchPromptsCache: ref is required");
  }
  if (!opts.cacheRoot || typeof opts.cacheRoot !== "string") {
    throw new Error("cloneOrFetchPromptsCache: cacheRoot is required");
  }
  // Disallow shell metacharacters in `ref` — even though we use execFileSync
  // (no shell), a refspec like `;rm -rf /` would be passed to git verbatim
  // and git's own parser might do something unexpected on certain refspecs.
  // Branch/tag names allow a wide character set; this is the conservative
  // intersection.
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,200}$/.test(opts.ref)) {
    throw new Error(
      `cloneOrFetchPromptsCache: ref ${JSON.stringify(opts.ref)} contains characters not allowed in a git refspec`,
    );
  }
}

/**
 * Acquire `<cacheRoot>.refresh.lock` via `O_CREAT | O_EXCL`. If the file
 * exists and is stale (older than `LOCK_STALE_MS`), we steal it. Throws
 * with a clear message if a fresh lock is held — caller should treat that
 * as "another process is already refreshing" and retry / coalesce upstream.
 *
 * Lives at the PARENT of `cacheRoot` (sibling, not child) so the atomic
 * rename of `<cacheRoot>.tmp` → `<cacheRoot>` doesn't displace it.
 */
function acquireLock(lockPath: string): void {
  // Make sure the parent directory exists before we try to create the lock
  // file. First-run on a fresh server has neither cacheRoot nor its
  // sibling lock present.
  mkdirSync(dirname(lockPath), { recursive: true });

  // Fast path — try exclusive create.
  try {
    const fd = openSync(lockPath, "wx");
    closeSync(fd);
    return;
  } catch (err) {
    const e = err as { code?: string };
    if (e.code !== "EEXIST") {
      throw new Error(
        `prompts-cache: could not create lock file ${lockPath}: ${(err as Error).message}`,
      );
    }
  }

  // EEXIST — check if it's stale.
  let lockStat;
  try {
    lockStat = statSync(lockPath);
  } catch (err) {
    // The file disappeared between openSync and statSync — extremely
    // unlikely race, retry the create once.
    try {
      const fd = openSync(lockPath, "wx");
      closeSync(fd);
      return;
    } catch (err2) {
      throw new Error(
        `prompts-cache: lock-file race on ${lockPath}: ${(err2 as Error).message}`,
      );
    }
  }

  const age = Date.now() - lockStat.mtimeMs;
  if (age > LOCK_STALE_MS) {
    // Steal the lock — previous holder is dead. `rmSync` then re-create.
    rmSync(lockPath, { force: true });
    const fd = openSync(lockPath, "wx");
    closeSync(fd);
    return;
  }

  throw new Error(
    `prompts-cache: refresh already in progress (lock ${lockPath} held, ${Math.round(age / 1000)}s old)`,
  );
}

function releaseLock(lockPath: string): void {
  try {
    rmSync(lockPath, { force: true });
  } catch {
    // Best-effort: if the lock is gone for some reason, we don't fail the
    // refresh over it. The next acquire will create afresh.
  }
}

/**
 * The actual refresh, called under the lock. Two paths:
 *
 *   - cacheRoot exists & looks like a git checkout → try in-place fetch
 *     (`git fetch` + `git reset --hard FETCH_HEAD`). Cheap, no rename.
 *   - cacheRoot missing, or in-place path failed → atomic rebuild via
 *     `<cacheRoot>.tmp` → renameSync.
 */
async function refreshInternal(
  opts: CloneOrFetchOpts & { cacheRoot: string },
): Promise<RefreshResult> {
  const { url, ref, cacheRoot, deployKeyPath } = opts;
  const env = buildGitEnv(deployKeyPath);
  const tmpPath = `${cacheRoot}.tmp`;

  // Clean any debris from a prior failed attempt up front. We deliberately
  // do NOT clean on failure (see module header) so a broken state can be
  // inspected by the operator before the next refresh wipes it.
  if (existsSync(tmpPath)) {
    rmSync(tmpPath, { recursive: true, force: true });
  }

  const cacheIsCheckout = existsSync(cacheRoot) && existsSync(`${cacheRoot}/.git`);

  if (cacheIsCheckout) {
    // Force the in-place fetch to use the URL the caller passed, not
    // whatever the .git/config remembers from the original clone. If the
    // operator rotates `STAMP_PROMPTS_REPO_URL` (e.g. HTTPS → SSH after
    // adding a deploy key) the next refresh must honor the new url
    // synchronously rather than continuing to fetch the old one. Also
    // means: if the caller passes a bogus url, the in-place fetch fails
    // here and we fall through to the atomic-rebuild path (which will
    // also fail against the same bogus url, throwing — exactly the
    // behavior the "mid-fetch failure" tests expect).
    try {
      runGit(cacheRoot, buildRemoteSetUrlArgs(url), env);
      runGit(cacheRoot, ["fetch", "--prune", "origin", "--", ref], env);
      runGit(cacheRoot, ["checkout", ref], env);
      runGit(cacheRoot, ["reset", "--hard", `origin/${ref}`], env);
      const commitSha = runGit(cacheRoot, ["rev-parse", "HEAD"], env).trim();
      return { commitSha, refreshedAt: new Date().toISOString() };
    } catch (err) {
      // In-place fetch failed (corrupted tree, remote moved, ref renamed,
      // network blip mid-fetch). Don't trust the partial state — fall
      // through to the atomic rebuild. The existing cacheRoot stays in
      // place until step 4 below.
      const reason = err instanceof Error ? err.message : String(err);
      process.stderr.write(
        `prompts-cache: in-place fetch failed (${reason}), falling back to atomic rebuild\n`,
      );
    }
  }

  // Atomic rebuild: clone to .tmp, verify, swap.
  mkdirSync(dirname(cacheRoot), { recursive: true });
  runGit(dirname(cacheRoot), buildCloneArgs(ref, url, tmpPath), env);

  // Belt-and-suspenders: confirm the ref resolved on disk before we commit
  // to the swap. `git clone --branch` would have errored if `ref` didn't
  // exist, but rev-parse catches "the clone succeeded but the working tree
  // is somehow empty" — paranoid, cheap.
  const commitSha = runGit(tmpPath, ["rev-parse", "HEAD"], env).trim();
  if (!/^[0-9a-f]{40}$/.test(commitSha)) {
    throw new Error(
      `prompts-cache: rev-parse HEAD in ${tmpPath} returned non-SHA ${JSON.stringify(commitSha)}`,
    );
  }

  // Atomic swap. POSIX rename(2) is atomic within a filesystem; we verified
  // both paths share a parent dir, so they're on the same filesystem by
  // construction.
  if (existsSync(cacheRoot)) {
    const oldPath = `${cacheRoot}.old`;
    if (existsSync(oldPath)) {
      rmSync(oldPath, { recursive: true, force: true });
    }
    renameSync(cacheRoot, oldPath);
    try {
      renameSync(tmpPath, cacheRoot);
    } catch (err) {
      // Restore the old cacheRoot if the second rename somehow fails.
      // Should be impossible on a healthy filesystem — both renames are
      // within the same dir — but if it does happen, the old cache is
      // still recoverable.
      try {
        renameSync(oldPath, cacheRoot);
      } catch {
        // We've now lost the cache. Surface the original error.
      }
      throw err;
    }
    rmSync(oldPath, { recursive: true, force: true });
  } else {
    renameSync(tmpPath, cacheRoot);
  }

  return { commitSha, refreshedAt: new Date().toISOString() };
}

/**
 * Build the env block we pass to git: inherits the parent env, then
 * overlays `GIT_SSH_COMMAND` if we have a deploy key. The known-hosts file
 * resolution lives here so a missing file produces a clear error before
 * git is invoked.
 */
function buildGitEnv(deployKeyPath: string | undefined): NodeJS.ProcessEnv {
  const env = { ...process.env };
  if (!deployKeyPath) return env;

  if (!existsSync(deployKeyPath)) {
    throw new Error(
      `prompts-cache: deployKeyPath ${deployKeyPath} does not exist — operator must provision the private SSH key`,
    );
  }

  const knownHostsPath = process.env["GIT_SSH_KNOWN_HOSTS"] || defaultKnownHostsPath();
  if (!existsSync(knownHostsPath)) {
    throw new Error(
      `prompts-cache: known-hosts file ${knownHostsPath} does not exist — image build is missing server/github-known-hosts`,
    );
  }

  env["GIT_SSH_COMMAND"] = [
    "ssh",
    "-i",
    quoteForSshCommand(deployKeyPath),
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${quoteForSshCommand(knownHostsPath)}`,
    "-o",
    "IdentitiesOnly=yes",
  ].join(" ");
  return env;
}

/**
 * `GIT_SSH_COMMAND` is parsed by /bin/sh, so paths containing spaces or
 * shell metacharacters would break. The stamp-server image's paths
 * (`/srv/git/...`) never contain such characters, but the dev sandbox or
 * a test fixture might (e.g. `/var/folders/.../T/`). Single-quote and
 * escape any embedded single quotes — same posture as `shell-quote` but
 * inlined to avoid a dependency for one call site.
 */
function quoteForSshCommand(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * Run `git` in `cwd` with the given args, return stdout. Throws on
 * non-zero exit. stderr is included in the thrown error's message so
 * the caller can log it. Uses `execFileSync` (no shell) — the args
 * array is the only injection surface, and we validate `ref` upstream.
 */
function runGit(cwd: string, args: string[], env: NodeJS.ProcessEnv): string {
  try {
    return execFileSync("git", args, {
      cwd,
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: Buffer | string; message?: string };
    const stderr = typeof e.stderr === "string" ? e.stderr : e.stderr?.toString("utf8") ?? "";
    // Scrub credentials from BOTH the composed argv and git's own stderr
    // (git echoes the remote URL in many failure messages) before the
    // string reaches a server log. AGT-417.
    const argv = scrubGitUrlCredentials(args.join(" "));
    const cleanStderr = scrubGitUrlCredentials(stderr.trim());
    throw new Error(
      `git ${argv} (cwd=${cwd}) failed: ${scrubGitUrlCredentials(e.message ?? String(err))}${cleanStderr ? `\nstderr: ${cleanStderr}` : ""}`,
    );
  }
}

