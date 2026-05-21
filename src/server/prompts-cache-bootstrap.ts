/**
 * Boot-time entrypoint: populate the prompts cache by calling
 * `cloneOrFetchPromptsCache` exactly once before stamp-server starts
 * accepting traffic. Phase B of the external-prompts-via-webhook
 * initiative (AGT-375). Runs from `server/entrypoint.sh` as root, after
 * `stamp-bootstrap-review-key`, before the HTTP listener launches.
 *
 * Gating:
 *   - `STAMP_PROMPTS_REPO_URL` unset → no-op, exit 0. Phase A path
 *     (bundled prompts at `/etc/stamp/reviewers/`) remains in effect.
 *     The entrypoint must call us unconditionally; we decide whether
 *     there's work to do.
 *   - `STAMP_PROMPTS_REPO_URL` set → resolve the cache root, invoke
 *     `cloneOrFetchPromptsCache`, log the resulting SHA + file
 *     inventory, exit 0 on success.
 *
 * Env-var contract:
 *
 *   - `STAMP_PROMPTS_REPO_URL` (required when populating cache):
 *     HTTPS or SSH git URL of the prompts repo.
 *   - `STAMP_PROMPTS_REPO_REF` (optional, default `main`): branch or
 *     tag to track.
 *   - `STAMP_PROMPTS_CACHE_ROOT` (optional, default
 *     `/srv/git/.prompts-cache`): absolute directory path. The parent
 *     must exist and be writable; the cache dir itself is created by
 *     `cloneOrFetchPromptsCache`. Override in tests.
 *   - `STAMP_PROMPTS_DEPLOY_KEY_PATH` (optional): private SSH key for
 *     SSH URLs. The entrypoint pre-checks existence with a clearer
 *     error before invoking us (AC #2 of AGT-375); we re-pass the
 *     value to the module so its own `buildGitEnv` check stays in the
 *     loop as defense-in-depth. For HTTPS URLs the module silently
 *     ignores this — see `prompts-cache.ts` module header.
 *
 * Output streams: progress + success lines go to stderr (matching
 * `entrypoint.sh`'s convention — its other log lines all redirect to
 * `>&2` so container logs interleave cleanly with sshd). Errors carry
 * the lowercase `error: ` prefix, also to stderr. Exit codes: 0 on
 * success or no-op; 1 on any populate failure (operator must fix
 * synchronously — no fallback to a partial cache).
 *
 * Why a dedicated bootstrap script vs `node -e "..."` from bash:
 * cleaner shell quoting (especially the deploy-key path), the
 * existing `stamp-bootstrap-review-key` shape already exists alongside,
 * and adding a one-off `node -e` would bury logic in `entrypoint.sh`
 * where it can't be type-checked.
 */

import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import {
  cloneOrFetchPromptsCache,
  type RefreshResult,
} from "./prompts-cache.js";

// ─── Constants ────────────────────────────────────────────────────────

/**
 * Default cache root when `STAMP_PROMPTS_CACHE_ROOT` is unset. Matches
 * the path named in the project README:
 * `<vault>/projects/external-prompt-storage-via-webhook/README.md`.
 * The stamp-server image's persistent volume is mounted at `/srv/git`,
 * so the cache lives there for the same survival-across-redeploy
 * reason as `.ssh-host-keys` and `.stamp-state`.
 */
const DEFAULT_CACHE_ROOT = "/srv/git/.prompts-cache";

/**
 * Default ref to track when `STAMP_PROMPTS_REPO_REF` is unset. Project
 * convention; documented in the operator-setup README section.
 */
const DEFAULT_REF = "main";

// ─── Entry point ──────────────────────────────────────────────────────

async function main(): Promise<void> {
  const repoUrl = process.env["STAMP_PROMPTS_REPO_URL"];

  if (!repoUrl) {
    // Phase A path. Stay silent — the inventory of bundled prompts at
    // /etc/stamp/reviewers/ is logged separately by entrypoint.sh, so
    // a second "no external prompts repo configured" line here would
    // be noise on every boot of every deployment that hasn't migrated.
    return;
  }

  const ref = process.env["STAMP_PROMPTS_REPO_REF"] || DEFAULT_REF;
  const cacheRoot = process.env["STAMP_PROMPTS_CACHE_ROOT"] || DEFAULT_CACHE_ROOT;
  const deployKeyPath = process.env["STAMP_PROMPTS_DEPLOY_KEY_PATH"] || undefined;

  // Pre-flight log: surface what we're about to do before the git
  // network round-trip. Operators debugging a slow boot will see this
  // line first and know which env vars resolved to what.
  process.stderr.write(
    `prompts-cache: populating cache at ${cacheRoot} from ${repoUrl}@${ref}` +
      (deployKeyPath ? ` (deploy key: ${deployKeyPath})` : "") +
      "\n",
  );

  let result: RefreshResult;
  try {
    result = await cloneOrFetchPromptsCache({
      url: repoUrl,
      ref,
      cacheRoot,
      deployKeyPath,
    });
  } catch (err) {
    // The module throws on any condition the operator must fix
    // synchronously — missing deploy key, unreachable remote,
    // unresolvable ref, etc. Surface verbatim with the `error: `
    // prefix and exit non-zero. entrypoint.sh's `set -e` then aborts
    // the boot before sshd or the HTTP listener launch.
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: prompts-cache populate failed: ${message}\n`);
    process.exit(1);
  }

  // Inventory log: cache root path + commit SHA + ls of *.md files.
  // The reviewer-prompt inventory shipped by Phase A uses
  // `xargs -n1 basename | paste -sd ','` to render a comma-list on one
  // line; we match that shape so operator log-greps stay uniform across
  // both prompt sources. Failure to enumerate (race with a concurrent
  // refresh wiping the dir, or a perms drift) is best-effort: we still
  // log the SHA so the populate-succeeded signal isn't lost.
  let inventory = "<inventory unavailable>";
  try {
    if (existsSync(cacheRoot) && statSync(cacheRoot).isDirectory()) {
      const entries = readdirSync(cacheRoot)
        .filter((name) => name.endsWith(".md"))
        .filter((name) => {
          // Hide directory entries that happen to end in .md (unlikely
          // but defensive — readdirSync's withFileTypes path would also
          // work, kept inline for the same simple style as the
          // entrypoint.sh inventory line).
          try {
            return statSync(join(cacheRoot, name)).isFile();
          } catch {
            return false;
          }
        })
        .sort();
      inventory = entries.length > 0 ? entries.join(",") : "<none>";
    }
  } catch (err) {
    // Non-fatal: the populate succeeded, just couldn't enumerate.
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`prompts-cache: inventory enumeration failed: ${message}\n`);
  }

  process.stderr.write(
    `prompts-cache: ready (cacheRoot=${cacheRoot} sha=${result.commitSha} files=${inventory})\n`,
  );
}

main().catch((err: unknown) => {
  // Safety net — any synchronous throw before the try/catch (e.g. a
  // bad URL shape rejected by validateOpts before the async work
  // starts) bubbles here. Mirror the same `error: ` shape.
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`error: prompts-cache bootstrap crashed: ${message}\n`);
  process.exit(1);
});
