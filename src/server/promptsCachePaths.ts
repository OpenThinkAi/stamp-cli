/**
 * Where the Phase B prompts cache and its deploy key live (AGT-2277).
 *
 * Three processes need the same answers: the boot-time
 * `stamp-prompts-cache-bootstrap`, the `stamp-workers` refresh (poll +
 * webhook trigger), and the `stamp-review` SSH verb that reads the cached
 * prompts. Each used to carry its own copy, and they drifted: the verb
 * hardcoded the default cache root (ignoring STAMP_PROMPTS_CACHE_ROOT), and
 * only the workers fell back to the default deploy key. One module now.
 *
 * No imports from the rest of src/server, so it can be pulled in by
 * prompts-cache.ts's import cycle (promptFetch ↔ prompts-cache) without
 * load-order surprises.
 */

import { existsSync } from "node:fs";

/** Default cache root, on the persistent volume. A dot-dir under /srv/git,
 *  so the SSH gate (AGT-2265) never serves it as a repo; the entrypoint
 *  refuses a STAMP_PROMPTS_CACHE_ROOT that isn't one. */
export const DEFAULT_PROMPTS_CACHE_ROOT = "/srv/git/.prompts-cache";

/** Default prompts deploy key, next to the mirror key in the root:git
 *  `.ssh-client-keys` dir (AGT-375). */
export const DEFAULT_PROMPTS_DEPLOY_KEY_PATH = "/srv/git/.ssh-client-keys/prompts_repo_key";

/** STAMP_PROMPTS_CACHE_ROOT, else the default. Empty counts as unset. */
export function resolvePromptsCacheRoot(env: NodeJS.ProcessEnv = process.env): string {
  return env["STAMP_PROMPTS_CACHE_ROOT"] || DEFAULT_PROMPTS_CACHE_ROOT;
}

/**
 * STAMP_PROMPTS_DEPLOY_KEY_PATH, else the default path only if a key is
 * actually there, else undefined (no key: HTTPS / file:// URLs). The cache
 * module throws on a named key that doesn't exist, so the default is never
 * passed blind — that broke every keyless deployment's refresh before
 * AGT-2264. Boot and runtime both resolve through here.
 */
export function resolvePromptsDeployKeyPath(
  env: NodeJS.ProcessEnv = process.env,
  defaultPath: string = DEFAULT_PROMPTS_DEPLOY_KEY_PATH,
): string | undefined {
  const explicit = env["STAMP_PROMPTS_DEPLOY_KEY_PATH"];
  if (explicit) return explicit;
  return existsSync(defaultPath) ? defaultPath : undefined;
}
