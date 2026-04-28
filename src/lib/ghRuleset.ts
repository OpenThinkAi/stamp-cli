/**
 * Programmatic application of the GitHub Ruleset that locks down a
 * stamp-protected mirror repo. Mirrors what `docs/github-ruleset-template.json`
 * + `docs/github-ruleset-setup.md` describe, but executes via `gh api` so
 * `stamp init` can do it inline rather than asking the operator to do it
 * after the fact.
 *
 * Triggered by `stamp init` when:
 *   - origin is forge-direct and the host is github.com (classifyRemote)
 *   - `gh` is installed and authenticated
 *   - --no-gh-protect was not passed
 *
 * The bypass actor is the gh-authenticated user — the same identity that
 * will be doing the mirror push. For a more locked-down setup (machine user
 * or GitHub App), the operator follows docs/github-ruleset-setup.md by hand.
 */

import { spawnSync } from "node:child_process";

export interface GhAvailability {
  available: boolean;
  /** Diagnostic if not available (e.g. "gh not on PATH", "gh not authenticated"). */
  reason?: string;
}

export function checkGhAvailable(): GhAvailability {
  // First: is gh on PATH at all?
  const v = spawnSync("gh", ["--version"], {
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  if (v.error || v.status !== 0) {
    return { available: false, reason: "`gh` is not installed or not on PATH" };
  }
  // Second: is it authenticated to github.com?
  const auth = spawnSync("gh", ["auth", "status", "--hostname", "github.com"], {
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  if (auth.status !== 0) {
    return { available: false, reason: "`gh` is not authenticated for github.com (run `gh auth login`)" };
  }
  return { available: true };
}

/**
 * Look up the numeric GitHub user-ID of the currently-authenticated `gh`
 * user. Returns null on failure; caller decides whether to surface or skip.
 */
export function lookupAuthenticatedUserId(): { id: number; login: string } | null {
  const r = spawnSync("gh", ["api", "/user", "--jq", "{id, login}"], {
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  if (r.status !== 0) return null;
  try {
    const obj = JSON.parse(r.stdout) as { id: number; login: string };
    if (typeof obj.id !== "number" || typeof obj.login !== "string") return null;
    return obj;
  } catch {
    return null;
  }
}

/**
 * Look up the owner type of a github.com repo: "User" (personal account)
 * or "Organization" (org-owned). Returns null on lookup failure.
 *
 * The owner type drives which bypass actor type the Ruleset gets:
 *   - User-owned repos use actor_type="User" (the operator).
 *   - Org-owned repos use actor_type="OrganizationAdmin" — GitHub's
 *     Ruleset evaluator silently ignores actor_type="User" on org repos
 *     (the bypass entry exists in the API response but doesn't actually
 *     bypass anything), so we have to pick a type the evaluator honors.
 */
export function lookupRepoOwnerType(
  owner: string,
  repo: string,
): "User" | "Organization" | null {
  const r = spawnSync(
    "gh",
    ["api", `/repos/${owner}/${repo}`, "--jq", ".owner.type"],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) return null;
  const t = r.stdout.trim();
  if (t === "User" || t === "Organization") return t;
  return null;
}

/**
 * Bypass actor descriptor — the part of the Ruleset that says "this
 * principal is allowed past the rules." Two shapes for now:
 *
 *   - { type: "User", id: <numeric> } — works on personal repos. The
 *     gh-authenticated user is the typical id.
 *   - { type: "OrganizationAdmin", id: 1 } — magic constant 1 means "any
 *     org admin." Works on org-owned repos; "User" doesn't.
 *
 * Future shapes (Integration / Team / DeployKey) can be added without
 * changing call sites.
 */
export type BypassActor =
  | { type: "User"; id: number }
  | { type: "OrganizationAdmin"; id: 1 };

/**
 * Parse a github.com origin URL into { owner, repo }. The single regex
 * matches all the URL shapes git supports for github (ssh://, scp-style
 * git@host:path, https://) via the `[:/]` character class. The non-greedy
 * repo segment plus the optional `\.git$` suffix correctly handles repos
 * with dots in their names (e.g. `has.dots.git` → repo = `has.dots`,
 * `has.dots` (no .git) → `has.dots`, `repo.git` → `repo`). Returns null
 * on a non-github URL.
 */
export function parseGithubOriginUrl(
  url: string,
): { owner: string; repo: string } | null {
  const m = url.match(/github\.com[:/]([^/]+)\/([^/]+?)(?:\.git)?$/);
  return m && m[1] && m[2] ? { owner: m[1], repo: m[2] } : null;
}

/**
 * Build the ruleset JSON payload for stamp's mirror-only protection.
 * Same structure as docs/github-ruleset-template.json but with the bypass
 * actor populated. `required_linear_history` is deliberately omitted —
 * stamp's --no-ff merge commits would be rejected by it.
 */
export function buildRulesetPayload(actor: BypassActor): unknown {
  return {
    name: "stamp-mirror-only",
    target: "branch",
    enforcement: "active",
    conditions: {
      ref_name: {
        exclude: [],
        include: ["~DEFAULT_BRANCH"],
      },
    },
    rules: [
      { type: "deletion" },
      { type: "non_fast_forward" },
      { type: "update" },
    ],
    bypass_actors: [
      {
        actor_id: actor.id,
        actor_type: actor.type,
        bypass_mode: "always",
      },
    ],
  };
}

/**
 * Check whether a ruleset named `stamp-mirror-only` already exists on the
 * repo. Used to avoid duplicate-creating on re-runs of stamp init. Returns
 * the existing ruleset's id, or null if absent.
 */
export function findExistingStampRuleset(
  owner: string,
  repo: string,
): number | null {
  const r = spawnSync(
    "gh",
    [
      "api",
      `/repos/${owner}/${repo}/rulesets`,
      "--jq",
      '[.[] | select(.name == "stamp-mirror-only")][0].id // empty',
    ],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) return null;
  const trimmed = r.stdout.trim();
  if (!trimmed) return null;
  const id = Number(trimmed);
  return Number.isFinite(id) ? id : null;
}

export interface ApplyRulesetResult {
  /** "created" — newly POSTed; "exists" — already present, no change; "failed" — gh api error. */
  status: "created" | "exists" | "failed";
  /** When status === "failed", the error/stderr from gh. */
  error?: string;
  /** When status !== "failed", the (created or existing) ruleset id. */
  rulesetId?: number;
}

/**
 * Apply (POST) the stamp-mirror-only ruleset to the given repo. Idempotent:
 * if a ruleset by this name already exists, returns "exists" without
 * touching it (operator may have customized it; we don't clobber).
 */
export function applyStampRuleset(
  owner: string,
  repo: string,
  actor: BypassActor,
): ApplyRulesetResult {
  const existing = findExistingStampRuleset(owner, repo);
  if (existing !== null) {
    return { status: "exists", rulesetId: existing };
  }
  const payload = buildRulesetPayload(actor);
  const r = spawnSync(
    "gh",
    [
      "api",
      "-X",
      "POST",
      `/repos/${owner}/${repo}/rulesets`,
      "--input",
      "-",
    ],
    {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      encoding: "utf8",
    },
  );
  if (r.status !== 0) {
    const stderr = (r.stderr ?? "").trim();
    const stdout = (r.stdout ?? "").trim();
    return {
      status: "failed",
      error: stderr || stdout || `gh api exited ${r.status}`,
    };
  }
  try {
    const created = JSON.parse(r.stdout) as { id?: number };
    return { status: "created", rulesetId: created.id };
  } catch {
    // POST succeeded; just couldn't parse the response body. Treat as success.
    return { status: "created" };
  }
}
