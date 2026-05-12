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
 * principal is allowed past the rules." Three shapes:
 *
 *   - { type: "User", id: <numeric> } — works on personal repos. The
 *     gh-authenticated user is the typical id.
 *   - { type: "OrganizationAdmin", id: 1 } — magic constant 1 means "any
 *     org admin." Works on org-owned repos; "User" doesn't.
 *   - { type: "DeployKey", id: <numeric> } — a write-enabled SSH deploy
 *     key registered on the repo. Survives the "no machine-user account,
 *     no GitHub App approval" constraint common at locked-down orgs:
 *     deploy keys are per-repo resources and don't touch org-level
 *     third-party-application policy. The id is the numeric key id from
 *     GET /repos/:o/:r/keys, NOT the user/app id.
 *
 * Future shapes (Integration / Team) can be added without changing call
 * sites — buildRulesetPayload passes actor.type / actor.id through
 * generically.
 */
export type BypassActor =
  | { type: "User"; id: number }
  | { type: "OrganizationAdmin"; id: 1 }
  | { type: "DeployKey"; id: number };

/**
 * Parse a github.com origin URL into { owner, repo }. Two distinct shapes
 * git supports for github are matched independently so an attacker can't
 * smuggle "github.com/<owner>/<repo>" through the path or userinfo of a
 * non-github URL:
 *
 *   - scp-style: anchored `^<user>@github.com:<owner>/<repo>[.git]?$`
 *   - url-style: parsed via `new URL()`, then host-component equality
 *     against "github.com" (not substring) and an explicit empty-port
 *     check (preserves the documented `ssh://git@github.com:22/...`
 *     limitation — see tests/validators.test.ts).
 *
 * Repo names with dots or dashes (`has.dots`, `foo-bar`) parse correctly;
 * the non-greedy repo segment plus optional `\.git$` suffix handles the
 * 0.7.1 dotted-repo bug. Returns null on any non-github URL or on URLs
 * whose host merely contains "github.com" as a substring.
 */
export function parseGithubOriginUrl(
  url: string,
): { owner: string; repo: string } | null {
  const scp = url.match(
    /^[A-Za-z0-9._-]+@github\.com:([^/]+)\/([^/]+?)(?:\.git)?$/,
  );
  if (scp && scp[1] && scp[2]) {
    return { owner: scp[1], repo: scp[2] };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.hostname.toLowerCase() !== "github.com") return null;
  if (
    parsed.protocol !== "https:" &&
    parsed.protocol !== "http:" &&
    parsed.protocol !== "ssh:" &&
    parsed.protocol !== "git:"
  ) {
    return null;
  }
  if (parsed.port !== "") return null;

  const path = parsed.pathname.replace(/^\//, "");
  const m = path.match(/^([^/]+)\/([^/]+?)(?:\.git)?$/);
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

/**
 * Find the numeric id of a deploy key on the given repo, matched by
 * title. Used for idempotent deploy-key registration: stamp picks a
 * stable title (e.g. "stamp-mirror") and re-uses any existing key
 * rather than creating duplicates on re-runs.
 *
 * Returns the key's id, or null if no key with that title exists or the
 * gh call fails. Caller decides whether absence vs. failure matters —
 * the typical caller (registerDeployKey) treats them the same and falls
 * through to POST.
 */
export function findDeployKey(
  owner: string,
  repo: string,
  title: string,
): number | null {
  const r = spawnSync(
    "gh",
    [
      "api",
      `/repos/${owner}/${repo}/keys`,
      "--jq",
      // JSON.stringify produces a valid jq string literal (double-quoted,
      // with backslash/quote escapes), so a title containing quotes or
      // backslashes can't break the jq filter or smuggle a different
      // selector.
      `[.[] | select(.title == ${JSON.stringify(title)})][0].id // empty`,
    ],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) return null;
  const trimmed = r.stdout.trim();
  if (!trimmed) return null;
  const id = Number(trimmed);
  return Number.isFinite(id) ? id : null;
}

export interface RegisterDeployKeyResult {
  /** "created" — newly POSTed; "exists" — already present, no change; "failed" — gh api error. */
  status: "created" | "exists" | "failed";
  /** When status === "failed", the error/stderr from gh. */
  error?: string;
  /** When status !== "failed", the (created or existing) deploy-key id. */
  keyId?: number;
}

/**
 * Register a write-enabled SSH deploy key on the given repo. Idempotent:
 * if a deploy key with the same `title` already exists, returns "exists"
 * without re-posting (operator may have customized the underlying key
 * but kept the title; we don't clobber).
 *
 * `publicKey` must be a full OpenSSH-format public-key line (e.g.
 * "ssh-ed25519 AAAA... stamp@<server>"). GitHub rejects malformed keys
 * with HTTP 422; the rejection surfaces via `status: "failed"` and the
 * `error` field carries gh's stderr.
 *
 * `read_only: false` is required: a deploy key referenced as a Ruleset
 * `DeployKey` bypass actor has to be able to update protected branches,
 * which the read-only flag forbids.
 */
export function registerDeployKey(
  owner: string,
  repo: string,
  title: string,
  publicKey: string,
): RegisterDeployKeyResult {
  const existing = findDeployKey(owner, repo, title);
  if (existing !== null) {
    return { status: "exists", keyId: existing };
  }
  const body = { title, key: publicKey, read_only: false };
  const r = spawnSync(
    "gh",
    [
      "api",
      "-X",
      "POST",
      `/repos/${owner}/${repo}/keys`,
      "--input",
      "-",
    ],
    {
      input: JSON.stringify(body),
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
    return { status: "created", keyId: created.id };
  } catch {
    // POST succeeded; just couldn't parse the response body. Treat as success.
    return { status: "created" };
  }
}
