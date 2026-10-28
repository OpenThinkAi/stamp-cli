/**
 * AGT-2240 — bind a peer-review `pr_url` to the payload's authorized `repo`.
 *
 * Peer-review events carry both a `repo` (`<owner>/<name>`, the repo whose
 * manifest authorizes the PR author) and a `pr_url` (what the listener hands
 * to `gh pr diff` / `gh pr review` under the reviewer's own GitHub token).
 * If the two are not bound together, an operator trusted in repo X can sign
 * an event with `repo: X` and `pr_url: <a PR in repo Y>`, and the reviewer's
 * listener would review — and auto-post on — Y under the reviewer's identity
 * (a confused deputy on the reviewer's GitHub credential).
 *
 * The check is applied twice: by the server (`stamp-pr-opened`) before it
 * persists and fans out the event, and by the listener (`stamp pr listen`)
 * before it calls `gh`. The listener check is the one that protects the
 * reviewer; the server check stops bad events at the broker.
 */

/** The only PR host peer reviews post to. */
export const PEER_PR_HOST = "github.com";

export interface ParsedPrUrl {
  owner: string;
  repo: string;
  number: number;
}

/**
 * GitHub owner/repo segment charset. Matches the `repo` format check in
 * `stamp-pr-opened` (alphanumeric, dash, dot, underscore).
 */
const SEGMENT = "[A-Za-z0-9_.-]+";
const PR_URL_RE = new RegExp(
  `^https://([A-Za-z0-9.-]+)/(${SEGMENT})/(${SEGMENT})/pull/([1-9][0-9]{0,9})$`,
);

/**
 * Parse a `https://github.com/<owner>/<repo>/pull/<n>` URL. Returns null for
 * anything else: another host, userinfo/port, query/fragment, trailing path,
 * flag-shaped strings, or `.`/`..` segments.
 */
export function parseGithubPrUrl(url: string): ParsedPrUrl | null {
  const m = PR_URL_RE.exec(url);
  if (!m) return null;
  const [, host, owner, repo, num] = m;
  if (host!.toLowerCase() !== PEER_PR_HOST) return null;
  if (owner === "." || owner === ".." || repo === "." || repo === "..") return null;
  return { owner: owner!, repo: repo!, number: Number(num) };
}

export type PrUrlBindingResult =
  | { ok: true; parsed: ParsedPrUrl }
  | { ok: false; reason: string };

/**
 * Verify `prUrl` is a github.com PR URL whose owner/repo equals `repo`
 * (`<owner>/<name>`). GitHub owner and repo names are case-insensitive, so
 * the comparison is too.
 */
export function checkPrUrlBinding(prUrl: string, repo: string): PrUrlBindingResult {
  const parsed = parseGithubPrUrl(prUrl);
  if (!parsed) {
    return {
      ok: false,
      reason:
        `pr_url ${JSON.stringify(prUrl)} is not a https://${PEER_PR_HOST}/<owner>/<repo>/pull/<n> URL`,
    };
  }
  const want = repo.toLowerCase();
  const got = `${parsed.owner}/${parsed.repo}`.toLowerCase();
  if (got !== want) {
    return {
      ok: false,
      reason:
        `pr_url ${JSON.stringify(prUrl)} points at ${parsed.owner}/${parsed.repo}, ` +
        `not the authorized repo ${JSON.stringify(repo)}`,
    };
  }
  return { ok: true, parsed };
}
