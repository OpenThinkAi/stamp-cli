/**
 * SSH session gate for the stamp server (AGT-2265).
 *
 * Every SSH user maps to the one Unix user `git`, and git-shell's built-in
 * `git-upload-pack` / `git-receive-pack` / `git-upload-archive` accept any
 * path the git user can read. Without a gate, any enrolled key — a `member`
 * included — could clone every repo on the server, the soft-deleted repos
 * in /srv/git/.trash (deleted to erase data), and the prompts cache.
 *
 * The AuthorizedKeysCommand resolver now emits every key as
 *
 *   command="stamp-gate <user-id>",restrict <key>
 *
 * so sshd runs the gate for every session, whatever the client asked for.
 * The gate parses SSH_ORIGINAL_COMMAND (this module), applies the access
 * rule, and hands a canonical re-quoted command back to git-shell.
 *
 * Path rule (every role): a git transport verb may only name a live bare
 * repo, `/srv/git/<name>.git` (`/srv/git/<name>` is accepted and
 * canonicalised). Anything else — a dot-dir (.trash, .prompts-cache,
 * .stamp-state, ...), a nested path, `..`, a relative or `~` path — is
 * refused before git sees it.
 *
 * Repo rule (who may use which live repo):
 *   - owner / admin: every live repo.
 *   - member with no repo grants (`stamp users grants`): every live repo.
 *     This is the single-tenant shape AGT-2252 calls "unscoped".
 *   - member with any grant: only repos whose `.stamp/mirror.yml`
 *     `github.repo` (read from the bare repo's HEAD branch) matches one of
 *     their grants. A repo with no readable mirror mapping is refused.
 * The same rule covers reads and pushes; pushes still go through
 * pre-receive and the review gate on top.
 */

import { spawnSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { parse as parseYaml } from "yaml";

/** Where the bare repos live on the server image. */
export const GIT_ROOT = "/srv/git";

/** Same shape new/delete/restore-stamp-repo enforce for repo names. */
export const SERVER_REPO_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

/** git-shell's built-in transport commands. */
export const GIT_SERVICES = ["git-upload-pack", "git-receive-pack", "git-upload-archive"] as const;
export type GitService = (typeof GIT_SERVICES)[number];

/**
 * Who may run a non-git verb at the gate.
 *
 *   - `self`: the verb resolves the caller and enforces its own role rule
 *     (AGT-2259 / AGT-2265 put `stamp-require-role` in the shell verbs; the
 *     Node verbs check in-process). The gate only checks the caller is
 *     enrolled.
 *   - `unscoped`: owner, admin, or a member with no repo grants. Used for
 *     `list-stamp-repos`: an unscoped member can read every live repo, so
 *     the list tells them nothing new; a scoped member would learn the
 *     names of repos they can't read.
 */
export type VerbPolicy = "self" | "unscoped";

/**
 * Every git-shell-commands verb the image installs, and its gate policy.
 * Kept in lockstep with the `ln -s` lines in server/Dockerfile (a unit
 * test diffs the two). A verb missing here is refused, so adding a verb
 * means adding it in both places.
 */
export const VERB_POLICIES: Readonly<Record<string, VerbPolicy>> = {
  "new-stamp-repo": "self",
  "delete-stamp-repo": "self",
  "restore-stamp-repo": "self",
  "list-trash": "self",
  "list-stamp-repos": "unscoped",
  "stamp-server-pubkey": "self",
  "resync-mirror": "self",
  "stamp-mint-invite": "self",
  "stamp-review": "self",
  "purge-trash": "self",
  "stamp-users": "self",
  "stamp-pr-opened": "self",
};

/** GitHub org/repo slug shape for a `.stamp/mirror.yml` `github.repo`. */
const MIRROR_SLUG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/;

/** One line naming what the gate serves, for refusals. */
export const ALLOWED_COMMANDS_HINT =
  `allowed: ${GIT_SERVICES.join(", ")} on ${GIT_ROOT}/<name>.git, or one of ` +
  `${Object.keys(VERB_POLICIES).join(", ")}`;

export type ParsedCommand =
  | { kind: "git"; service: GitService; name: string; repoPath: string }
  | { kind: "verb"; verb: string; args: string[] };

export type ParseResult = { ok: true; cmd: ParsedCommand } | { ok: false; message: string };

/**
 * Split a command line exactly the way git-shell does (git's
 * `split_cmdline`): whitespace separates words; single or double quotes
 * group; a backslash escapes the next character except inside single
 * quotes. Returns null on an unclosed quote or a trailing backslash, which
 * git-shell also rejects.
 *
 * The gate never hands git-shell the client's raw string: it re-emits the
 * words it parsed here with `sqQuote`, so what git-shell runs is exactly
 * what the gate checked.
 */
export function splitCmdline(line: string): string[] | null {
  const out: string[] = [];
  let cur = "";
  let inWord = false;
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quote === null && /\s/.test(c)) {
      if (inWord) {
        out.push(cur);
        cur = "";
        inWord = false;
      }
      continue;
    }
    inWord = true;
    if (quote === null && (c === "'" || c === '"')) {
      quote = c;
    } else if (c === quote) {
      quote = null;
    } else if (c === "\\" && quote !== "'") {
      i++;
      if (i >= line.length) return null;
      cur += line[i]!;
    } else {
      cur += c;
    }
  }
  if (quote !== null) return null;
  if (inWord) out.push(cur);
  return out;
}

/** Single-quote one word for git-shell (`'` becomes `'\''`). */
export function sqQuote(word: string): string {
  return `'${word.replace(/'/g, `'\\''`)}'`;
}

/**
 * Resolve the path a git transport verb names to a live bare repo name.
 * Accepts `/srv/git/<name>.git` and `/srv/git/<name>` only, with an
 * optional trailing slash. Returns the bare name (no `.git`) or null.
 */
export function repoNameFromPath(path: string): string | null {
  const prefix = `${GIT_ROOT}/`;
  if (!path.startsWith(prefix)) return null;
  let rest = path.slice(prefix.length);
  if (rest.endsWith("/")) rest = rest.slice(0, -1);
  if (rest.endsWith(".git")) rest = rest.slice(0, -".git".length);
  // The regex already refuses '/', a leading '.', '-' and whitespace;
  // '..' inside a name is refused explicitly, same as the shell verbs.
  if (!SERVER_REPO_NAME_RE.test(rest) || rest.includes("..")) return null;
  return rest;
}

/**
 * Parse SSH_ORIGINAL_COMMAND. Shape errors only; access is decided by the
 * caller. Messages are client-facing.
 */
export function parseOriginalCommand(original: string | undefined): ParseResult {
  if (original === undefined || original.trim() === "") {
    return {
      ok: false,
      message:
        "interactive sessions are not available on this server; run a git command or a stamp verb (see server/README.md).",
    };
  }
  // Refuse control characters outright (newlines included). git-shell's
  // split would treat a newline as whitespace; nothing legitimate sends one.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(original)) {
    return { ok: false, message: "command contains control characters; refused." };
  }
  const words = splitCmdline(original);
  if (!words || words.length === 0) {
    return { ok: false, message: "could not parse the command (unbalanced quote or trailing backslash)." };
  }
  let head = words[0]!;
  let args = words.slice(1);
  // git-shell rewrites "git upload-pack ..." to "git-upload-pack ...".
  if (head === "git" && args.length > 0) {
    head = `git-${args[0]!}`;
    args = args.slice(1);
  }
  if ((GIT_SERVICES as readonly string[]).includes(head)) {
    if (args.length !== 1) {
      return { ok: false, message: `${head} takes exactly one repository path.` };
    }
    const name = repoNameFromPath(args[0]!);
    if (name === null) {
      return {
        ok: false,
        message:
          `repository path '${args[0]!}' is not allowed: only live repos at ` +
          `${GIT_ROOT}/<name>.git are served (e.g. git@<host>:${GIT_ROOT}/<name>.git).`,
      };
    }
    return {
      ok: true,
      cmd: { kind: "git", service: head as GitService, name, repoPath: `${GIT_ROOT}/${name}.git` },
    };
  }
  if (Object.prototype.hasOwnProperty.call(VERB_POLICIES, head)) {
    return { ok: true, cmd: { kind: "verb", verb: head, args } };
  }
  // Echo a bounded, printable form of the verb only.
  const shown = head.length > 64 ? `${head.slice(0, 64)}...` : head;
  return { ok: false, message: `unrecognized command '${shown}'; ${ALLOWED_COMMANDS_HINT}.` };
}

/** The command line the gate hands to `git-shell -c`. */
export function canonicalCommand(cmd: ParsedCommand): string {
  if (cmd.kind === "git") return `${cmd.service} ${sqQuote(cmd.repoPath)}`;
  return [cmd.verb, ...cmd.args.map(sqQuote)].join(" ");
}

/**
 * True when `repoPath` is a real directory (not a symlink, and no symlinked
 * component), so the name the gate checked is the repo git opens.
 */
export function isLiveBareRepo(repoPath: string): boolean {
  try {
    const st = lstatSync(repoPath);
    if (!st.isDirectory()) return false;
    return realpathSync(repoPath) === repoPath;
  } catch {
    return false;
  }
}

/**
 * The GitHub `<owner>/<repo>` a server repo mirrors to, from
 * `.stamp/mirror.yml` (`github.repo`) on the bare repo's HEAD branch.
 * That branch is stamp-protected, so the mapping only changes through a
 * reviewed, signed merge. Returns null when there is no readable mapping.
 */
export function readServerRepoMapping(repoPath: string): { org: string; repo: string } | null {
  const res = spawnSync("git", ["--git-dir", repoPath, "show", "HEAD:.stamp/mirror.yml"], {
    encoding: "utf8",
    timeout: 5000,
    stdio: ["ignore", "pipe", "ignore"],
    env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", HOME: "/nonexistent" },
  });
  if (res.status !== 0 || typeof res.stdout !== "string") return null;
  try {
    const parsed = parseYaml(res.stdout) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const gh = (parsed as Record<string, unknown>)["github"];
    if (!gh || typeof gh !== "object" || Array.isArray(gh)) return null;
    const spec = (gh as Record<string, unknown>)["repo"];
    if (typeof spec !== "string") return null;
    const parts = spec.split("/");
    if (parts.length !== 2) return null;
    const [org, repo] = parts as [string, string];
    if (!MIRROR_SLUG_RE.test(org) || !MIRROR_SLUG_RE.test(repo)) return null;
    return { org: org.toLowerCase(), repo: repo.toLowerCase() };
  } catch {
    return null;
  }
}

export type GateDecision = { ok: true } | { ok: false; message: string };

/** The parts of the caller and its grants the repo rule needs. */
export interface GateCaller {
  role: "owner" | "admin" | "member";
  /** The caller's `user_repo_grants` rows (lowercased; repo may be `*`). */
  grants: ReadonlyArray<{ org: string; repo: string }>;
}

/** Owner, admin, or a member with no grants (AGT-2252's "unscoped"). */
export function isUnscoped(caller: GateCaller): boolean {
  return caller.role === "owner" || caller.role === "admin" || caller.grants.length === 0;
}

/**
 * Apply the repo rule (module header) to a live repo. `mapping` is called
 * only for a scoped member, so the common paths never spawn git.
 */
export function decideRepoAccess(
  caller: GateCaller,
  name: string,
  mapping: () => { org: string; repo: string } | null,
): GateDecision {
  if (isUnscoped(caller)) return { ok: true };
  const m = mapping();
  const denied: GateDecision = {
    ok: false,
    message:
      `repository '${name}' not found or not permitted. Your repo grants don't cover it; ` +
      `ask an owner or admin to run 'stamp users grant <you> --repo <org>/<repo>'.`,
  };
  if (!m) return denied;
  const hit = caller.grants.some((g) => g.org === m.org && (g.repo === "*" || g.repo === m.repo));
  return hit ? { ok: true } : denied;
}

/** Apply a verb's gate policy. */
export function decideVerbAccess(caller: GateCaller, verb: string): GateDecision {
  if (!Object.prototype.hasOwnProperty.call(VERB_POLICIES, verb)) {
    return { ok: false, message: `unrecognized command '${verb}'; ${ALLOWED_COMMANDS_HINT}.` };
  }
  const policy = VERB_POLICIES[verb];
  if (policy === "self") return { ok: true };
  if (policy === "unscoped" && isUnscoped(caller)) return { ok: true };
  return {
    ok: false,
    message:
      `role ${caller.role} with repo grants is not permitted to run ${verb}; ` +
      `'stamp users grants <you>' lists the repos you can use.`,
  };
}
