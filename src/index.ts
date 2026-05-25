process.removeAllListeners("warning");
process.on("warning", (warn) => {
  if (
    warn.name === "ExperimentalWarning" &&
    /SQLite/i.test(warn.message)
  ) {
    return;
  }
  console.warn(warn);
});

import { Command } from "commander";
import { runBootstrap } from "./commands/bootstrap.js";
import { runInit, removedPrModeNotice } from "./commands/init.js";
import { runMigrateToServerAttested } from "./commands/migrateServerAttested.js";
import {
  runInvitesAccept,
  runInvitesMint,
  type InviteRole,
} from "./commands/invites.js";
import { runProvision } from "./commands/provision.js";
import { runTrustGrant } from "./commands/trust.js";
import {
  runUsersDemote,
  runUsersList,
  runUsersPromote,
  runUsersRemove,
  runUsersSetName,
  runUsersPrune,
} from "./commands/users.js";
import {
  runServerRepoDelete,
  runServerRepoList,
  runServerRepoPurge,
  runServerRepoRestore,
} from "./commands/serverRepo.js";
import {
  keysExport,
  keysGenerate,
  keysList,
  keysTrust,
} from "./commands/keys.js";
import { runAdminSign } from "./commands/adminSign.js";
import {
  runAdminAddKey,
  runAdminListKeys,
  runAdminRevoke,
} from "./commands/adminRotate.js";
import { runLog } from "./commands/log.js";
import { runAttest } from "./commands/attest.js";
import { runMerge } from "./commands/merge.js";
import { runPrOpen } from "./commands/prOpen.js";
import { runPrListen } from "./commands/prListen.js";
import { runPrPing } from "./commands/prPing.js";
import { runPeerTest } from "./commands/peerTest.js";
import { runPrune } from "./commands/prune.js";
import { runPush } from "./commands/push.js";
import { runReview } from "./commands/review.js";
import { runServerConfig, runServerPubkey } from "./commands/server.js";
import {
  runConfigReviewersClear,
  runConfigReviewersSet,
  runConfigReviewersShow,
} from "./commands/config.js";
import {
  reviewersAdd,
  reviewersEdit,
  reviewersFetch,
  reviewersList,
  reviewersRemove,
  reviewersShow,
  reviewersTest,
  reviewersVerify,
} from "./commands/reviewers.js";
import { runStatus } from "./commands/status.js";
import { runUpdate } from "./commands/update.js";
import { runVerify } from "./commands/verify.js";
import { runVerifyPr } from "./commands/verifyPr.js";
import { readPackageVersion } from "./lib/version.js";

const program = new Command();

program
  .name("stamp")
  .description(
    "Local, headless pull-request system for agent-to-agent code review.",
  )
  .version(readPackageVersion());

program
  .command("init")
  .description(
    "scaffold .stamp/ (three-persona starter: security/standards/product), generate a keypair, and ensure AGENTS.md guidance",
  )
  .option(
    "--minimal",
    "scaffold a single placeholder reviewer instead of the three-persona starter",
  )
  .option(
    "--no-agents-md",
    "skip creating or updating AGENTS.md at the repo root",
  )
  .option(
    "--no-claude-md",
    "skip creating or updating CLAUDE.md at the repo root (CLAUDE.md is auto-loaded by Claude Code)",
  )
  .option(
    "--no-bootstrap-commit",
    "skip the auto bootstrap commit (which adds .stamp/ + AGENTS.md + CLAUDE.md to a fresh repo and pushes)",
  )
  .option(
    "--no-gh-protect",
    "skip auto-applying the GitHub Ruleset to lock the mirror repo (forge-direct github.com origins only; requires `gh`)",
  )
  .option(
    "--mode <mode>",
    "deployment mode: 'server-gated' (origin is a stamp server, gate is enforced) or 'local-only' (no server, advisory). Auto-detected from the configured remote if omitted.",
  )
  .option(
    "--remote <name>",
    "remote name to inspect for deployment-shape detection (default: origin)",
    "origin",
  )
  .option(
    "--no-oteam",
    "bypass the oteam-detection prompt that offers to fill stamp.host in ~/.open-team/config.json",
  )
  .option(
    "--no-pr-check",
    "skip dropping .github/workflows/stamp-verify.yml (PR-check mode workflow). Default behaviour: write the workflow for forge-direct + local-only modes, skip for server-gated.",
  )
  .option(
    "--migrate-to-server-attested",
    "scaffold the complete Shape 4 setup for an existing stamp 1.x repo (one PR): writes .stamp/trusted-keys/manifest.yml + new server pubkey + .github/workflows/stamp-verify.yml, adds review_server to the default branch, rewrites reviewer entries to {} (Shape 4 server-bundled prompt form), smart-defaults path_rules minimum_signatures based on admin count, and deletes .stamp/reviewers/*.md. Output passes `stamp attest --migrate-existing` cleanly. See docs/migration-1.x-to-2.x.md.",
  )
  .option(
    "--server <host:port>",
    "with --migrate-to-server-attested: stamp server endpoint to fetch the review-signing pubkey from. Falls back to ~/.stamp/server.yml. No-op outside the migration path.",
  )
  .option(
    "--dry-run",
    "with --migrate-to-server-attested: print proposed changes without writing them or fetching the server pubkey. No-op outside the migration path.",
  )
  .option(
    "--admin-keys <fingerprints>",
    "with --migrate-to-server-attested: comma-separated sha256:<64hex> fingerprints of the detected keys to promote to the [admin] capability. Required in non-interactive contexts (CI, agent runs). Takes precedence over the interactive prompt; refuses unknown fingerprints with the available set in the error.",
  )
  .option(
    "--action-source <org/repo>",
    "GitHub repo that hosts the stamp/verify-attestation action used by .github/workflows/stamp-verify.yml. Default 'OpenThinkAi/stamp-cli'. Override when consuming a fork (e.g. 'Anglepoint-Inc/anglepoint-stamp-server') so the workflow tracks your fork's updates instead of the upstream.",
  )
  .action(
    (opts: {
      minimal?: boolean;
      agentsMd: boolean;
      claudeMd: boolean;
      bootstrapCommit: boolean;
      ghProtect: boolean;
      mode?: string;
      remote: string;
      oteam: boolean;
      prCheck: boolean;
      migrateToServerAttested?: boolean;
      server?: string;
      dryRun?: boolean;
      adminKeys?: string;
      actionSource?: string;
    }) => {
      try {
        // The migration flag short-circuits the normal init flow: an
        // existing 1.x repo already has reviewers + a keypair + a
        // committed config; the migration only adds the v4 trust
        // anchors. Re-running the full `stamp init` scaffold against an
        // existing repo would be redundant (and would print the
        // already-on-disk summary block again).
        if (opts.migrateToServerAttested) {
          // Parse --admin-keys at the CLI surface so a malformed input
          // fails before any IO. Each entry must look like a canonical
          // fingerprint (sha256:<64-lowercase-hex>); reject obvious
          // typos (wrong prefix, wrong length, non-hex chars) here so
          // the operator sees the failure at parse time, not after the
          // server pubkey fetch.
          let adminKeys: string[] | undefined;
          if (opts.adminKeys !== undefined) {
            const fingerprintRe = /^sha256:[0-9a-f]{64}$/;
            const raw = opts.adminKeys.split(",").map((s) => s.trim()).filter(Boolean);
            if (raw.length === 0) {
              throw new Error(
                "--admin-keys: at least one comma-separated sha256:<64hex> fingerprint is required.",
              );
            }
            const malformed = raw.filter((fp) => !fingerprintRe.test(fp));
            if (malformed.length > 0) {
              throw new Error(
                `--admin-keys: malformed fingerprint(s): ${malformed.join(", ")}. ` +
                  `Expected sha256:<64 lowercase hex chars>; got input that does not match.`,
              );
            }
            adminKeys = raw;
          }
          runMigrateToServerAttested({
            dryRun: opts.dryRun === true,
            server: opts.server,
            adminKeys,
          });
          return;
        }
        // `--dry-run` is migration-path-only — the other init code
        // paths (mode auto-detection, GitHub Ruleset application) write
        // files and call out to `gh` unconditionally.
        // Silently ignoring `--dry-run` outside the migration was a
        // footgun: agents (and humans) reasonably expect "preview only"
        // semantics universally. Error loudly instead so the operator
        // gets a clear signal before the scaffold runs.
        if (opts.dryRun === true) {
          throw new Error(
            "--dry-run is supported only with --migrate-to-server-attested. " +
              "Re-run with --migrate-to-server-attested to preview the migration scaffold, " +
              "or drop --dry-run to run the requested init operation.",
          );
        }
        let mode: "server-gated" | "local-only" | undefined;
        if (opts.mode === undefined) {
          mode = undefined;
        } else if (opts.mode === "server-gated" || opts.mode === "local-only") {
          mode = opts.mode;
        } else {
          throw new Error(
            `--mode must be 'server-gated' or 'local-only' (got "${opts.mode}")`,
          );
        }
        // Validate --action-source shape (org/repo). Reject early so we
        // don't write a workflow that GitHub will reject at lookup time.
        if (opts.actionSource !== undefined) {
          if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(opts.actionSource)) {
            throw new Error(
              `--action-source must be of the form 'org/repo' (got "${opts.actionSource}")`,
            );
          }
        }
        runInit({
          minimal: opts.minimal,
          agentsMd: opts.agentsMd,
          claudeMd: opts.claudeMd,
          bootstrapCommit: opts.bootstrapCommit,
          ghProtect: opts.ghProtect,
          mode,
          remote: opts.remote,
          oteam: opts.oteam,
          // commander's --no-pr-check yields opts.prCheck === false; no
          // flag yields true (the default-true sentinel). We only want
          // to forward an explicit `false` to runInit so its mode-aware
          // default fires when the operator hasn't opted out.
          prCheck: opts.prCheck === false ? false : undefined,
          actionSource: opts.actionSource,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`error: ${message}`);
        process.exit(1);
      }
    },
  );

program
  .command("bootstrap")
  .description(
    "land real reviewers in a freshly-provisioned stamp repo (replaces the placeholder example reviewer in one command)",
  )
  .option(
    "--reviewers <names>",
    "comma-separated starter persona names (default: security,standards,product)",
  )
  .option(
    "--from <dir>",
    "use a project-specific .stamp/ seed dir instead of starter personas (must contain config.yml + reviewers/)",
  )
  .option("--no-push", "skip the final git push after merging")
  .option("--remote <name>", "remote to push to", "origin")
  .option("--dry-run", "print the plan without making changes")
  .option("--force", "bypass the fresh-placeholder safety check")
  .option(
    "--no-agents-md",
    "skip creating or updating AGENTS.md at the repo root",
  )
  .option(
    "--no-claude-md",
    "skip creating or updating CLAUDE.md at the repo root (CLAUDE.md is auto-loaded by Claude Code)",
  )
  .action(
    async (opts: {
      reviewers?: string;
      from?: string;
      push: boolean;
      remote: string;
      dryRun?: boolean;
      force?: boolean;
      agentsMd: boolean;
      claudeMd: boolean;
    }) => {
      try {
        await runBootstrap({
          reviewers: opts.reviewers
            ? opts.reviewers.split(",").map((s) => s.trim()).filter(Boolean)
            : undefined,
          from: opts.from,
          noPush: !opts.push,
          remote: opts.remote,
          dryRun: opts.dryRun,
          force: opts.force,
          agentsMd: opts.agentsMd,
          claudeMd: opts.claudeMd,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`error: ${message}`);
        process.exit(1);
      }
    },
  );

program
  .command("provision [name]")
  .description(
    "single-command server-gated repo setup: provision a bare repo on the stamp server (~/.stamp/server.yml or --server), clone it, run bootstrap, optionally create a GitHub mirror + apply the Ruleset. With --migrate-bypass, migrate an existing server-gated repo's Ruleset bypass from OrganizationAdmin to a per-repo DeployKey actor (cwd's .stamp/mirror.yml identifies the target; <name> is ignored).",
  )
  .option(
    "--server <host:port>",
    "override ~/.stamp/server.yml with an inline endpoint",
  )
  .option(
    "--org <github-org>",
    "GitHub org or user to host the mirror repo under (skip mirror entirely if omitted)",
  )
  .option(
    "--into <path>",
    "where to clone the new repo locally (default: ./<name>)",
  )
  .option(
    "--public",
    "create the GitHub mirror repo as public instead of private",
  )
  .option("--no-mirror", "skip GitHub mirror creation + .stamp/mirror.yml")
  .option("--no-ruleset", "skip applying the GitHub Ruleset on the mirror")
  .option("--dry-run", "print the plan without making changes")
  .option(
    "--migrate-existing",
    "brownfield: migrate the existing repo at cwd (with .stamp/ committed and origin → github) to server-gated; preserves history, renames origin → github, points new origin at the stamp server",
  )
  .option(
    "--migrate-bypass",
    "migrate an existing server-gated repo's stamp-mirror-only Ruleset bypass actor from OrganizationAdmin to a per-repo DeployKey. Identifies the target via cwd's .stamp/mirror.yml. Additive by default (DeployKey added alongside existing actors); pair with --remove-orgadmin to also strip OrganizationAdmin from the bypass list",
  )
  .option(
    "--remove-orgadmin",
    "under --migrate-bypass, also remove OrganizationAdmin from the ruleset's bypass list. Verify the DeployKey transport works (one stamp push) before running this — there is no automated push-verification step",
  )
  .action(
    async (
      name: string | undefined,
      opts: {
        server?: string;
        org?: string;
        into?: string;
        public?: boolean;
        mirror: boolean;
        ruleset: boolean;
        dryRun?: boolean;
        migrateExisting?: boolean;
        migrateBypass?: boolean;
        removeOrgadmin?: boolean;
      },
    ) => {
      try {
        await runProvision({
          // ProvisionOptions.name is typed `string` so the rest of the
          // downstream readers don't have to narrow. Empty placeholder
          // for --migrate-bypass (which doesn't read it); the validation
          // block in runProvision requires a non-empty name in all other
          // modes.
          name: name ?? "",
          server: opts.server,
          org: opts.org,
          into: opts.into,
          privateRepo: !opts.public,
          noMirror: !opts.mirror,
          noRuleset: !opts.ruleset,
          dryRun: opts.dryRun,
          migrateExisting: opts.migrateExisting,
          migrateBypass: opts.migrateBypass,
          removeOrgadmin: opts.removeOrgadmin,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`error: ${message}`);
        process.exit(1);
      }
    },
  );

// Shared CLI catch shape: usage errors (bad name shape, malformed --from,
// etc.) get exit 2; everything else gets exit 1. Per the documented
// exit-code contract — 2 means "you passed bad args, fix and retry"; 1
// means "the operation failed mid-flight, decide whether to retry."
// Most commands don't currently throw UsageError, so they still exit 1
// as before; the path is in place for future commands that need to
// distinguish.
function handleCliError(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  // Match by .name rather than instanceof — TypeScript/tsup-bundled
  // modules can produce distinct class identities for the same exported
  // class depending on import paths, which makes `instanceof UsageError`
  // unreliable. The name property is set in UsageError's constructor.
  const isUsageError =
    err instanceof Error && (err as Error).name === "UsageError";
  console.error(`error: ${message}`);
  process.exit(isUsageError ? 2 : 1);
}

const server = program
  .command("server")
  .description(
    "manage the per-operator stamp server config at ~/.stamp/server.yml (commands like `stamp provision` and `stamp server-repos` read this file).",
  );
server
  .command("config [host:port]")
  .description(
    "write/inspect/remove ~/.stamp/server.yml. Provide exactly one of <host:port> (write), --show (print), or --unset (remove).",
  )
  .option("--show", "print the resolved config (or note if no config is set)")
  .option("--unset", "remove ~/.stamp/server.yml")
  .option("--user <user>", "SSH user when writing (default: git)")
  .option("--repo-root-prefix <path>", "repo root prefix on the server when writing (default: /srv/git)")
  .action(
    (
      hostPort: string | undefined,
      opts: { show?: boolean; unset?: boolean; user?: string; repoRootPrefix?: string },
    ) => {
      try {
        runServerConfig({
          hostPort,
          show: opts.show,
          unset: opts.unset,
          user: opts.user,
          repoRootPrefix: opts.repoRootPrefix,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );
server
  .command("pubkey")
  .description(
    "print a stamp-server-managed GitHub mirror-push deploy-key public half — single OpenSSH line, pipe-able into `gh api -X POST /repos/:o/:r/keys --field key=@-` to register as a deploy key. Without --repo, returns the legacy shared key (back-compat). With --repo <owner/repo>, returns a per-repo key that the server lazily generates on first request — preferred for new migrations because GitHub rejects re-registering the same key on a second repo.",
  )
  .option(
    "--server <host:port>",
    "override ~/.stamp/server.yml for this call",
  )
  .option(
    "--repo <owner>/<repo>",
    "fetch the per-repo deploy key for this GitHub mirror (lazy-generated server-side on first request)",
  )
  .action((opts: { server?: string; repo?: string }) => {
    try {
      runServerPubkey({ server: opts.server, repo: opts.repo });
    } catch (err) {
      handleCliError(err);
    }
  });

const config = program
  .command("config")
  .description(
    "manage per-user stamp config at ~/.stamp/config.yml — operator-level knobs that shouldn't be committed. Per-repo policy lives in `.stamp/config.yml`.",
  );
const configReviewers = config
  .command("reviewers")
  .description(
    "pin which Anthropic model each reviewer (security/standards/product/…) runs on. Defaults to claude-sonnet-4-6 for the three starter personas; opt into Opus on security with `set security claude-opus-4-7`.",
  );
configReviewers
  .command("set <reviewer> <model-id>")
  .description(
    "pin <reviewer> to <model-id> (e.g. `set security claude-opus-4-7`). Model id is opaque to stamp — passed straight to the agent SDK, so any string the SDK accepts works.",
  )
  .action((reviewer: string, modelId: string) => {
    try {
      runConfigReviewersSet({ reviewer, modelId });
    } catch (err) {
      handleCliError(err);
    }
  });
configReviewers
  .command("clear [reviewer]")
  .description(
    "remove a reviewer's model pin (resolver falls back to the SDK default), or pass --all to delete the whole ~/.stamp/config.yml.",
  )
  .option(
    "--all",
    "remove the entire ~/.stamp/config.yml file (every reviewer falls back to the SDK default)",
  )
  .action((reviewer: string | undefined, opts: { all?: boolean }) => {
    try {
      runConfigReviewersClear({ reviewer, all: opts.all });
    } catch (err) {
      handleCliError(err);
    }
  });
configReviewers
  .command("show")
  .description(
    "print the resolved per-reviewer model config (or note that no config is set and which defaults will apply).",
  )
  .action(() => {
    try {
      runConfigReviewersShow();
    } catch (err) {
      handleCliError(err);
    }
  });

const serverRepo = program
  .command("server-repos")
  .description(
    "manage bare repos on the stamp server (list / delete / restore). Uses ~/.stamp/server.yml or --server.",
  );
serverRepo
  .command("list")
  .description(
    "list bare repos on the stamp server (default: live repos; --trash: soft-deleted entries awaiting restore or purge)",
  )
  .option("--server <host:port>", "override ~/.stamp/server.yml")
  .option("--trash", "list soft-deleted (trashed) entries instead of live repos")
  .action((opts: { server?: string; trash?: boolean }) => {
    try {
      runServerRepoList({ server: opts.server, trash: opts.trash });
    } catch (err) {
      handleCliError(err);
    }
  });
serverRepo
  .command("delete <name>")
  .description("soft-delete (default) or --purge a bare repo on the stamp server")
  .option("--server <host:port>", "override ~/.stamp/server.yml")
  .option("--purge", "hard delete (no recovery; also clears any trashed copies)")
  .option("--also-github <owner/repo>", "also `gh repo delete` the GitHub mirror after server-side success")
  .option(
    "--yes",
    "skip the typed-confirmation prompts — both the initial delete prompt and the secondary GitHub-mirror prompt when --also-github is set (use only in non-interactive contexts)",
  )
  .action(
    async (
      name: string,
      opts: { server?: string; purge?: boolean; alsoGithub?: string; yes?: boolean },
    ) => {
      try {
        await runServerRepoDelete({
          name,
          server: opts.server,
          purge: opts.purge,
          alsoGithub: opts.alsoGithub,
          yes: opts.yes,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );
serverRepo
  .command("restore <name>")
  .description("restore the most recent soft-deleted copy of <name> (or a specific one via --from)")
  .option("--server <host:port>", "override ~/.stamp/server.yml")
  .option(
    "--from <trash-entry>",
    "restore a specific trash entry (see `stamp server-repos list --trash` for names)",
  )
  .option("--as <new-name>", "restore under a different live name")
  .action(
    async (
      name: string,
      opts: { server?: string; from?: string; as?: string },
    ) => {
      try {
        await runServerRepoRestore({
          name,
          server: opts.server,
          from: opts.from,
          asName: opts.as,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );

serverRepo
  .command("purge")
  .description(
    "permanently delete soft-deleted (trashed) bare repos older than --older-than (irreversible). The server also auto-purges on a schedule (STAMP_TRASH_TTL_DAYS, default 30d); this is the on-demand path. `--older-than 0d` purges ALL trash.",
  )
  .requiredOption("--older-than <Nd>", "purge trash older than this many whole days, e.g. 30d (0d = all)")
  .option("--server <host:port>", "override ~/.stamp/server.yml")
  .option("--yes", "skip the typed confirmation (destructive)")
  .action(async (opts: { olderThan: string; server?: string; yes?: boolean }) => {
    try {
      await runServerRepoPurge({
        olderThan: opts.olderThan,
        server: opts.server,
        yes: opts.yes,
      });
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("review")
  .description(
    "run configured reviewer(s) against a diff. Reviewer config + prompts are sourced from the merge-base tree (security: prevents feature-branch self-review). For lock-file drift checks, use `stamp reviewers verify` (which exits 3 on drift). Reviewer execution budgets resolve narrowest-wins: `.stamp/config.yml` per-reviewer fields (`reviewers.<name>.max_turns` / `timeout_ms`, committed, sourced from the merge-base tree), then env overrides (`STAMP_REVIEWER_MAX_TURNS` default 8, `STAMP_REVIEWER_TIMEOUT_MS` default 300000), then defaults. Re-reviews on the same branch are narrowed to delta-since-prior-review so the LLM cannot re-flag unchanged code (set STAMP_NO_DELTA_REVIEW=1 to fall back to full-diff with prompt-only ratchet). On failure a structured turn trace is written to `.git/stamp/failed-runs/` — see docs/troubleshooting.md.",
  )
  .requiredOption("--diff <revspec>", "git revspec to review, e.g. main..HEAD")
  .option("--only <reviewer>", "run a single reviewer by name")
  .option(
    "--into <target>",
    "target branch whose rule to evaluate (default: inferred from the diff's left side). Determines which branch rule's `review_server` is consulted in trusted mode — pass when the revspec base differs from the merge target.",
  )
  .option(
    "--allow-large",
    "bypass the 200KB diff size cap (raise STAMP_REVIEW_DIFF_CAP_BYTES for a different threshold)",
  )
  .option(
    "--no-cache",
    "skip the verdict cache and force a fresh LLM call for every reviewer (default: serve from cache when (reviewer, diff, prompt) tuple matches a prior verdict). STAMP_NO_REVIEW_CACHE=1 has the same effect.",
  )
  .option(
    "--plan",
    "local-only mode: emit a JSON plan on stdout for a parent agent to dispatch subagents against; do NOT call the LLM. Plan fields: schema_version, revspec, base_sha, head_sha, diff, reviewers[] (each with name, prompt, fence_hex). Writes a `note:`-prefixed no-trust advisory to stderr (no attestation is produced). In plan mode `--no-cache` and `--allow-large` are inert — no LLM call, no cache hit, no diff-size cap.",
  )
  .option(
    "--headless",
    "headless local-only mode (sibling to --plan, for cron / git hooks / scripts): stamp calls the Anthropic Messages API directly for each reviewer (one shot, no tool-use loop, no MCP) and emits a JSON plan on stdout with each reviewer's verdict + prose folded in. Requires ANTHROPIC_API_KEY (otherwise exits with usage error 2). Output JSON is a superset of --plan so downstream tooling doesn't branch. No attestation is produced; the stderr banner flags API-key metering separate from Claude Code subscription billing. Mutually exclusive with --plan. See docs/local-only-mode.md.",
  )
  .option(
    "--no-prose",
    "record only the verdict + diff/prompt hashes, omitting reviewer prose from `.git/stamp/state.db` (for regulated repos that don't want quoted diff snippets persisted). The gate, cache, and attestation are unaffected. Note: a later cached hit on the same (diff, prompt, reviewer) replays empty prose unless --no-cache.",
  )
  .action(
    async (opts: {
      diff: string;
      only?: string;
      into?: string;
      allowLarge?: boolean;
      cache?: boolean;
      plan?: boolean;
      headless?: boolean;
      prose?: boolean;
    }) => {
      try {
        // commander's --no-cache sets opts.cache = false; absent flag leaves
        // it undefined (default-on). Normalize to noCache: true on the
        // runReview side. --no-prose behaves the same way (opts.prose).
        await runReview({
          diff: opts.diff,
          only: opts.only,
          into: opts.into,
          allowLarge: opts.allowLarge,
          noCache: opts.cache === false,
          noProse: opts.prose === false,
          plan: opts.plan === true,
          headless: opts.headless === true,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );

program
  .command("status")
  .description("show gate state for a diff; exit 0 if gate is open, 1 if closed")
  .requiredOption("--diff <revspec>", "git revspec to inspect")
  .option(
    "--into <target>",
    "target branch whose rule to check (default: inferred from diff base)",
  )
  .action((opts: { diff: string; into?: string }) => {
    try {
      runStatus({ diff: opts.diff, into: opts.into });
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("merge <branch>")
  .description("merge <branch> into --into <target> if the gate is open")
  .requiredOption("--into <target>", "target branch to merge into")
  .option(
    "-y, --yes",
    "skip the operator-confirmation prompt for this invocation " +
      "(equivalent to STAMP_REQUIRE_HUMAN_MERGE=0; see audit H1)",
  )
  .action((branch: string, opts: { into: string; yes?: boolean }) => {
    try {
      runMerge({ branch, into: opts.into, yes: opts.yes });
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("attest [branch]")
  .description(
    "PR-check mode counterpart to `stamp merge` — sign an attestation envelope and write it to refs/stamp/attestations/<patch-id> for a GitHub Action to verify on the PR (no actual git merge happens here)",
  )
  .requiredOption("--into <target>", "target branch whose rule the gate is checked against")
  .option(
    "--push [remote]",
    "after attesting locally, push the current branch + the attestation ref to <remote> in one atomic git push (default remote: origin)",
  )
  .option(
    "--migrate-existing",
    "Shape 4 migration bootstrap (AGT-398): attest a narrowly-scoped diff that ADDS `review_server:` + `[server]`-capability trust-anchor entries (the chicken-and-egg PR that activates server-attested reviews on an existing repo). Produces a v3 envelope with empty server_signatures, a migration-bootstrap marker in the operator-signed payload, and exactly one operator-self admin counter-signature in `trust_anchor_signatures`. The flag is REFUSED on any diff outside the narrow Shape-4-activation whitelist (no files outside .stamp/, no modifications to existing trust-anchor entries, no removals). Requires the operator's local key to have `admin` capability in the working-tree manifest and `path_rules` to cover the activated paths with `bypass_review_cycle: true` and `minimum_signatures: 1`. See docs/migration-1.x-to-2.x.md for the full Shape 4 bootstrap walkthrough.",
  )
  .action(
    (
      branch: string | undefined,
      opts: { into: string; push?: string | boolean; migrateExisting?: boolean },
    ) => {
      try {
        // commander gives us:
        //   undefined when --push isn't passed
        //   true      when --push is passed alone
        //   "<name>"  when --push <name> is passed
        // Normalize to a remote string or undefined.
        const pushTo =
          opts.push === true
            ? "origin"
            : typeof opts.push === "string"
              ? opts.push
              : undefined;
        runAttest({
          branch,
          into: opts.into,
          pushTo,
          migrateExisting: opts.migrateExisting === true,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );

program
  .command("push <target>")
  .description("push <target> to origin; surfaces stamp-verify hook stderr on rejection")
  .option("--remote <name>", "remote to push to", "origin")
  .action((target: string, opts: { remote: string }) => {
    try {
      runPush({ target, remote: opts.remote });
    } catch (err) {
      handleCliError(err);
    }
  });

const pr = program
  .command("pr")
  .description(
    "GitHub PR integration for stamp — opt-in peer-agentic review broadcast",
  );

pr
  .command("open <branch>")
  .description(
    "push <branch> to origin, open a GitHub PR via 'gh pr create', and broadcast a signed " +
      "pr-opened event to the stamp-server so peer-agentic reviewers are notified. " +
      "Plain 'git push' + 'gh pr create' do NOT trigger any broadcast — the opt-in boundary " +
      "is enforced solely by this command.",
  )
  .option(
    "--server <host:port>",
    "override ~/.stamp/server.yml with an inline endpoint",
  )
  .option(
    "--remote <name>",
    "remote to push to (default: origin)",
    "origin",
  )
  .addHelpText(
    "after",
    `
Three-step sequence:
  1. git push <remote> <branch>           — push the branch to the remote (default: origin)
  2. gh pr create --head <branch> --fill  — open the GitHub PR
  3. broadcast signed pr-opened payload   — notify stamp-server listeners

Exit codes:
  0   — full success (all three steps completed), OR stamp-server has peer
        reviews disabled (STAMP_PEER_REVIEWS_ENABLED not set) — informational
  1   — 'git push' failed; no PR opened, no broadcast attempted
  3   — 'gh pr create' failed; push already landed — open PR manually or retry
  4   — broadcast failed; PR is live on GitHub but listeners were not notified
  127 — 'gh' (GitHub CLI) not found on PATH

Prerequisites:
  - 'gh' must be installed: https://cli.github.com
  - stamp signing key at ~/.stamp/keys/ed25519 ('stamp keys generate' to create)
  - stamp-server config at ~/.stamp/server.yml ('stamp server config <host:port>' to set)
`,
  )
  .action(async (branch: string, opts: { server?: string; remote: string }) => {
    await runPrOpen({ branch, server: opts.server, remote: opts.remote });
  });

pr
  .command("listen")
  .description(
    "subscribe to peer-review PR events for the given org(s) and run the builtin-default review " +
      "for each incoming PR-opened event. Runs as a foreground loop until ctrl-C.",
  )
  .requiredOption(
    "--org <org>",
    "org slug to subscribe to (repeat for multiple orgs)",
    (v: string, acc: string[]) => { acc.push(v); return acc; },
    [] as string[],
  )
  .option(
    "--server <host:port>",
    "override ~/.stamp/server.yml with an inline endpoint",
  )
  .addHelpText(
    "after",
    `
Subscribes the operator's stamp identity to PR-opened events for the given orgs,
then loops indefinitely:
  - Receives pr-opened events via the in-process fanout registry (wire-frame;
    real cross-process delivery via WebSocket transport is not yet implemented)
  - Applies author-exclusion (skips own PRs)
  - Claims a reviewer seat; runs the builtin-default review via the Claude Agent SDK
  - Posts the result via 'gh pr review --comment'
  - Sends a heartbeat every 60 s to keep the seat alive

Exit codes:
  0   — clean shutdown (ctrl-C / SIGINT)
  1   — auth failure (no signing key, subscribe failed)
  2   — arg-parse error (--org is required)

Prerequisites:
  - 'gh' must be installed: https://cli.github.com
  - stamp signing key at ~/.stamp/keys/ed25519 ('stamp keys generate' to create)
  - stamp-server config at ~/.stamp/server.yml ('stamp server config <host:port>' to set)
`,
  )
  .action(async (opts: { org: string[]; server?: string }) => {
    const orgs: string[] = Array.isArray(opts.org) ? opts.org : [opts.org];
    if (orgs.length === 0) {
      process.stderr.write(`error: --org is required (repeat for multiple orgs)\n`);
      process.exit(2);
    }
    await runPrListen({ orgs, server: opts.server });
  });

pr
  .command("ping [pr-url]")
  .description(
    "notify prior reviewers that a PR has been updated with new commits. " +
      "Sends a signed re-review-request to the stamp-server for the patch_id " +
      "resolved from the current branch (or from <pr-url> when given). " +
      "Without --reviewer, all active seat-holders are pinged.",
  )
  .option(
    "--reviewer <name>",
    "restrict re-review notification to this reviewer (repeat for multiple)",
    (v: string, acc: string[]) => { acc.push(v); return acc; },
    [] as string[],
  )
  .option(
    "--server <host:port>",
    "override ~/.stamp/server.yml with an inline endpoint",
  )
  .addHelpText(
    "after",
    `
Resolves the patch_id from the current branch's open PR (via 'gh pr view')
or from <pr-url> when given, then sends a signed re-review-request to the
stamp-server. Each active seat-holder whose listener is online receives a
re-review-requested event and re-runs their triage + review flow.

Exit codes:
  0  — success (including when no active seat-holders exist — a stderr note
       is printed)
  1  — auth failure: no signing key, or operator is not the original PR author
  2  — reserved for arg-parse errors (Commander only; not set by this command)
  3  — patch_id resolution failed: no open PR for current HEAD, or <pr-url>
       is unknown to the stamp-server (was the PR opened via 'stamp pr open'?)

Prerequisites:
  - 'gh' must be installed: https://cli.github.com
  - stamp signing key at ~/.stamp/keys/ed25519 ('stamp keys generate' to create)
  - stamp-server config at ~/.stamp/server.yml ('stamp server config <host:port>' to set)
  - PR must have been opened via 'stamp pr open' (plain 'gh pr create' does not register
    a patch_id on the stamp-server)
`,
  )
  .action(async (prUrl: string | undefined, opts: { reviewer: string[]; server?: string }) => {
    await runPrPing({ prUrl, reviewer: opts.reviewer, server: opts.server });
  });

const peer = program
  .command("peer")
  .description(
    "Operator tools for the peer-agentic review system — triage, prompt management, and dry-runs.",
  );

peer
  .command("test")
  .description(
    "dry-run the triage call against a saved event fixture and print the TriageDecision to stdout",
  )
  .requiredOption(
    "--event <path>",
    "path to a saved pr-opened event JSON fixture",
  )
  .addHelpText(
    "after",
    `
Loads ~/.stamp/peer-watch.md and the given event JSON fixture, makes the Haiku
triage call, and pretty-prints the resulting TriageDecision to stdout.

Exit codes:
  0   — success; TriageDecision JSON on stdout
  1   — peer-watch.md missing or event fixture unreadable/invalid
  3   — Haiku call or schema validation failed
`,
  )
  .action(async (opts: { event: string }) => {
    await runPeerTest({ eventPath: opts.event });
  });

program
  .command("verify <sha>")
  .description("verify an existing merge commit's attestation locally")
  .action((sha: string) => {
    try {
      runVerify(sha);
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("verify-pr <head>")
  .description(
    "verify a PR attestation at refs/stamp/attestations/<patch-id> for the diff <base>..<head> against the --into branch's rule (used by stamp/verify-attestation@v1; also runnable locally for debugging)",
  )
  .requiredOption("--base <ref>", "PR base ref (commit SHA, branch, or any rev-parse-able value)")
  .requiredOption(
    "--into <branch>",
    "branch the PR is merging into; must equal the attestation's target_branch",
  )
  .action((head: string, opts: { base: string; into: string }) => {
    try {
      runVerifyPr({ head, base: opts.base, into: opts.into });
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("update")
  .description(
    "upgrade stamp to the latest npm release (runs 'npm install -g @openthink/stamp@latest')",
  )
  .action(() => wrap(() => runUpdate()));

program
  .command("prune")
  .description(
    "delete review-history rows older than <duration> from the per-machine " +
      "state.db (then VACUUM), AND unlink failed-parse spool files under " +
      ".git/stamp/failed-parses/ whose mtime is older than <duration>. Use " +
      "--dry-run first to preview both passes.",
  )
  .requiredOption(
    "--older-than <duration>",
    "retention cutoff, e.g. 30d (days), 12h (hours), 90m (minutes)",
  )
  .option(
    "--dry-run",
    "print the per-reviewer breakdown of state.db rows AND the list of " +
      "spool file paths that would be pruned, without modifying anything",
  )
  .action((opts: { olderThan: string; dryRun?: boolean }) => {
    try {
      runPrune({ olderThan: opts.olderThan, dryRun: opts.dryRun });
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("ui")
  .description("launch the interactive terminal UI")
  .action(async () => {
    try {
      // Dynamic import keeps ink/react (~35 transitive deps) out of the
      // hot path for every non-ui command.
      const { runUi } = await import("./commands/ui.js");
      runUi();
    } catch (err) {
      handleCliError(err);
    }
  });

program
  .command("log [sha]")
  .description(
    "show first-parent merge history with attestation summaries; <sha> shows full detail for one commit",
  )
  .option("--limit <n>", "max entries in list view", "20")
  .option("--branch <name>", "branch/ref to list; defaults to current branch")
  .option(
    "--reviews",
    "legacy view — raw review DB rows instead of commit history",
  )
  .option(
    "--diff <revspec>",
    "with --reviews, filter rows to this exact diff",
  )
  .action(
    (
      sha: string | undefined,
      opts: {
        limit: string;
        branch?: string;
        reviews?: boolean;
        diff?: string;
      },
    ) => {
      wrap(() =>
        runLog({
          sha,
          limit: Number(opts.limit) || 20,
          branch: opts.branch,
          reviews: opts.reviews ?? false,
          diff: opts.diff,
        }),
      );
    },
  );

const keys = program
  .command("keys")
  .description("manage signing keys");
keys
  .command("generate")
  .description("generate a new Ed25519 keypair at ~/.stamp/keys/")
  .action(() => wrap(() => keysGenerate()));
keys
  .command("list")
  .description("list local and trusted keys")
  .action(() => wrap(() => keysList()));
keys
  .command("export")
  .description("print the local public key (for committing to trusted-keys)")
  .option("--pub", "export public key (default)")
  .action(() => wrap(() => keysExport()));
keys
  .command("trust <pub-file>")
  .description("copy a public key into the repo's .stamp/trusted-keys/")
  .action((pubFile: string) => wrap(() => keysTrust(pubFile)));

const admin = program
  .command("admin")
  .description(
    "operator workflows for trust-anchor (admin-capability) actions on .stamp/** changes",
  );

admin
  .command("sign")
  .description(
    "collect or add admin-capability counter-signatures for pending .stamp/** commits",
  )
  .option(
    "--pending [sha]",
    "list pending .stamp/** commits awaiting counter-signature, or sign the given SHA",
  )
  .option(
    "--target-branch <name>",
    "override the predicted target branch baked into the admin signing target (default: current branch's upstream basename, else current branch)",
  )
  .option(
    "--signer-key-id <fingerprint>",
    "override the predicted operator fingerprint baked into the signing target — required for non-operator co-signers in multi-admin workflows (form: sha256:<64-hex>)",
  )
  .option(
    "--mode <mode>",
    "envelope format to produce the signature for: 'auto' (default — detect from review_server at base_sha), 'pr' (Shape 4 PR-mode, schema_version 3), or 'v4' (commit-trailer, schema_version 5). Force a mode for debugging or staged migrations.",
    "auto",
  )
  .option("--json", "(list mode only) emit pending commits as JSON")
  .action((opts: { pending?: string | boolean; targetBranch?: string; signerKeyId?: string; mode?: string; json?: boolean }) => {
    try {
      // commander returns `true` when --pending is passed without a value
      // (the [sha] form). Map that to undefined → list mode. A real string
      // value → sign mode for that SHA. Absence of the flag entirely is
      // currently also treated as list mode — there's no other meaningful
      // shape for `stamp admin sign` today.
      const pendingArg =
        typeof opts.pending === "string" ? opts.pending : undefined;
      const mode = opts.mode ?? "auto";
      if (mode !== "auto" && mode !== "pr" && mode !== "v4") {
        throw new Error(
          `--mode must be one of: auto, pr, v4 (got ${JSON.stringify(mode)})`,
        );
      }
      runAdminSign({
        pending: pendingArg,
        targetBranch: opts.targetBranch,
        signerKeyId: opts.signerKeyId,
        mode,
        json: opts.json,
      });
    } catch (err) {
      handleCliError(err);
    }
  });

admin
  .command("add-key <pubkey-path>")
  .description(
    "add a new trusted-keys entry, copy the pub file into .stamp/trusted-keys/, and commit (path_rules gate applies)",
  )
  .requiredOption(
    "--name <name>",
    "short name for the manifest entry (ASCII letters/digits/'.','-','_')",
  )
  .requiredOption(
    "--capabilities <list>",
    "comma-separated capabilities — one or more of admin, operator, server (e.g. 'admin,operator')",
  )
  .action(
    (
      pubkeyPath: string,
      opts: { name: string; capabilities: string },
    ) => {
      try {
        runAdminAddKey({
          pubkeyPath,
          name: opts.name,
          capabilities: opts.capabilities,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );

admin
  .command("revoke <fingerprint>")
  .description(
    "remove the given fingerprint from the trusted-keys manifest and commit (path_rules gate applies)",
  )
  .action((fingerprint: string) => {
    try {
      runAdminRevoke({ fingerprint });
    } catch (err) {
      handleCliError(err);
    }
  });

admin
  .command("list-keys")
  .description(
    "list every entry in .stamp/trusted-keys/manifest.yml (name, fingerprint, capabilities)",
  )
  .option("--json", "emit the manifest as JSON instead of the human table")
  .action((opts: { json?: boolean }) => {
    try {
      runAdminListKeys({ json: opts.json });
    } catch (err) {
      handleCliError(err);
    }
  });

function wrap(fn: () => void): void {
  try {
    fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`error: ${message}`);
    process.exit(1);
  }
}

const invites = program
  .command("invites")
  .description("mint and accept single-use invite tokens for teammate onboarding");

invites
  .command("mint <short-name>")
  .description("mint an invite for a teammate (15-min TTL, admin/owner only)")
  .option("--role <admin|member>", "role to grant on accept", "member")
  .action((shortName: string, opts: { role: string }) => {
    try {
      if (opts.role !== "admin" && opts.role !== "member") {
        throw new Error(
          `--role must be 'admin' or 'member' (got ${JSON.stringify(opts.role)})`,
        );
      }
      runInvitesMint({ shortName, role: opts.role as InviteRole });
    } catch (err) {
      handleCliError(err);
    }
  });

invites
  .command("accept <share-url-or-token>")
  .description("redeem an invite token; auto-detects local keys, prompts to confirm")
  .option("--server <host:port>", "server endpoint when passing a bare token (no URL)")
  .option("--ssh-pubkey <path>", "override SSH pubkey path (default ~/.ssh/id_ed25519.pub)")
  .option("--stamp-pubkey <path>", "override stamp signing pubkey path (default ~/.stamp/keys/ed25519.pub)")
  .option("--short-name <name>", "override the short_name (default derived from user@host)")
  .option("--yes", "skip the confirmation prompt (required for non-TTY stdin)")
  .option(
    "--insecure-http-for-dev",
    "use plaintext HTTP for the accept POST (dev / LAN only; default is HTTPS). Requires --accept-insecure.",
  )
  .option(
    "--accept-insecure",
    "explicit consent to send the token + SSH pubkey over plaintext HTTP (required with --insecure-http-for-dev; --yes alone does NOT enable HTTP)",
  )
  .action(
    async (
      urlOrToken: string,
      opts: {
        server?: string;
        sshPubkey?: string;
        stampPubkey?: string;
        shortName?: string;
        yes?: boolean;
        insecureHttpForDev?: boolean;
        acceptInsecure?: boolean;
      },
    ) => {
      try {
        await runInvitesAccept({
          urlOrToken,
          server: opts.server,
          sshPubkeyPath: opts.sshPubkey,
          stampPubkeyPath: opts.stampPubkey,
          shortName: opts.shortName,
          yes: opts.yes,
          insecureHttpForDev: opts.insecureHttpForDev,
          acceptInsecure: opts.acceptInsecure,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );

const users = program
  .command("users")
  .description("list, promote, demote, and remove enrolled users on the stamp server");

users
  .command("list")
  .description("list enrolled users (everyone authenticated may run this)")
  .option("--json", "emit the raw server JSON instead of the formatted table")
  .action((opts: { json?: boolean }) => {
    try {
      runUsersList({ json: opts.json });
    } catch (err) {
      handleCliError(err);
    }
  });

users
  .command("promote <short-name>")
  .description("promote a user; admins may not promote to admin/owner except for the no-owners bootstrap path")
  .requiredOption("--to <admin|owner>", "target role")
  .action((shortName: string, opts: { to: string }) => {
    try {
      if (opts.to !== "admin" && opts.to !== "owner") {
        throw new Error(
          `promote --to must be 'admin' or 'owner' (got ${JSON.stringify(opts.to)})`,
        );
      }
      runUsersPromote({ shortName, to: opts.to });
    } catch (err) {
      handleCliError(err);
    }
  });

users
  .command("demote <short-name>")
  .description("demote a user (admin/owner only; last-owner guard prevents zeroing out ownership)")
  .requiredOption("--to <admin|member>", "target role")
  .action((shortName: string, opts: { to: string }) => {
    try {
      if (opts.to !== "admin" && opts.to !== "member") {
        throw new Error(
          `demote --to must be 'admin' or 'member' (got ${JSON.stringify(opts.to)})`,
        );
      }
      runUsersDemote({ shortName, to: opts.to });
    } catch (err) {
      handleCliError(err);
    }
  });

users
  .command("remove <short-name>")
  .description("remove a user from the membership DB (admins may remove members only; cannot remove self)")
  .action((shortName: string) => {
    try {
      runUsersRemove({ shortName });
    } catch (err) {
      handleCliError(err);
    }
  });

users
  .command("set-name <short-name>")
  .description(
    "set a user's human-readable short_name (default is a content-addressed user-<hex> slug). Owners may rename anyone; admins may rename members; anyone may rename themselves.",
  )
  .requiredOption("--to <new-name>", "the new short_name (alphanumerics + . _ -, start with alnum, max 63 chars)")
  .action((shortName: string, opts: { to: string }) => {
    try {
      runUsersSetName({ shortName, to: opts.to });
    } catch (err) {
      handleCliError(err);
    }
  });

users
  .command("prune")
  .description(
    "remove users idle for at least the given window (by last_seen_at, falling back to created_at). Owners may prune admins+members; admins may prune members. Never prunes owners or yourself.",
  )
  .requiredOption("--idle-for <Nd>", "idle window in whole days, e.g. 30d")
  .action((opts: { idleFor: string }) => {
    try {
      runUsersPrune({ idleFor: opts.idleFor });
    } catch (err) {
      handleCliError(err);
    }
  });

const trust = program
  .command("trust")
  .description("manage per-repo stamp signing trust (committed under .stamp/trusted-keys/)");

trust
  .command("grant <short-name>")
  .description("stage a trust-grant for an enrolled user on a new branch; review + merge through the usual gate")
  .option("--repo <path>", "repo root to operate on (default: cwd)")
  .option("--force-dirty", "stage the grant even if the working tree has uncommitted changes")
  .action(
    (shortName: string, opts: { repo?: string; forceDirty?: boolean }) => {
      try {
        runTrustGrant({
          shortName,
          repoPath: opts.repo,
          forceDirty: opts.forceDirty,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );

const reviewers = program
  .command("reviewers")
  .description("manage reviewer prompts");
reviewers
  .command("list")
  .description("list configured reviewers and their prompt file status")
  .action(() => wrap(() => reviewersList()));
reviewers
  .command("add <name>")
  .description("scaffold a new reviewer: create prompt file, register in config, open in editor")
  .option("--no-edit", "skip opening $EDITOR after scaffolding")
  .action((name: string, opts: { edit: boolean }) =>
    wrap(() => reviewersAdd(name, { noEdit: !opts.edit })),
  );
reviewers
  .command("remove <name>")
  .description("remove a reviewer from config (fails if in use by a branch rule)")
  .option("--delete-file", "also delete the reviewer's prompt file")
  .action((name: string, opts: { deleteFile?: boolean }) =>
    wrap(() => reviewersRemove(name, { deleteFile: opts.deleteFile })),
  );
reviewers
  .command("edit <name>")
  .description("open a reviewer's prompt file in $EDITOR")
  .action((name: string) => wrap(() => reviewersEdit(name)));
reviewers
  .command("test <name>")
  .description("invoke a reviewer against a diff WITHOUT recording to DB (prompt tuning)")
  .requiredOption("--diff <revspec>", "git revspec to review, e.g. main..HEAD")
  .action(async (name: string, opts: { diff: string }) => {
    try {
      await reviewersTest(name, opts.diff);
    } catch (err) {
      handleCliError(err);
    }
  });
reviewers
  .command("show <name>")
  .description("show a reviewer's verdict history and aggregate stats")
  .option("--limit <n>", "max recent verdicts to list", "10")
  .action((name: string, opts: { limit: string }) =>
    wrap(() =>
      reviewersShow(name, { limit: Number(opts.limit) || 10 }),
    ),
  );
reviewers
  .command("fetch <name>")
  .description(
    "install a reviewer from a remote canonical source (writes prompt + lock file)",
  )
  .requiredOption(
    "--from <source@ref>",
    "source repo and ref — '<owner>/<repo>@<tag>' (GitHub) or full 'https://' URL + ref",
  )
  .option(
    "--expect-prompt-sha <sha256>",
    "out-of-band trust anchor: refuse the fetch if prompt.md SHA-256 doesn't match (hex; 'sha256:' prefix tolerated)",
  )
  .option(
    "--expect-tools-sha <sha256>",
    "trust anchor for the canonicalized tools-array hash (only meaningful when config.yaml is present)",
  )
  .option(
    "--expect-mcp-sha <sha256>",
    "trust anchor for the canonicalized mcp_servers-map hash (only meaningful when config.yaml is present)",
  )
  .action(
    async (
      name: string,
      opts: {
        from: string;
        expectPromptSha?: string;
        expectToolsSha?: string;
        expectMcpSha?: string;
      },
    ) => {
      try {
        await reviewersFetch(name, {
          from: opts.from,
          expectPromptSha: opts.expectPromptSha,
          expectToolsSha: opts.expectToolsSha,
          expectMcpSha: opts.expectMcpSha,
        });
      } catch (err) {
        handleCliError(err);
      }
    },
  );
reviewers
  .command("verify [name]")
  .description(
    "check reviewer prompt/tool/mcp config against lock files; exit 3 on drift",
  )
  .action((name: string | undefined) =>
    wrap(() => reviewersVerify({ only: name })),
  );

// Tombstone the removed Shape 2 `--pr-mode` flags with an actionable notice
// before commander rejects them as a bare "unknown option". Exit 2 = usage.
const prModeRemoval = removedPrModeNotice(process.argv);
if (prModeRemoval) {
  for (const line of prModeRemoval) console.error(line);
  process.exit(2);
}

program.parseAsync(process.argv).catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`error: ${message}`);
  process.exit(1);
});
