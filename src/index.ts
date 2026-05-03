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
import { runInit } from "./commands/init.js";
import { runProvision } from "./commands/provision.js";
import {
  runServerRepoDelete,
  runServerRepoList,
  runServerRepoRestore,
} from "./commands/serverRepo.js";
import {
  keysExport,
  keysGenerate,
  keysList,
  keysTrust,
} from "./commands/keys.js";
import { runLog } from "./commands/log.js";
import { runMerge } from "./commands/merge.js";
import { runPrune } from "./commands/prune.js";
import { runPush } from "./commands/push.js";
import { runReview } from "./commands/review.js";
import { runServerConfig } from "./commands/server.js";
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
  .action(
    (opts: {
      minimal?: boolean;
      agentsMd: boolean;
      claudeMd: boolean;
      bootstrapCommit: boolean;
      ghProtect: boolean;
      mode?: string;
      remote: string;
    }) => {
      try {
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
        runInit({
          minimal: opts.minimal,
          agentsMd: opts.agentsMd,
          claudeMd: opts.claudeMd,
          bootstrapCommit: opts.bootstrapCommit,
          ghProtect: opts.ghProtect,
          mode,
          remote: opts.remote,
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
  .command("provision <name>")
  .description(
    "single-command server-gated repo setup: provision a bare repo on the stamp server (~/.stamp/server.yml or --server), clone it, run bootstrap, optionally create a GitHub mirror + apply the Ruleset",
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
  .action(
    async (
      name: string,
      opts: {
        server?: string;
        org?: string;
        into?: string;
        public?: boolean;
        mirror: boolean;
        ruleset: boolean;
        dryRun?: boolean;
        migrateExisting?: boolean;
      },
    ) => {
      try {
        await runProvision({
          name,
          server: opts.server,
          org: opts.org,
          into: opts.into,
          privateRepo: !opts.public,
          noMirror: !opts.mirror,
          noRuleset: !opts.ruleset,
          dryRun: opts.dryRun,
          migrateExisting: opts.migrateExisting,
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

program
  .command("review")
  .description(
    "run configured reviewer(s) against a diff. Reviewer config + prompts are sourced from the merge-base tree (security: prevents feature-branch self-review). For lock-file drift checks, use `stamp reviewers verify` (which exits 3 on drift).",
  )
  .requiredOption("--diff <revspec>", "git revspec to review, e.g. main..HEAD")
  .option("--only <reviewer>", "run a single reviewer by name")
  .option(
    "--allow-large",
    "bypass the 200KB diff size cap (raise STAMP_REVIEW_DIFF_CAP_BYTES for a different threshold)",
  )
  .action(async (opts: { diff: string; only?: string; allowLarge?: boolean }) => {
    try {
      await runReview({
        diff: opts.diff,
        only: opts.only,
        allowLarge: opts.allowLarge,
      });
    } catch (err) {
      handleCliError(err);
    }
  });

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
  .action((branch: string, opts: { into: string }) => {
    try {
      runMerge({ branch, into: opts.into });
    } catch (err) {
      handleCliError(err);
    }
  });

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
  .command("update")
  .description(
    "upgrade stamp-cli to the latest npm release (runs 'npm install -g stamp-cli@latest')",
  )
  .action(() => wrap(() => runUpdate()));

program
  .command("prune")
  .description(
    "delete review-history rows older than <duration> from the per-machine state.db, then VACUUM. Use --dry-run first to preview.",
  )
  .requiredOption(
    "--older-than <duration>",
    "retention cutoff, e.g. 30d (days), 12h (hours), 90m (minutes)",
  )
  .option(
    "--dry-run",
    "print the per-reviewer breakdown that would be pruned without modifying the DB",
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

function wrap(fn: () => void): void {
  try {
    fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`error: ${message}`);
    process.exit(1);
  }
}

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

program.parseAsync(process.argv).catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`error: ${message}`);
  process.exit(1);
});
