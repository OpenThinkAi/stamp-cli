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
import { runInit } from "./commands/init.js";
import {
  keysExport,
  keysGenerate,
  keysList,
  keysTrust,
} from "./commands/keys.js";
import { runLog } from "./commands/log.js";
import { runMerge } from "./commands/merge.js";
import { runPush } from "./commands/push.js";
import { runReview } from "./commands/review.js";
import {
  reviewersAdd,
  reviewersEdit,
  reviewersList,
  reviewersRemove,
  reviewersShow,
  reviewersTest,
} from "./commands/reviewers.js";
import { runStatus } from "./commands/status.js";
import { runVerify } from "./commands/verify.js";

const program = new Command();

program
  .name("stamp")
  .description(
    "Local, headless pull-request system for agent-to-agent code review.",
  )
  .version("0.1.0-alpha.0");

program
  .command("init")
  .description(
    "scaffold .stamp/ (three-persona starter: security/standards/product) and generate a keypair",
  )
  .option(
    "--minimal",
    "scaffold a single placeholder reviewer instead of the three-persona starter",
  )
  .action((opts: { minimal?: boolean }) => {
    try {
      runInit({ minimal: opts.minimal });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
    }
  });

program
  .command("review")
  .description("run configured reviewer(s) against a diff")
  .requiredOption("--diff <revspec>", "git revspec to review, e.g. main..HEAD")
  .option("--only <reviewer>", "run a single reviewer by name")
  .action(async (opts: { diff: string; only?: string }) => {
    try {
      await runReview({ diff: opts.diff, only: opts.only });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
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
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
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
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
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
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
    }
  });

program
  .command("verify <sha>")
  .description("verify an existing merge commit's attestation locally")
  .action((sha: string) => {
    try {
      runVerify(sha);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
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
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
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
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exit(1);
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

program.parseAsync(process.argv).catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`error: ${message}`);
  process.exit(1);
});
