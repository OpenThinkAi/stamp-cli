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
import { runMerge } from "./commands/merge.js";
import { runReview } from "./commands/review.js";
import { runStatus } from "./commands/status.js";
import { runVerify } from "./commands/verify.js";
import { runLog, runPush, runReviewers } from "./commands/stubs.js";

const program = new Command();

program
  .name("stamp")
  .description(
    "Local, headless pull-request system for agent-to-agent code review.",
  )
  .version("0.1.0-alpha.0");

program
  .command("init")
  .description("scaffold .stamp/ in the current repo and generate a keypair")
  .action(() => {
    try {
      runInit();
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
  .description("push <target> to origin and report hook verdict")
  .action(() => runPush());

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
  .command("log")
  .description("show review history on the current branch (prose)")
  .option("--limit <n>", "max entries", "50")
  .action(() => runLog());

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
  .description("list configured reviewers")
  .action(() => runReviewers("list"));
reviewers
  .command("edit <name>")
  .description("open a reviewer prompt in $EDITOR")
  .action(() => runReviewers("edit"));

program.parseAsync(process.argv).catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`error: ${message}`);
  process.exit(1);
});
