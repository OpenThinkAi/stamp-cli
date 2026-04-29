import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ensureAgentsMd, ensureClaudeMd } from "../lib/agentsMd.js";
import {
  DEFAULT_PRODUCT_PROMPT,
  DEFAULT_SECURITY_PROMPT,
  DEFAULT_STANDARDS_PROMPT,
  findBranchRule,
  loadConfig,
  parseConfigFromYaml,
  stringifyConfig,
  type BranchRule,
  type StampConfig,
} from "../lib/config.js";
import { currentBranch, runGit } from "../lib/git.js";
import { classifyRemote, describeShape } from "../lib/remote.js";
import {
  ensureDir,
  findRepoRoot,
  stampConfigDir,
  stampConfigFile,
  stampReviewersDir,
} from "../lib/paths.js";
import { runMerge } from "./merge.js";
import { runPush } from "./push.js";
import { runReview } from "./review.js";

export interface BootstrapOptions {
  /** Reviewers to install. Defaults to the three starter personas. */
  reviewers?: string[];
  /** Skip the final `git push origin <target>`. Default false. */
  noPush?: boolean;
  /** Print the plan and exit without making changes. */
  dryRun?: boolean;
  /**
   * Optional path to a directory containing a project-specific `.stamp/` seed
   * (config.yml + reviewers/, optionally mirror.yml). Used in place of the
   * three starter personas. Same contract as `setup-repo.sh`'s seed-dir arg.
   */
  from?: string;
  /** Remote to push to. Default "origin". */
  remote?: string;
  /** Bypass the fresh-placeholder safety check. */
  force?: boolean;
  /**
   * When false, skip creating or updating AGENTS.md at the repo root.
   * Default true.
   */
  agentsMd?: boolean;
  /**
   * When false, skip creating or updating CLAUDE.md at the repo root.
   * Default true. CLAUDE.md is auto-loaded by Claude Code into the model
   * context, so this is the file most likely to actually surface the
   * "use stamp flow" rule to a Claude-Code agent.
   */
  claudeMd?: boolean;
}

const STARTER_PROMPTS: Record<string, string> = {
  security: DEFAULT_SECURITY_PROMPT,
  standards: DEFAULT_STANDARDS_PROMPT,
  product: DEFAULT_PRODUCT_PROMPT,
};

const BOOTSTRAP_BRANCH = "stamp/bootstrap";

export async function runBootstrap(opts: BootstrapOptions = {}): Promise<void> {
  const repoRoot = findRepoRoot();
  const configFile = stampConfigFile(repoRoot);

  // 1. Pre-flight: must have a config, must be on a real branch, working tree clean.
  if (!existsSync(configFile)) {
    throw new Error(
      `no .stamp/config.yml at ${configFile}. This command runs against an already-provisioned ` +
        `stamp repo (cloned from a stamp server with the placeholder seed). ` +
        `For a fresh local repo, run \`stamp init\` instead.`,
    );
  }

  const targetBranch = currentBranch(repoRoot);
  if (targetBranch === "HEAD") {
    throw new Error(
      `HEAD is detached. Check out a branch first (typically \`git checkout main\`).`,
    );
  }

  if (workingTreeDirty(repoRoot)) {
    throw new Error(
      `working tree has uncommitted changes to tracked files. Commit or stash before running \`stamp bootstrap\`.`,
    );
  }

  const currentConfig = loadConfig(configFile);
  const targetRule = findBranchRule(currentConfig.branches, targetBranch);
  if (!targetRule) {
    throw new Error(
      `.stamp/config.yml has no rule for branch "${targetBranch}". Switch to your protected branch first.`,
    );
  }

  // 2. Detect "fresh placeholder" state unless --force.
  if (!opts.force) {
    const reviewerNames = Object.keys(currentConfig.reviewers);
    const requiredOnTarget = targetRule.required;
    const isFreshPlaceholder =
      reviewerNames.length === 1 &&
      reviewerNames[0] === "example" &&
      requiredOnTarget.length === 1 &&
      requiredOnTarget[0] === "example";
    if (!isFreshPlaceholder) {
      // If origin is a public forge, the user almost certainly meant `stamp
      // init` (the local-only/no-server path), not bootstrap (which only
      // applies on a clone of a stamp-server-provisioned repo with the
      // example placeholder seed). Surface that hint inline so the agent
      // running this doesn't conclude "bootstrap isn't needed" and ship a
      // config that nothing enforces.
      const remoteClass = classifyRemote(opts.remote ?? "origin", repoRoot);
      const deploymentHint =
        remoteClass.shape === "forge-direct"
          ? `\n\n` +
            `Note: ${describeShape(remoteClass)}. \`stamp bootstrap\` runs in a clone of a ` +
            `stamp-server-provisioned repo (one with the placeholder \`example\` reviewer ` +
            `seeded by setup-repo.sh). Your origin is a public forge directly, so this ` +
            `command isn't applicable. For local-only / advisory use against this remote, ` +
            `run \`stamp init --mode local-only\` instead. For server-gated enforcement, ` +
            `deploy a stamp server (docs/quickstart-server.md), provision a repo on it, ` +
            `clone the result, then run \`stamp bootstrap\` on the clone.`
          : "";
      throw new Error(
        `this repo doesn't look like a fresh placeholder bootstrap state. ` +
          `Expected: exactly one reviewer ("example") required by branch "${targetBranch}". ` +
          `Found reviewers: [${reviewerNames.join(", ")}], required: [${requiredOnTarget.join(", ")}]. ` +
          `If you're sure you want to overwrite this config, re-run with --force.` +
          deploymentHint,
      );
    }
  }

  // 3. Refuse if a previous bootstrap branch is still around.
  if (branchExists(BOOTSTRAP_BRANCH, repoRoot)) {
    throw new Error(
      `branch "${BOOTSTRAP_BRANCH}" already exists. ` +
        `Delete it (\`git branch -D ${BOOTSTRAP_BRANCH}\`) and re-run, or check it out and finish the bootstrap manually.`,
    );
  }

  // 4. Build the new config + reviewer prompts.
  const plan = buildPlan(currentConfig, targetBranch, targetRule, opts);

  // 5. Show the plan. Always — bootstrap is meant to be transparent.
  printPlan(plan, opts);

  if (opts.dryRun) {
    console.log("\n(dry run — no changes made)");
    return;
  }

  // 6. Create the bootstrap branch and write files.
  console.log(`\nCreating branch "${BOOTSTRAP_BRANCH}"`);
  runGit(["checkout", "-b", BOOTSTRAP_BRANCH], repoRoot);

  try {
    writeBootstrapFiles(repoRoot, plan);
    const agentsMdAction =
      opts.agentsMd === false ? "skipped" : ensureAgentsMd(repoRoot);
    const claudeMdAction =
      opts.claudeMd === false ? "skipped" : ensureClaudeMd(repoRoot);

    runGit(["add", ".stamp"], repoRoot);
    if (agentsMdAction !== "skipped") {
      runGit(["add", "AGENTS.md"], repoRoot);
    }
    if (claudeMdAction !== "skipped") {
      runGit(["add", "CLAUDE.md"], repoRoot);
    }
    const agentsMdLine = {
      created: "Creates AGENTS.md with stamp-protected-repo guidance for future agents.",
      replaced: "Refreshes the stamp-managed section of AGENTS.md.",
      appended: "Appends a stamp-protected-repo guidance section to the existing AGENTS.md.",
      unchanged: "AGENTS.md already up to date.",
      skipped: "AGENTS.md write skipped (--no-agents-md).",
    }[agentsMdAction];
    const claudeMdLine = {
      created: "Creates CLAUDE.md so Claude Code auto-loads the stamp rules.",
      replaced: "Refreshes the stamp-managed section of CLAUDE.md.",
      appended: "Appends a stamp section to the existing CLAUDE.md.",
      unchanged: "CLAUDE.md already up to date.",
      skipped: "CLAUDE.md write skipped (--no-claude-md).",
    }[claudeMdAction];
    const commitMsg =
      `stamp: bootstrap real reviewers (${plan.newReviewers.join(", ")})\n\n` +
      `Installs ${plan.newReviewers.join(", ")} as required reviewers on ${plan.targetBranch}.\n` +
      `Keeps the example placeholder defined-but-unrequired (so it can be re-bootstrapped).\n` +
      `${agentsMdLine}\n${claudeMdLine}`;
    runGit(["commit", "-m", commitMsg], repoRoot);

    // 7. Run the placeholder reviewer to record an approval. With --only,
    //    only `example` runs; the new reviewers exist in config but their
    //    verdicts aren't required by the pre-merge branch rule (which is
    //    still the pre-bootstrap "example only" rule on the target branch).
    console.log(
      `\nRunning placeholder reviewer to record approval for the bootstrap merge`,
    );
    await runReview({
      diff: `${targetBranch}..${BOOTSTRAP_BRANCH}`,
      only: "example",
    });

    // 8. Switch back to target and merge. Pre-merge required = [example],
    //    which we just approved. Post-merge config has the new reviewers
    //    declared, but the attestation only needs to cover the pre-merge
    //    required list (which the server hook also reads from pre-push state).
    console.log(`\nMerging into "${targetBranch}"`);
    runGit(["checkout", targetBranch], repoRoot);
    runMerge({ branch: BOOTSTRAP_BRANCH, into: targetBranch });

    // 9. Push (default).
    if (!opts.noPush) {
      console.log(`\nPushing "${targetBranch}" to ${opts.remote ?? "origin"}`);
      runPush({ target: targetBranch, remote: opts.remote });
    }
  } catch (err) {
    console.error(
      `\nbootstrap failed; the working tree may be on branch "${BOOTSTRAP_BRANCH}". ` +
        `Inspect with \`git status\` / \`git log -3\`. To start over: ` +
        `\`git checkout ${targetBranch} && git branch -D ${BOOTSTRAP_BRANCH}\`.`,
    );
    throw err;
  }

  // 10. Success summary.
  const bar = "─".repeat(72);
  console.log(`\n${bar}`);
  console.log(`✓ bootstrap complete`);
  console.log(bar);
  // Padding aligned with printPlan above so plan and summary scan identically.
  console.log(`  branch:           ${targetBranch}`);
  console.log(`  reviewers:        ${plan.newReviewers.join(", ")} (now required)`);
  console.log(`  example:          defined-but-unrequired (safe to remove later via a normal review/merge cycle)`);
  if (opts.noPush) {
    console.log(
      `\nLocal merge complete but not pushed. Push with: stamp push ${targetBranch}`,
    );
  } else {
    console.log(
      `\nNext: customize the scaffolded reviewer prompts in .stamp/reviewers/ to match\nyour project (see docs/personas.md), then commit + go through stamp review/merge.`,
    );
  }
}

interface BootstrapPlan {
  targetBranch: string;
  newReviewers: string[];
  /** Map of reviewer name → file path (relative to repo root) → prompt body */
  reviewerFiles: Map<string, { path: string; content: string }>;
  /** Optional mirror.yml content from --from */
  mirrorYml?: string;
  newConfig: StampConfig;
}

function buildPlan(
  current: StampConfig,
  targetBranch: string,
  targetRule: BranchRule,
  opts: BootstrapOptions,
): BootstrapPlan {
  const reviewerFiles = new Map<string, { path: string; content: string }>();
  let mirrorYml: string | undefined;

  let newReviewers: string[];
  let newReviewersConfig: StampConfig["reviewers"];

  if (opts.from) {
    if (opts.reviewers && opts.reviewers.length > 0) {
      throw new Error(
        `--reviewers is incompatible with --from. The seed dir's config.yml is the source of truth for which reviewers get installed.`,
      );
    }
    const seed = readSeedDir(opts.from);
    newReviewers = Object.keys(seed.config.reviewers);
    if (newReviewers.length === 0) {
      throw new Error(
        `seed dir "${opts.from}" has no reviewers configured in config.yml`,
      );
    }
    newReviewersConfig = seed.config.reviewers;
    for (const [name, def] of Object.entries(seed.config.reviewers)) {
      const promptBody = seed.reviewerFiles.get(def.prompt);
      if (promptBody === undefined) {
        throw new Error(
          `seed dir "${opts.from}": reviewer "${name}" references prompt "${def.prompt}" which is not present`,
        );
      }
      reviewerFiles.set(name, { path: def.prompt, content: promptBody });
    }
    mirrorYml = seed.mirrorYml;
  } else {
    const requested = opts.reviewers ?? ["security", "standards", "product"];
    for (const name of requested) {
      if (!(name in STARTER_PROMPTS)) {
        throw new Error(
          `unknown starter reviewer "${name}". Available: ${Object.keys(STARTER_PROMPTS).join(", ")}. ` +
            `For custom reviewers, prepare a seed dir and use --from <dir>.`,
        );
      }
    }
    newReviewers = requested;
    newReviewersConfig = {};
    for (const name of requested) {
      newReviewersConfig[name] = { prompt: `.stamp/reviewers/${name}.md` };
      reviewerFiles.set(name, {
        path: `.stamp/reviewers/${name}.md`,
        content: STARTER_PROMPTS[name]!,
      });
    }
  }

  // Build the new config. Always keep `example` defined-but-unrequired —
  // dropping it from `reviewers:` while the bootstrap merge's attestation
  // still cites `example`'s approval would trip the `required-but-not-defined`
  // post-merge check (see merge.ts). To remove `example` entirely later, run
  // a normal `stamp review` / `stamp merge` cycle once the new reviewers are
  // calibrated.
  const reviewers = { ...newReviewersConfig };
  if (current.reviewers.example) {
    reviewers.example = current.reviewers.example;
  }

  const newConfig: StampConfig = {
    branches: {
      ...current.branches,
      [targetBranch]: {
        required: newReviewers,
        ...(targetRule.required_checks
          ? { required_checks: targetRule.required_checks }
          : {}),
      },
    },
    reviewers,
  };

  return {
    targetBranch,
    newReviewers,
    reviewerFiles,
    mirrorYml,
    newConfig,
  };
}

interface SeedRead {
  config: StampConfig;
  reviewerFiles: Map<string, string>; // path (.stamp/reviewers/X.md) -> content
  mirrorYml?: string;
}

function readSeedDir(seedDir: string): SeedRead {
  if (!existsSync(seedDir) || !statSync(seedDir).isDirectory()) {
    throw new Error(`--from path is not a directory: ${seedDir}`);
  }
  const configPath = join(seedDir, "config.yml");
  if (!existsSync(configPath)) {
    throw new Error(`--from dir missing config.yml: ${configPath}`);
  }
  const reviewersDir = join(seedDir, "reviewers");
  if (!existsSync(reviewersDir) || !statSync(reviewersDir).isDirectory()) {
    throw new Error(`--from dir missing reviewers/ subdirectory: ${reviewersDir}`);
  }
  const yaml = readFileSync(configPath, "utf8");
  const config = parseConfigFromYaml(yaml);

  const reviewerFiles = new Map<string, string>();
  for (const entry of readdirSync(reviewersDir)) {
    const full = join(reviewersDir, entry);
    if (statSync(full).isFile()) {
      reviewerFiles.set(`.stamp/reviewers/${entry}`, readFileSync(full, "utf8"));
    }
  }

  let mirrorYml: string | undefined;
  const mirrorPath = join(seedDir, "mirror.yml");
  if (existsSync(mirrorPath)) {
    mirrorYml = readFileSync(mirrorPath, "utf8");
  }

  return { config, reviewerFiles, mirrorYml };
}

function writeBootstrapFiles(repoRoot: string, plan: BootstrapPlan): void {
  ensureDir(stampConfigDir(repoRoot));
  ensureDir(stampReviewersDir(repoRoot));

  for (const { path, content } of plan.reviewerFiles.values()) {
    const full = join(repoRoot, path);
    ensureDir(dirname(full));
    writeFileSync(full, content);
  }

  if (plan.mirrorYml !== undefined) {
    writeFileSync(join(repoRoot, ".stamp/mirror.yml"), plan.mirrorYml);
  }

  writeFileSync(stampConfigFile(repoRoot), stringifyConfig(plan.newConfig));
}

function printPlan(plan: BootstrapPlan, opts: BootstrapOptions): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`stamp bootstrap — plan`);
  console.log(bar);
  console.log(`  target branch:    ${plan.targetBranch}`);
  console.log(`  source:           ${opts.from ? `seed dir (${opts.from})` : "starter personas"}`);
  console.log(`  new reviewers:    ${plan.newReviewers.join(", ")}`);
  if (plan.mirrorYml !== undefined) {
    console.log(`  mirror.yml:       install from seed dir`);
  }
  console.log(`  example reviewer: keep defined-but-unrequired`);
  console.log(
    `  AGENTS.md:        ${
      opts.agentsMd === false
        ? "skip (--no-agents-md)"
        : "create or update with stamp-protected-repo guidance"
    }`,
  );
  console.log(
    `  CLAUDE.md:        ${
      opts.claudeMd === false
        ? "skip (--no-claude-md)"
        : "create or update (auto-loaded by Claude Code)"
    }`,
  );
  console.log(`  push after merge: ${opts.noPush ? "no" : `yes (to ${opts.remote ?? "origin"})`}`);
  console.log(`  bootstrap branch: ${BOOTSTRAP_BRANCH}`);
  console.log(bar);
}

// ---------- bootstrap-specific git helpers ----------

function workingTreeDirty(cwd: string): boolean {
  return runGit(["status", "--porcelain", "--untracked-files=no"], cwd).trim().length > 0;
}

function branchExists(name: string, cwd: string): boolean {
  // show-ref exits 0 if the ref exists, 1 if not. Use the exit-code form
  // directly rather than try/catch around runGit() because "ref does not
  // exist" isn't an error worth wrapping.
  try {
    execFileSync(
      "git",
      ["show-ref", "--verify", "--quiet", `refs/heads/${name}`],
      { cwd, stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}
