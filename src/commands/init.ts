import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureAgentsMd, ensureClaudeMd, type AgentsMdMode } from "../lib/agentsMd.js";
import { isPathTracked, runGit } from "../lib/git.js";
import {
  applyStampRuleset,
  checkGhAvailable,
  lookupAuthenticatedUserId,
  parseGithubOriginUrl,
} from "../lib/ghRuleset.js";
import { classifyRemote, describeShape } from "../lib/remote.js";
import {
  DEFAULT_CONFIG,
  DEFAULT_PRODUCT_PROMPT,
  DEFAULT_SECURITY_PROMPT,
  DEFAULT_STANDARDS_PROMPT,
  EXAMPLE_REVIEWER_PROMPT,
  MINIMAL_CONFIG,
  stringifyConfig,
} from "../lib/config.js";
import { openDb } from "../lib/db.js";
import {
  ensureUserKeypair,
  publicKeyFingerprintFilename,
} from "../lib/keys.js";
import {
  ensureDir,
  findRepoRoot,
  stampConfigDir,
  stampConfigFile,
  stampReviewersDir,
  stampStateDbPath,
  stampTrustedKeysDir,
} from "../lib/paths.js";

export interface InitOptions {
  /**
   * When true, scaffold a single placeholder `example` reviewer and require
   * only it. When false (default), scaffold three starter reviewers
   * (security / standards / product) and require all three.
   */
  minimal?: boolean;
  /**
   * When false, skip creating or updating AGENTS.md at the repo root.
   * Default true (writes/refreshes the marker-delimited stamp section so a
   * future agent dropped into the repo sees the gate model). Opt-out for
   * projects that maintain their own AGENTS.md discipline.
   */
  agentsMd?: boolean;
  /**
   * When false, skip creating or updating CLAUDE.md at the repo root.
   * Default true. CLAUDE.md is auto-loaded by Claude Code into the model's
   * context; AGENTS.md generally is not, so the CLAUDE.md write exists to
   * make sure a Claude-Code agent that never explicitly opens AGENTS.md
   * still sees the "use stamp flow, don't push directly" rule.
   */
  claudeMd?: boolean;
  /**
   * When false, skip the auto bootstrap commit (the one that adds .stamp/ +
   * AGENTS.md + CLAUDE.md to a fresh repo). Default true. The bootstrap
   * commit is the chicken-and-egg moment — there's nothing on main to
   * review against — so stamp init handles it directly. Opt out if you
   * want to commit the scaffold yourself (e.g. squash with other changes).
   */
  bootstrapCommit?: boolean;
  /**
   * When false, skip auto-applying the GitHub Ruleset to a forge-direct
   * github.com origin. Default true. Requires `gh` installed and
   * authenticated. Skipped silently for non-github / non-forge origins.
   */
  ghProtect?: boolean;
  /**
   * Deployment shape this repo is being initialized for.
   *
   * - "server-gated": the user has a stamp server fronting this repo. Origin
   *   should be the stamp server's bare repo. Init refuses if origin is a
   *   public forge (GitHub etc.) directly — that case wants `stamp bootstrap`
   *   on a clone of a server-provisioned repo, not `stamp init`.
   * - "local-only": no server in the picture. Init proceeds with a louder
   *   warning and the AGENTS.md content reflects "advisory, not enforced."
   * - undefined (default): classify origin and act accordingly. Forge-direct
   *   gets a prominent warning but doesn't block (back-compat for users
   *   who've been running `stamp init` this way).
   */
  mode?: AgentsMdMode;
  /** Remote name to inspect for deployment-shape detection. Default "origin". */
  remote?: string;
}

export function runInit(opts: InitOptions = {}): void {
  const repoRoot = findRepoRoot();
  const configDir = stampConfigDir(repoRoot);
  const configFile = stampConfigFile(repoRoot);
  const reviewersDir = stampReviewersDir(repoRoot);
  const trustedKeysDir = stampTrustedKeysDir(repoRoot);
  const stateDbPath = stampStateDbPath(repoRoot);

  // Resolve the effective deployment mode FIRST. If the user explicitly
  // asked for server-gated but origin is a public forge, we want to fail
  // before we've written anything — surfacing the misconfiguration loudly
  // rather than scaffolding a config that the AGENTS.md will then lie
  // about.
  const remoteName = opts.remote ?? "origin";
  const remoteClass = classifyRemote(remoteName, repoRoot);
  const { effectiveMode, warnings } = resolveMode(opts.mode, remoteClass);

  if (opts.mode === "server-gated" && remoteClass.shape === "forge-direct") {
    throw new Error(
      `--mode server-gated requires origin to be a stamp server, but ${describeShape(remoteClass)}.\n` +
        `\n` +
        `For server-gated enforcement, the recommended one-command path is:\n` +
        `  stamp provision <name> --org <github-org>\n` +
        `(needs ~/.stamp/server.yml with your stamp server's host + port, or --server <host>:<port>).\n` +
        `That command handles the bare-repo creation, clone, bootstrap merge, GitHub mirror, and Ruleset.\n` +
        `\n` +
        `For local-only / advisory use against this GitHub repo: re-run with \`stamp init --mode local-only\`. ` +
        `That mode is honest about the lack of server-side enforcement (signed merges still work, ` +
        `but \`git push origin main\` will not be rejected by the remote).`,
    );
  }

  const alreadyHasConfig = existsSync(configFile);

  ensureDir(configDir);
  ensureDir(reviewersDir);
  ensureDir(trustedKeysDir);

  if (!alreadyHasConfig) {
    if (opts.minimal) {
      writeFileSync(configFile, stringifyConfig(MINIMAL_CONFIG));
      writeFileSync(join(reviewersDir, "example.md"), EXAMPLE_REVIEWER_PROMPT);
    } else {
      writeFileSync(configFile, stringifyConfig(DEFAULT_CONFIG));
      writeFileSync(
        join(reviewersDir, "security.md"),
        DEFAULT_SECURITY_PROMPT,
      );
      writeFileSync(
        join(reviewersDir, "standards.md"),
        DEFAULT_STANDARDS_PROMPT,
      );
      writeFileSync(
        join(reviewersDir, "product.md"),
        DEFAULT_PRODUCT_PROMPT,
      );
    }
  }

  const { keypair, created: keyCreated } = ensureUserKeypair();

  const pubKeyPath = join(
    trustedKeysDir,
    publicKeyFingerprintFilename(keypair.fingerprint),
  );
  const keyDeposited = !existsSync(pubKeyPath);
  if (keyDeposited) {
    writeFileSync(pubKeyPath, keypair.publicKeyPem);
  }

  const dbExisted = existsSync(stateDbPath);
  const db = openDb(stateDbPath);
  db.close();

  // Ensure AGENTS.md carries the stamp guidance section unless the operator
  // opted out with --no-agents-md. The content branches on effectiveMode —
  // server-gated promises rejection, local-only is honest that pushes are
  // unenforced. Lying to a future agent is worse than the smaller diff.
  const agentsMdAction =
    opts.agentsMd === false
      ? "skipped"
      : ensureAgentsMd(repoRoot, effectiveMode);
  const claudeMdAction =
    opts.claudeMd === false ? "skipped" : ensureClaudeMd(repoRoot);

  const scaffoldOrSync = alreadyHasConfig ? "sync" : "scaffold";
  console.log(
    scaffoldOrSync === "scaffold"
      ? `stamp initialized (scaffolded fresh repo${opts.minimal ? " — minimal mode, single placeholder reviewer" : " with three starter reviewers"}).\n`
      : "stamp initialized (synced to existing .stamp/ config).\n",
  );
  console.log(`  repo root:   ${repoRoot}`);
  console.log(`  mode:        ${effectiveMode}${opts.mode ? "" : " (auto-detected)"}`);
  // Generic "remote:" label — describeShape's prose already carries the
  // remote name, so a `origin:` label here would read `origin: origin pushes...`.
  console.log(`  remote:      ${describeShape(remoteClass)}`);
  console.log(
    `  config:      ${configFile}${alreadyHasConfig ? " (existing)" : " (created)"}`,
  );
  console.log(`  trust store: ${trustedKeysDir}/`);
  console.log(
    `  state db:    ${stateDbPath}${dbExisted ? " (existing)" : " (created)"}`,
  );
  console.log(
    `  your key:    ${keypair.fingerprint} ${keyCreated ? "(generated)" : "(existing)"}`,
  );
  if (agentsMdAction !== "unchanged" && agentsMdAction !== "skipped") {
    console.log(
      `  AGENTS.md:   ${agentsMdAction} at repo root (${effectiveMode} guidance)`,
    );
  }
  if (claudeMdAction !== "unchanged" && claudeMdAction !== "skipped") {
    console.log(
      `  CLAUDE.md:   ${claudeMdAction} at repo root (auto-loaded by Claude Code)`,
    );
  }
  console.log();

  // Bootstrap commit: if .stamp/config.yml isn't tracked yet, this is the
  // first time stamp is being added to this repo. The chicken-and-egg
  // problem is that there's nothing on main to review against — `stamp
  // review` would have no base. So just commit the scaffolding files
  // directly and push. Every commit AFTER this one goes through the stamp
  // flow normally. Skipping this step (--no-bootstrap-commit) is the
  // escape hatch for users who want to squash with other changes.
  if (opts.bootstrapCommit !== false) {
    printBootstrapCommitResult(runBootstrapCommit(repoRoot, scaffoldOrSync));
  }

  // GitHub Ruleset: if origin is github.com directly AND `gh` is available,
  // apply the stamp-mirror-only ruleset that locks main to the bypass actor
  // (the gh-authenticated user). This is the GitHub-side guardrail that
  // makes "you can git push origin main bypassing stamp" actually false at
  // the remote, even in local-only mode.
  const ghProtectOpt = opts.ghProtect !== false;
  if (
    ghProtectOpt &&
    remoteClass.shape === "forge-direct" &&
    remoteClass.forge === "github.com" &&
    remoteClass.url
  ) {
    applyGitHubRulesetWithReporting(remoteClass.url);
  }

  // Print any deployment-shape warnings AFTER the summary. They're advisory
  // when no --mode flag was passed (back-compat), so don't drown the success
  // message in red text.
  for (const warning of warnings) {
    console.error(warning);
    console.error();
  }

  if (scaffoldOrSync === "scaffold") {
    if (effectiveMode === "local-only") {
      console.log(
        "Local-only mode — your stamp config is committed but NOT enforced server-side.",
      );
      console.log(
        "Direct `git push origin main` will succeed. To enforce, deploy a stamp",
      );
      console.log(
        "server (see docs/quickstart-server.md) and re-init with --mode server-gated.",
      );
      console.log();
    }
    console.log("Next steps:");
    if (opts.minimal) {
      console.log(
        "  1. Replace .stamp/reviewers/example.md with your own reviewer prompt.",
      );
      console.log("  2. Or add more reviewers: `stamp reviewers add <name>`.");
    } else {
      console.log(
        "  1. Read the scaffolded prompts in .stamp/reviewers/ — they're",
      );
      console.log(
        "     starting points calibrated for generic TS/JS projects; customize",
      );
      console.log("     for your codebase. See docs/personas.md for guidance.");
      console.log(
        "  2. Optionally add `required_checks` to .stamp/config.yml (e.g.",
      );
      console.log(`     \`npm run build\`, \`npm run typecheck\`).`);
    }
    console.log("  3. Commit the .stamp/ directory.");
    console.log(
      "  4. Share your public key (in .stamp/trusted-keys/) with any other",
    );
    console.log("     machines that will push to this repo.");
  } else if (keyDeposited) {
    console.log(
      `Your public key was deposited at ${pubKeyPath}.`,
    );
    console.log(
      `Commit + push it so the remote will accept merges signed by this machine.`,
    );
  } else {
    console.log(
      "Your key is already in .stamp/trusted-keys/. You're ready to review + merge.",
    );
  }

  // Loud agent-imperative footer. Prints regardless of mode — both
  // server-gated (where it's redundant but harmless) and local-only (where
  // the agent IS the enforcement and easily skips the rule by accident).
  // The most common failure mode is an agent running `stamp init` and then
  // immediately doing `git commit && git push origin main` because nothing
  // told it not to.
  if (agentsMdAction !== "skipped" || claudeMdAction !== "skipped") {
    console.log();
    const bar = "─".repeat(72);
    console.log(bar);
    console.log("note: AI agents — read AGENTS.md at the repo root before any git command.");
    console.log();
    console.log("This repo is stamp-protected. Direct `git commit` to main and direct");
    console.log("`git push origin main` are violations of the process, even when the");
    console.log("remote accepts them. The required flow is:");
    console.log();
    console.log("  git checkout -b feature; <edit/commit on feature>;");
    console.log("  stamp review --diff main..feature; stamp merge feature --into main;");
    console.log("  git push origin main  (or `stamp push main` if origin is a stamp server).");
    console.log();
    console.log("Full reference: AGENTS.md (and CLAUDE.md) at the repo root.");
    console.log(bar);
  }
}

/**
 * If `.stamp/config.yml` isn't tracked yet (first-time stamp setup on this
 * repo), commit the scaffolding files directly to the current branch and
 * push. This is the bootstrap exception — there's no prior state to review
 * against, so the chicken-and-egg can't be resolved by going through the
 * stamp flow. Every commit AFTER this one follows the normal cycle.
 *
 * For sync-mode runs (re-running stamp init on an existing stamp repo),
 * skips because `.stamp/config.yml` is already tracked.
 */
type BootstrapResult =
  | { kind: "did-commit" }
  | { kind: "did-commit-and-push" }
  | { kind: "skipped-already-tracked" }
  | { kind: "skipped-no-changes" }
  | { kind: "push-failed"; error: string };

function runBootstrapCommit(
  repoRoot: string,
  scaffoldOrSync: "scaffold" | "sync",
): BootstrapResult {
  // Already-tracked check: `.stamp/config.yml` is the canary. Tracked → not
  // a bootstrap moment, even if we just rewrote AGENTS.md/CLAUDE.md.
  if (scaffoldOrSync === "sync" || isPathTracked(".stamp/config.yml", repoRoot)) {
    return { kind: "skipped-already-tracked" };
  }

  // Stage the bootstrap files. AGENTS.md and CLAUDE.md may not exist if
  // --no-agents-md / --no-claude-md was passed; `git add` of a missing
  // pathspec exits non-zero, so add files conditionally.
  const toAdd = [".stamp"];
  if (existsSync(join(repoRoot, "AGENTS.md"))) toAdd.push("AGENTS.md");
  if (existsSync(join(repoRoot, "CLAUDE.md"))) toAdd.push("CLAUDE.md");
  runGit(["add", ...toAdd], repoRoot);

  // Are there actually any changes to commit? `git diff --cached --quiet`
  // exits 0 when there are no staged changes, 1 when there are. We use a
  // try/catch on the throw because runGit treats non-zero exits as throws,
  // which is the wrong polarity for this query.
  let hasStagedChanges = false;
  try {
    runGit(["diff", "--cached", "--quiet"], repoRoot);
  } catch {
    hasStagedChanges = true;
  }
  if (!hasStagedChanges) return { kind: "skipped-no-changes" };

  runGit(
    [
      "commit",
      "-m",
      "stamp: bootstrap config (one-time exception — every later commit goes through stamp review/merge)",
    ],
    repoRoot,
  );

  // Push if origin is configured. Don't fail the whole init if push fails;
  // the user can push manually. Surface the actual git error on failure
  // so the user/agent can act on it (auth issue, network, etc.).
  try {
    runGit(["remote", "get-url", "origin"], repoRoot);
  } catch {
    return { kind: "did-commit" }; // committed locally but no remote to push to
  }

  try {
    // Need to know the current branch to push it. HEAD is the safe choice
    // here — works for "main", "master", or whatever branch the user is on.
    const branch = runGit(["rev-parse", "--abbrev-ref", "HEAD"], repoRoot).trim();
    runGit(["push", "origin", branch], repoRoot);
    return { kind: "did-commit-and-push" };
  } catch (err) {
    return {
      kind: "push-failed",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function printBootstrapCommitResult(result: BootstrapResult): void {
  switch (result.kind) {
    case "did-commit-and-push":
      console.log(
        "Bootstrap commit: created and pushed to origin. Every commit from now on goes through stamp review/merge.",
      );
      break;
    case "did-commit":
      console.log(
        "Bootstrap commit: created locally (no `origin` remote configured). Push when you've added one.",
      );
      break;
    case "push-failed":
      console.log(
        "warning: bootstrap commit created locally but `git push origin` failed.",
      );
      console.log(`         underlying error: ${result.error}`);
      console.log(
        "         Resolve auth/network/branch-protection and run `git push origin` manually.",
      );
      break;
    case "skipped-no-changes":
      // Quiet: nothing to commit means the scaffolding was already current.
      break;
    case "skipped-already-tracked":
      // Quiet: re-running stamp init on an existing stamp repo. Any updates
      // to AGENTS.md/CLAUDE.md are unstaged for the user to review/commit
      // through the normal stamp flow.
      break;
  }
}

/**
 * Apply the stamp-mirror-only GitHub Ruleset to the origin repo. Skips
 * silently if `gh` isn't available (printing a clear note that points the
 * operator at the manual setup doc as a fallback).
 */
function applyGitHubRulesetWithReporting(remoteUrl: string): void {
  const parsed = parseGithubOriginUrl(remoteUrl);
  if (!parsed) {
    // classifyRemote thought this was github.com but the URL doesn't parse
    // — odd but recoverable. Skip silently.
    return;
  }

  const ghCheck = checkGhAvailable();
  if (!ghCheck.available) {
    console.log(
      `note: GitHub Ruleset auto-apply skipped — ${ghCheck.reason}.`,
    );
    console.log(
      `      For manual setup, see docs/github-ruleset-setup.md.`,
    );
    console.log();
    return;
  }

  const user = lookupAuthenticatedUserId();
  if (!user) {
    console.log(
      `note: GitHub Ruleset auto-apply skipped — couldn't look up the gh-authenticated user.`,
    );
    console.log(
      `      Try \`gh auth status\` to confirm authentication, then re-run \`stamp init\`.`,
    );
    console.log();
    return;
  }

  const result = applyStampRuleset(parsed.owner, parsed.repo, user.id);
  switch (result.status) {
    case "created":
      console.log(
        `GitHub Ruleset: created stamp-mirror-only on ${parsed.owner}/${parsed.repo} (bypass actor: ${user.login}, id ${user.id}).`,
      );
      console.log(
        `                Direct \`git push origin main\` from any other identity will now be rejected by GitHub.`,
      );
      console.log();
      break;
    case "exists":
      console.log(
        `GitHub Ruleset: stamp-mirror-only already present on ${parsed.owner}/${parsed.repo} (id ${result.rulesetId}). Not modified.`,
      );
      console.log();
      break;
    case "failed":
      console.log(
        `warning: GitHub Ruleset auto-apply failed: ${result.error}`,
      );
      console.log(
        `         For manual setup, see docs/github-ruleset-setup.md.`,
      );
      console.log();
      break;
  }
}

/**
 * Resolve the effective deployment mode from the user's --mode flag and the
 * detected origin shape. Returns the mode plus any warnings to print to the
 * user — warnings fire when --mode wasn't passed and the detected shape
 * suggests a footgun (forge-direct without an explicit local-only ack, or
 * unset/unknown remote when an explicit choice would help).
 *
 * Hard error case (--mode server-gated + forge-direct origin) is handled by
 * the caller, BEFORE any files are written. This helper handles the softer
 * warn-and-proceed paths.
 */
function resolveMode(
  userMode: AgentsMdMode | undefined,
  remoteClass: ReturnType<typeof classifyRemote>,
): { effectiveMode: AgentsMdMode; warnings: string[] } {
  const warnings: string[] = [];

  // Explicit local-only is always honored. The user is acknowledging the
  // lack of enforcement deliberately.
  if (userMode === "local-only") {
    return { effectiveMode: "local-only", warnings };
  }

  // Explicit server-gated is honored unless origin is forge-direct (caller
  // converts that to a hard error before reaching here).
  if (userMode === "server-gated") {
    return { effectiveMode: "server-gated", warnings };
  }

  // Auto-detect path. Choose the mode that matches the detected shape so the
  // resulting AGENTS.md content is honest about what's actually enforced.
  switch (remoteClass.shape) {
    case "stamp-server":
      return { effectiveMode: "server-gated", warnings };

    case "forge-direct":
      warnings.push(
        `warning: ${describeShape(remoteClass)}.\n` +
          `         Defaulting to --mode local-only because there's no stamp server in this picture.\n` +
          `         The committed .stamp/ config will NOT be enforced — direct \`git push origin main\`\n` +
          `         will succeed against this remote.\n` +
          `         To enforce: deploy a stamp server (docs/quickstart-server.md) and re-run with\n` +
          `         --mode server-gated. To silence this warning: pass --mode local-only explicitly.`,
      );
      return { effectiveMode: "local-only", warnings };

    case "unset":
      // No remote configured yet. Same honest-default reasoning as the
      // unknown branch: we can't promise enforcement, so don't write
      // AGENTS.md content that does. The user will likely `git remote add
      // origin ...` after init; if they point at a stamp server they should
      // re-run with --mode server-gated to refresh the AGENTS.md content.
      warnings.push(
        `note: ${describeShape(remoteClass)}.\n` +
          `      Defaulting to --mode local-only because no remote means no detectable\n` +
          `      server-side enforcement. If you're about to point this at a stamp server,\n` +
          `      re-run with --mode server-gated after \`git remote add\` so the generated\n` +
          `      AGENTS.md content matches.`,
      );
      return { effectiveMode: "local-only", warnings };

    case "unknown":
      // Honest default: we don't know whether this remote enforces stamp,
      // so don't write AGENTS.md content that promises rejection. If origin
      // really is a stamp server (custom domain, self-hosted, etc.), the
      // user can re-run with --mode server-gated to get the gated content.
      // Mirroring the forge-direct branch's philosophy: "Lying to a future
      // agent is worse than the smaller content difference."
      warnings.push(
        `note: ${describeShape(remoteClass)}.\n` +
          `      Defaulting to --mode local-only because stamp can't confirm the remote\n` +
          `      enforces the gate. If origin really is a stamp server, re-run with\n` +
          `      --mode server-gated to get the AGENTS.md content that promises rejection.`,
      );
      return { effectiveMode: "local-only", warnings };
  }
}
