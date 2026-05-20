import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ensureAgentsMd, ensureClaudeMd, type AgentsMdMode } from "../lib/agentsMd.js";
import { maybePrintDeprecationNotice } from "../lib/deprecationNotice.js";
import { isPathTracked, runGit } from "../lib/git.js";
import {
  applyStampRuleset,
  checkGhAvailable,
  lookupAuthenticatedUserId,
  lookupRepoOwnerType,
  parseGithubOriginUrl,
  type BypassActor,
} from "../lib/ghRuleset.js";
import { readLineSync } from "../lib/humanMerge.js";
import { readOteamConfig, patchStampHost } from "../lib/oteamConfig.js";
import { classifyRemote, describeShape, parseOrgRepoFromUrl } from "../lib/remote.js";
import { loadServerConfig } from "../lib/serverConfig.js";
import {
  DEFAULT_CONFIG,
  DEFAULT_PRODUCT_PROMPT,
  DEFAULT_SECURITY_PROMPT,
  DEFAULT_STANDARDS_PROMPT,
  EXAMPLE_REVIEWER_PROMPT,
  MINIMAL_CONFIG,
  parseConfigFromYaml,
  stringifyConfig,
} from "../lib/config.js";
import { parseReviewServerUrl } from "../lib/sshReviewClient.js";
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
import { loadOrCreateUserConfig } from "../lib/userConfig.js";

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
   * When false, skip the oteam-detection prompt that offers to fill
   * `stamp.host` in ~/.open-team/config.json when a local stamp server is
   * configured. Default true (offer the prompt when conditions are met).
   * The prompt is also silently skipped in non-TTY contexts regardless of
   * this flag. Corresponds to the `--no-oteam` CLI flag.
   */
  oteam?: boolean;
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
  /**
   * When false, skip dropping `.github/workflows/stamp-verify.yml` (the
   * workflow that runs `stamp/verify-attestation@v1` on every PR).
   *
   * Default behavior, opt-in by mode:
   *   - forge-direct: drop the workflow (PR-check mode is the natural fit)
   *   - server-gated: SKIP — the stamp server enforces at the receive
   *     hook; a duplicate PR-side check would be redundant
   *   - local-only: drop the workflow (operators using local-only often
   *     mirror to GitHub for visibility; the check makes that mirror
   *     useful as a gate too)
   *
   * Setting `prCheck: false` opts out for any mode. Setting it to `true`
   * forces the drop even in server-gated mode (rare; only useful if the
   * operator wants belt-and-suspenders enforcement on a github.com
   * mirror of their server-gated repo).
   */
  prCheck?: boolean;
  /**
   * When true, scaffold the Shape 2 (PR mode) auto-mirror workflow at
   * `.github/workflows/stamp-mirror.yml`. The workflow pushes the repo
   * to stamp-server on every GitHub push, using `secrets.STAMP_MIRROR_KEY`
   * (an org-level secret the operator registers once).
   *
   * Independent of the `--mode` flag: `--pr-mode` is the Shape 2 fit, but
   * the operator may legitimately drop the workflow into any repo whose
   * remote is github.com. Template placeholders are filled from
   * `.stamp/config.yml`'s `review_server` (host + port) and
   * `git remote get-url origin` (org + repo). When `review_server` is
   * not yet configured, the file is written with `<STAMP_SERVER_HOST>` /
   * `<STAMP_SERVER_PORT>` literals so the operator can run AGT-342's
   * `--migrate-to-server-attested` first and re-run with `--force`.
   *
   * Idempotent: if a `stamp-mirror.yml` already exists at the target
   * path, init reports "exists" and leaves it alone. `prModeForce: true`
   * overwrites unconditionally — escape hatch for re-running after
   * `review_server` was added.
   */
  prMode?: boolean;
  /**
   * When true and `prMode` is also true, overwrite an existing
   * `.github/workflows/stamp-mirror.yml` rather than leaving it
   * untouched. Default false (idempotent re-init preserves operator
   * customizations). Useful when re-running after configuring
   * `review_server` so the host/port placeholders get filled in.
   */
  prModeForce?: boolean;
  /**
   * GitHub `org/repo` that hosts the `stamp/verify-attestation` action
   * referenced from `.github/workflows/stamp-verify.yml`. Default
   * `OpenThinkAi/stamp-cli` — set when consuming a fork so the workflow
   * tracks the fork instead of the upstream. Caller is responsible for
   * shape validation; this code path only string-substitutes it into
   * the template.
   */
  actionSource?: string;
}

/**
 * Upstream source of the `stamp/verify-attestation` action. Operators
 * consuming a fork override via `--action-source <org/repo>`. Exported
 * so tests + the workflow renderer agree on the default.
 */
export const DEFAULT_ACTION_SOURCE = "OpenThinkAi/stamp-cli";

export function runInit(opts: InitOptions = {}): void {
  // Bridge-release deprecation banner (AGT-346). Printed to stderr before
  // any of init's own structured output so it never gets buried under the
  // success-summary block. Suppress with STAMP_SUPPRESS_DEPRECATION=1.
  maybePrintDeprecationNotice();

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

  // Per-user reviewer-model config (~/.stamp/config.yml). On a fresh
  // install this writes Sonnet defaults for security/standards/product;
  // on a re-init it leaves any operator customisation alone (idempotent).
  // Reviewer-spawning code reads this at review time and threads `model`
  // through to the agent SDK; absence falls back to the SDK's default,
  // so older clones continue to work unchanged.
  const userCfg = loadOrCreateUserConfig();

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

  // PR-check mode workflow drop. Defaults to "yes for forge-direct +
  // local-only, no for server-gated" — see InitOptions.prCheck JSDoc
  // for the rationale. Operator overrides any default with explicit
  // true/false. Result is reported in the summary block below so the
  // operator sees what landed on disk.
  const prCheckResult = maybeWriteVerifyWorkflow(
    repoRoot,
    opts.prCheck,
    effectiveMode,
    opts.actionSource ?? DEFAULT_ACTION_SOURCE,
  );

  // PR-mode auto-mirror workflow (Shape 2 of the server-attested-reviews
  // deployment shapes — GitHub primary, stamp-server does reviews).
  // Opt-in only — operators have to ask for this with `--pr-mode`
  // because the mirror workflow pushes to stamp-server on every GitHub
  // push and requires an org-level `STAMP_MIRROR_KEY` secret to be set
  // up. The walkthrough text printed below this block tells the
  // operator what to do next.
  const prModeResult = opts.prMode
    ? maybeWritePrModeMirrorWorkflow(repoRoot, { force: opts.prModeForce })
    : { action: "skipped" as const, path: PR_MODE_WORKFLOW_PATH, substitution: null };

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
  if (prCheckResult.action !== "skipped") {
    console.log(
      `  PR check:    ${prCheckResult.action} ${prCheckResult.path} ` +
        `(stamp/verify-attestation@${VERIFY_ACTION_REF})`,
    );
  }
  if (prModeResult.action !== "skipped") {
    const subSuffix = prModeResult.substitution
      ? ` (host: ${prModeResult.substitution.host}:${prModeResult.substitution.port}, repo: ${prModeResult.substitution.org}/${prModeResult.substitution.repo})`
      : " (placeholders unfilled — configure review_server then re-run with --force)";
    console.log(
      `  PR mirror:   ${prModeResult.action} ${prModeResult.path}${subSuffix}`,
    );
  }
  console.log(
    `  models:      ${userCfg.path}${userCfg.created ? " (created — Sonnet defaults; tweak with `stamp config reviewers set <name> <model-id>`)" : " (existing)"}`,
  );
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

  // Oteam cross-link: offer to fill stamp.host in ~/.open-team/config.json
  // when oteam is detected and a local stamp server is configured. One-way
  // file read + file patch; no runtime dep on @openthink/team.
  if (opts.oteam !== false) {
    maybeOfferOteamHostFill();
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

  // PR-check setup hint. Only fires when we just dropped (or already
  // had) the workflow file AND the operator hasn't done the
  // branch-protection wiring yet. We can't detect the latter without
  // hitting the GitHub API, so the hint always prints when a workflow
  // is in play; it's idempotent reading material on re-init.
  if (prCheckResult.action !== "skipped") {
    console.log(
      "PR-check mode notes:\n" +
        "  - The workflow runs the verifier on every PR but does NOT block\n" +
        "    merge by itself. Wire it into branch protection so green-check\n" +
        "    is required before merge:\n" +
        "      Settings → Branches → main → Protect → Require status checks →\n" +
        "      add `stamp verify` (the workflow's job name) as required.\n" +
        "  - Operator workflow per PR: stamp review → stamp attest --into main\n" +
        "    --push origin → open PR → check goes green → human merges.\n",
    );
  }

  // PR-mode walkthrough. Print whenever the workflow exists on disk
  // (just-written OR pre-existing). The walkthrough is mostly out-of-
  // band setup (keypair generation, org-secret registration on
  // github.com) so a re-init operator sees the checklist again and
  // can use it to confirm they finished step 3.
  if (prModeResult.action !== "skipped") {
    printPrModeWalkthrough(prModeResult);
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

  // Privacy disclosure: applies to every init path (first-time setup,
  // additional-machine key deposit, already-trusted machine), since any
  // operator who proceeds will run stamp review. Pull out of the
  // first-time branch so the keyDeposited / already-trusted paths see it
  // too — the per-repo first-run `note:` is the safety net but init is
  // the right time to surface the data-flow contract.
  console.log();
  console.log(
    "Privacy: every `stamp review` ships the diff to Anthropic via the Claude",
  );
  console.log(
    "Agent SDK. See README \"Data flow / privacy\" for what's sent and how to",
  );
  console.log(
    "opt out of the per-repo notice (STAMP_SUPPRESS_LLM_NOTICE=1).",
  );

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

  // Pick a bypass actor type that GitHub will actually honor:
  //   - personal repos: actor_type="User", id=gh-authenticated user
  //   - org repos: actor_type="OrganizationAdmin", id=1 (the magic constant
  //     for "any org admin"). actor_type="User" silently no-ops on org
  //     repos — GitHub accepts the API call but the bypass entry doesn't
  //     evaluate.
  const ownerType = lookupRepoOwnerType(parsed.owner, parsed.repo);
  if (ownerType === null) {
    console.log(
      `note: GitHub Ruleset auto-apply skipped — couldn't determine whether ${parsed.owner}/${parsed.repo} is a personal or org repo.`,
    );
    console.log(`      For manual setup, see docs/github-ruleset-setup.md.`);
    console.log();
    return;
  }
  const actor: BypassActor =
    ownerType === "Organization"
      ? { type: "OrganizationAdmin", id: 1 }
      : { type: "User", id: user.id };
  const actorDescription =
    actor.type === "OrganizationAdmin"
      ? "any org admin (your gh-authed user must be one to push as bypass)"
      : `${user.login}, id ${user.id}`;

  const result = applyStampRuleset(parsed.owner, parsed.repo, actor);
  switch (result.status) {
    case "created":
      console.log(
        `GitHub Ruleset: created stamp-mirror-only on ${parsed.owner}/${parsed.repo} (bypass actor: ${actorDescription}).`,
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
 * Offer to fill oteam's `stamp.host` config when all three conditions hold:
 *   1. ~/.open-team/config.json exists and stamp.host is not yet set
 *   2. ~/.stamp/server.yml is configured with a local stamp host
 *   3. stdin/stdout are both TTYs (non-interactive runs skip silently)
 *
 * On yes, atomically patches ~/.open-team/config.json. On no, or when any
 * condition is unmet, does nothing — no error, no warning (AC #4).
 */
function maybeOfferOteamHostFill(): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return;

  let oteamCfg: unknown;
  try {
    oteamCfg = readOteamConfig();
  } catch {
    return; // malformed oteam config — skip silently
  }
  if (oteamCfg === null) return; // oteam not installed/configured

  const cfg = oteamCfg as Record<string, unknown>;
  const stamp = cfg.stamp as Record<string, unknown> | undefined;
  if (stamp?.host) return; // stamp.host already set

  let serverCfg: ReturnType<typeof loadServerConfig>;
  try {
    serverCfg = loadServerConfig();
  } catch {
    return; // malformed server.yml — skip silently
  }
  if (!serverCfg) return; // no local stamp server configured

  const host = serverCfg.host;
  process.stdout.write(
    `Set oteam's \`stamp.host\` to "${host}"? [y/N] `,
  );
  const answer = readLineSync().trim().toLowerCase();
  if (answer !== "y" && answer !== "yes") return;

  try {
    patchStampHost(host);
    console.log(
      `oteam config: stamp.host set to "${host}" in ~/.open-team/config.json`,
    );
    console.log();
  } catch (err) {
    // Patch failure is non-fatal — surface the error as a warning so the
    // user can fix it manually, but don't abort the init.
    console.log(
      `warning: could not patch ~/.open-team/config.json: ${err instanceof Error ? err.message : String(err)}`,
    );
    console.log();
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


/**
 * stamp/verify-attestation Action ref pinned by stamp-cli releases.
 * Operators who care about action stability bump this in lockstep with
 * the stamp-cli release that contains the matching action.yml. Bumping
 * stamp-cli without bumping this ref would point users at an Action
 * that doesn't exist (or worse, that semantically differs from the
 * stamp version they have installed locally).
 */
export const VERIFY_ACTION_REF = "v1.6.1";

/**
 * Drop the `.github/workflows/stamp-verify.yml` workflow file when
 * appropriate for the resolved deployment mode. Returns a small
 * { action, path } object so the init summary block can report what
 * happened without re-deriving the answer.
 */
export function maybeWriteVerifyWorkflow(
  repoRoot: string,
  prCheckOpt: boolean | undefined,
  effectiveMode: AgentsMdMode,
  actionSource: string = DEFAULT_ACTION_SOURCE,
): { action: "wrote" | "exists" | "skipped"; path: string } {
  const path = ".github/workflows/stamp-verify.yml";
  const fullPath = join(repoRoot, path);

  // Mode-aware default: forge-direct + local-only get the workflow;
  // server-gated doesn't (server enforces at the receive hook). The
  // operator's explicit prCheckOpt overrides the default in either
  // direction.
  const defaultForMode = effectiveMode !== "server-gated";
  const shouldWrite = prCheckOpt ?? defaultForMode;
  if (!shouldWrite) return { action: "skipped", path };

  if (existsSync(fullPath)) {
    // Idempotent re-init: don't clobber operator edits to a workflow
    // they may have customized (added concurrency, fork-PR conditions,
    // etc.). The summary line distinguishes "exists" from "wrote" so
    // a re-init is honest about not touching the file.
    return { action: "exists", path };
  }

  ensureDir(dirname(fullPath));
  writeFileSync(fullPath, renderVerifyWorkflow(actionSource));
  return { action: "wrote", path };
}

/**
 * Path of the Shape 2 (PR mode) auto-mirror workflow file written by
 * `stamp init --pr-mode`. Exported so tests + the summary-line emitter
 * stay in sync with the actual destination.
 */
export const PR_MODE_WORKFLOW_PATH = ".github/workflows/stamp-mirror.yml";

/** Substituted values used when rendering the PR-mode mirror workflow. */
export interface PrModeSubstitution {
  host: string;
  port: number;
  org: string;
  repo: string;
}

/** Result of attempting to drop the PR-mode mirror workflow file. */
export interface PrModeMirrorResult {
  action: "wrote" | "exists" | "skipped";
  path: string;
  /** What `derivePrModeSubstitution` resolved at the time of this call.
   *  Non-null when both `.stamp/config.yml`'s `review_server` parsed and
   *  `origin` parsed into `(org, repo)`. Null otherwise — the workflow
   *  is then rendered with `<STAMP_SERVER_HOST>` / `<STAMP_SERVER_PORT>`
   *  / `<REPO_ORG>` / `<REPO_NAME>` placeholders.
   *
   *  This is a *snapshot of the derivation*, not an assertion about the
   *  bytes on disk. When `action === "exists"`, this may be non-null
   *  while the existing file still has stale placeholders (or vice
   *  versa). Use `--pr-mode-force` to refresh the file. */
  substitution: PrModeSubstitution | null;
}

/**
 * Drop `.github/workflows/stamp-mirror.yml` from a template, substituting
 * the stamp-server endpoint (from `.stamp/config.yml`'s `review_server`)
 * and the GitHub repo (from `git remote get-url origin`). Returns "wrote",
 * "exists", or "skipped" so the caller can report what landed.
 *
 * Idempotent by default — if the target file already exists, we leave it
 * alone (operator may have customized concurrency, fork-PR conditions,
 * etc.). Pass `force: true` to overwrite — useful when re-running after
 * configuring `review_server` so the host/port placeholders get filled in.
 *
 * The walkthrough text (keypair generation, secret registration) is the
 * caller's job; see `printPrModeWalkthrough` below.
 */
export function maybeWritePrModeMirrorWorkflow(
  repoRoot: string,
  opts: { force?: boolean } = {},
): PrModeMirrorResult {
  const fullPath = join(repoRoot, PR_MODE_WORKFLOW_PATH);

  // Try to derive substitution values. Best-effort: if `.stamp/config.yml`
  // doesn't have a `review_server` yet (operator may run --pr-mode before
  // AGT-342's --migrate-to-server-attested) we still write the workflow,
  // but with `<STAMP_SERVER_HOST>` / `<STAMP_SERVER_PORT>` literals so
  // the operator can fill them in by hand or re-run with --force after
  // configuring review_server.
  const substitution = derivePrModeSubstitution(repoRoot);

  if (existsSync(fullPath) && !opts.force) {
    return { action: "exists", path: PR_MODE_WORKFLOW_PATH, substitution };
  }

  ensureDir(dirname(fullPath));
  writeFileSync(fullPath, renderMirrorWorkflow(substitution));
  return { action: "wrote", path: PR_MODE_WORKFLOW_PATH, substitution };
}

/**
 * Best-effort: derive `(host, port, org, repo)` from this repo's
 * `.stamp/config.yml` and `git remote get-url origin`. Returns null when
 * either side can't be confidently parsed — the caller then renders the
 * workflow with raw placeholders so the operator can edit by hand.
 *
 * Pulls (host, port) from any branch rule's `review_server` URL — the
 * first one that parses cleanly wins. Phase 1 of server-attested
 * reviews has a single per-branch URL by design (see "Deferred to
 * Phase 2" in docs/plans/server-attested-reviews.md), so "first match
 * wins" is the same as "the only match." If a future schema adds
 * per-reviewer overrides, this helper stays correct because the
 * branch-rule URL remains the canonical mirror endpoint.
 */
export function derivePrModeSubstitution(
  repoRoot: string,
): PrModeSubstitution | null {
  let host: string | null = null;
  let port: number | null = null;
  try {
    const configFile = join(repoRoot, ".stamp", "config.yml");
    if (existsSync(configFile)) {
      const cfg = parseConfigFromYaml(readFileSync(configFile, "utf8"));
      for (const rule of Object.values(cfg.branches)) {
        if (rule.review_server) {
          try {
            const url = parseReviewServerUrl(rule.review_server);
            host = url.host;
            port = url.port;
            break;
          } catch {
            // Malformed URL — skip this rule, try the next. Don't fail
            // the whole substitution; config validation will surface
            // the error to the operator separately.
          }
        }
      }
    }
  } catch {
    // Malformed config — fall through to placeholder rendering.
  }

  let org: string | null = null;
  let repo: string | null = null;
  try {
    const url = runGit(["remote", "get-url", "origin"], repoRoot).trim();
    const parsed = parseOrgRepoFromUrl(url);
    if (parsed) {
      org = parsed.org;
      repo = parsed.repo;
    }
  } catch {
    // No origin configured, or git failure — fall through.
  }

  if (host === null || port === null || org === null || repo === null) {
    return null;
  }
  return { host, port, org, repo };
}

/**
 * Build the PR-mode auto-mirror workflow body. When `sub` is null, the
 * template is rendered with literal `<PLACEHOLDER>` markers so the
 * operator can fill them in by hand and re-run init with --force.
 *
 * Defense-in-depth: substituted values (host/port/org/repo) are emitted
 * as YAML `env:` variables on the run step and referenced as `"$VAR"`
 * inside the shell — they never appear as command tokens. Even if the
 * upstream parsers (`parseReviewServerUrl`, `parseOrgRepoFromUrl`)
 * grow a regression that lets a metacharacter slip through, the
 * generated shell still sees the values as quoted variable expansions,
 * not as syntactically-active tokens.
 *
 * Inline rather than file-loaded because the template is short and
 * version-bound to this release (matching the pattern of
 * `renderVerifyWorkflow` above).
 */
export function renderMirrorWorkflow(sub: PrModeSubstitution | null): string {
  // Substituted values are emitted as YAML `env:` entries on the run
  // step (see "Defense-in-depth" in the JSDoc above). Either a parsed
  // value or a literal `<PLACEHOLDER>` marker the operator hand-fills.
  // Either way the value never becomes a shell command token.
  const host = sub ? sub.host : "<STAMP_SERVER_HOST>";
  const port = sub ? String(sub.port) : "<STAMP_SERVER_PORT>";
  const org = sub ? sub.org : "<REPO_ORG>";
  const repo = sub ? sub.repo : "<REPO_NAME>";

  return [
    "name: stamp-mirror",
    "",
    "# Shape 2 (PR mode) auto-mirror: pushes every GitHub push to the",
    "# stamp-server bare repo over SSH, so `stamp-review` (the server-",
    "# attested-reviews verb) can see the new commits. See",
    "# docs/migration-1.x-to-2.x.md for the full Shape 2 setup.",
    "#",
    "# Auth: org-level secret STAMP_MIRROR_KEY (an Ed25519 private key",
    "# whose pubkey is registered on stamp-server via",
    "# `stamp-mint-invite mirror --role member`). Scope the secret to",
    "# repos using stamp at the GitHub org level — once, not per repo.",
    "",
    "on:",
    "  push:",
    "    branches: ['**']",
    "    tags: ['**']",
    "",
    "permissions:",
    "  # Read-only is sufficient: we push to stamp-server over SSH",
    "  # using STAMP_MIRROR_KEY, not back to github via GITHUB_TOKEN.",
    "  contents: read",
    "",
    "jobs:",
    "  mirror:",
    "    name: mirror to stamp-server",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 5",
    "    steps:",
    "      - name: checkout",
    "        uses: actions/checkout@v4",
    "        with:",
    "          # Full history so `git push --mirror` ships every ref",
    "          # the server needs to resolve `base..head` diffs.",
    "          fetch-depth: 0",
    "      - name: push to stamp-server",
    "        env:",
    "          STAMP_MIRROR_KEY: ${{ secrets.STAMP_MIRROR_KEY }}",
    "          # Substituted values flow through env: so the shell never",
    "          # sees them as command tokens — defense-in-depth against",
    "          # any future parser regression that lets a shell",
    "          # metacharacter slip past the upstream URL validators.",
    `          STAMP_SERVER_HOST: ${yamlScalar(host)}`,
    `          STAMP_SERVER_PORT: ${yamlScalar(port)}`,
    `          STAMP_REPO_ORG: ${yamlScalar(org)}`,
    `          STAMP_REPO_NAME: ${yamlScalar(repo)}`,
    "        run: |",
    "          set -euo pipefail",
    "          if [ -z \"${STAMP_MIRROR_KEY:-}\" ]; then",
    "            echo 'error: STAMP_MIRROR_KEY is not set.' >&2",
    "            echo 'Register the org secret at:' >&2",
    "            echo '  https://github.com/organizations/<your-org>/settings/secrets/actions/new' >&2",
    "            echo 'Name: STAMP_MIRROR_KEY. Scope: repos using stamp.' >&2",
    "            exit 1",
    "          fi",
    "          mkdir -p ~/.ssh",
    "          chmod 0700 ~/.ssh",
    "          # Write the key atomically with restrictive perms: a subshell",
    "          # umask 077 creates the file already 0600, eliminating the race",
    "          # between `>` (which would use the runner's umask, typically 0644)",
    "          # and a follow-up `chmod`. Matters on self-hosted runners where",
    "          # other processes share the user; near-zero blast radius on the",
    "          # GitHub-hosted ephemeral VMs. Trailing newline kept — some",
    "          # openssh versions reject keys without one.",
    "          (umask 077 && printf '%s\\n' \"$STAMP_MIRROR_KEY\" > ~/.ssh/stamp_mirror_key)",
    "          # Pin the host key on first contact. TOFU on every job;",
    "          # for higher assurance, REPLACE the keyscan with a known-",
    "          # host fingerprint your operator verified out-of-band",
    "          # (e.g. `ssh-keygen -lf <pubkey>`). The walkthrough that",
    "          # `stamp init --pr-mode` prints calls this out as a",
    "          # post-setup hardening step.",
    "          ssh-keyscan -p \"$STAMP_SERVER_PORT\" \"$STAMP_SERVER_HOST\" \\",
    "            >> ~/.ssh/known_hosts 2>/dev/null",
    "          # `|| true` on remote-add because rerunning the job (e.g.",
    "          # workflow re-run) finds an existing remote and would fail",
    "          # otherwise. The fetch URL is fixed by template; nothing",
    "          # gets clobbered by tolerating the add-already-exists case.",
    "          git remote add stamp-server \\",
    "            \"ssh://git@${STAMP_SERVER_HOST}:${STAMP_SERVER_PORT}/srv/git/${STAMP_REPO_ORG}/${STAMP_REPO_NAME}.git\" \\",
    "            || true",
    "          GIT_SSH_COMMAND=\"ssh -i ~/.ssh/stamp_mirror_key -o IdentitiesOnly=yes -o UserKnownHostsFile=~/.ssh/known_hosts\" \\",
    "            git push --mirror stamp-server",
    "",
  ].join("\n");
}

/**
 * Emit a value as a YAML scalar that round-trips back to the same
 * string regardless of its contents. Used to inject substituted
 * host/port/org/repo into `env:` entries in the generated workflow
 * without risking YAML parser hiccups when the value contains a `<`,
 * a `-` lead, or any other character YAML treats specially in plain
 * scalar form. We always double-quote, escaping `\` and `"` per the
 * YAML 1.2 double-quoted-scalar grammar. This is the minimal subset
 * needed for our four substituted strings (which are already shape-
 * validated by `parseReviewServerUrl` / `parseOrgRepoFromUrl`); we
 * deliberately do NOT use the `yaml` package's `stringify` here
 * because the surrounding template is hand-built line-by-line and
 * pulling a YAML stringifier in for four scalars is overkill.
 */
function yamlScalar(value: string): string {
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `"${escaped}"`;
}

/**
 * Print the post-scaffold walkthrough to stdout. Walks the operator
 * through the one-time org-level setup (keypair generation, registering
 * the pubkey on stamp-server, depositing the private key as an org
 * secret on GitHub) plus the per-repo finish step (commit + push the
 * workflow file). Re-printed on every `--pr-mode` re-init so the
 * checklist stays discoverable.
 */
function printPrModeWalkthrough(result: PrModeMirrorResult): void {
  const subSummary = result.substitution
    ? `stamp-server at ssh://git@${result.substitution.host}:${result.substitution.port}, mirror path /srv/git/${result.substitution.org}/${result.substitution.repo}.git`
    : "stamp-server host/port and org/repo placeholders unfilled — see below";

  // Walkthrough verb must match `action` so it agrees with the
  // `PR mirror:` summary line emitted earlier. "Wrote" on an "exists"
  // result would produce a direct factual contradiction in the same
  // stdout stream.
  const verb = result.action === "wrote" ? "Wrote" : "Found existing";

  console.log("PR-mode (Shape 2) mirror workflow notes:");
  console.log(`  ${verb} ${result.path} (${subSummary}).`);
  console.log();
  if (!result.substitution) {
    console.log(
      "  Placeholders not substituted because `.stamp/config.yml` has no",
    );
    console.log(
      "  `review_server` configured (or `origin` couldn't be parsed). Either:",
    );
    console.log(
      "    - run `stamp init --migrate-to-server-attested` first to add",
    );
    console.log(
      "      `review_server`, then re-run `stamp init --pr-mode --pr-mode-force`,",
    );
    console.log(
      "    - or hand-edit the <STAMP_SERVER_HOST> / <STAMP_SERVER_PORT> /",
    );
    console.log(
      "      <REPO_ORG> / <REPO_NAME> markers in the workflow file.",
    );
    console.log();
  }
  console.log("  Next steps (one-time per org, not per repo):");
  console.log();
  console.log(
    "    1. Generate an Ed25519 mirror keypair locally:",
  );
  console.log(
    "         ssh-keygen -t ed25519 -f stamp-mirror -N '' -C 'stamp-mirror@<your-org>'",
  );
  console.log();
  console.log(
    "    2. Register the public half (`stamp-mirror.pub`) on stamp-server",
  );
  console.log("       via the invite flow:");
  if (result.substitution) {
    console.log(
      `         ssh -p ${result.substitution.port} git@${result.substitution.host} \\`,
    );
  } else {
    console.log("         ssh -p <port> git@<stamp-server-host> \\");
  }
  console.log(
    "           stamp-mint-invite mirror --role member",
  );
  console.log(
    "       Accept the invite with the pubkey from step 1 to create the",
  );
  console.log(
    "       `mirror` service-account user on stamp-server.",
  );
  console.log();
  console.log(
    "    3. Add the PRIVATE half (`stamp-mirror`) as an org-level secret",
  );
  console.log("       on GitHub:");
  console.log(
    "         https://github.com/organizations/<your-org>/settings/secrets/actions/new",
  );
  console.log(
    "       Name: STAMP_MIRROR_KEY. Scope: repos using stamp.",
  );
  console.log();
  console.log(
    "    4. Commit and push the workflow file. The first push will trigger",
  );
  console.log(
    "       the mirror; subsequent pushes mirror automatically.",
  );
  console.log();
  console.log(
    "    5. (Recommended) Pin the stamp-server SSH host key in the",
  );
  console.log(
    "       workflow. The template uses `ssh-keyscan` for first-contact",
  );
  console.log(
    "       TOFU on every run, which an active MitM at push time could",
  );
  console.log(
    "       defeat. To harden, capture the fingerprint out-of-band:",
  );
  if (result.substitution) {
    console.log(
      `         ssh-keyscan -p ${result.substitution.port} ${result.substitution.host}`,
    );
  } else {
    console.log("         ssh-keyscan -p <port> <stamp-server-host>");
  }
  console.log(
    "       Verify it matches what your operator independently knows,",
  );
  console.log(
    "       then commit the line into `~/.ssh/known_hosts` in the",
  );
  console.log(
    "       workflow run-step (replacing the `ssh-keyscan` invocation).",
  );
  console.log();
  console.log(
    "  Re-running `stamp init --pr-mode` is idempotent — the existing",
  );
  console.log(
    "  workflow file is left alone. Pass `--pr-mode-force` to overwrite",
  );
  console.log(
    "  (useful after configuring `review_server` so placeholders fill in).",
  );
  console.log();
}

/**
 * Build the workflow file body. Pulled into its own function so a test
 * can verify the action reference, the trigger, and the permissions
 * shape without re-rendering or string-grepping. Inline rather than
 * file-loaded because the template is short and version-bound to this
 * release.
 */
export function renderVerifyWorkflow(
  actionSource: string = DEFAULT_ACTION_SOURCE,
): string {
  return [
    "name: stamp verify",
    "",
    `# Runs stamp/verify-attestation@${VERIFY_ACTION_REF} on every PR.`,
    "# Wire `stamp verify` (this job's name) into branch protection",
    "# Required Status Checks to make a green attestation a merge",
    "# precondition.",
    "",
    "on:",
    "  pull_request:",
    "    branches: [main]",
    "",
    "permissions:",
    "  # checkout + read .stamp/{config,trusted-keys}/ from the base ref",
    "  contents: read",
    "  # for the workflow's check-run summary on the PR",
    "  checks: write",
    "",
    "jobs:",
    "  stamp-verify:",
    "    name: stamp verify",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 5",
    "    steps:",
    "      - name: checkout",
    "        uses: actions/checkout@v4",
    "        with:",
    "          # Full history so the action can fetch the base ref's tree",
    "          # and resolve refs/stamp/attestations/*. Shallow clones",
    "          # would force per-step refetches.",
    "          fetch-depth: 0",
    "      - name: stamp/verify-attestation",
    `        uses: ${actionSource}/.github/actions/verify-attestation@${VERIFY_ACTION_REF}`,
    "",
  ].join("\n");
}
