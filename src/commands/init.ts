import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureAgentsMd, type AgentsMdMode } from "../lib/agentsMd.js";
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
        `For server-gated enforcement: deploy a stamp server (see docs/quickstart-server.md), ` +
        `provision a repo on it (\`ssh git@<stamp-host> new-stamp-repo <name>\`), clone the result, ` +
        `then run \`stamp bootstrap\` (NOT \`stamp init\`) on the clone.\n` +
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
  console.log();

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
