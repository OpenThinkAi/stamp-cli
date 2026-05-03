import { spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import {
  ENV_IDENTIFIER_REGEX,
  EXAMPLE_REVIEWER_PROMPT,
  loadConfig,
  stringifyConfig,
  parseToolsLoose,
  type McpServerDef,
  type ToolSpec,
} from "../lib/config.js";
import {
  openDb,
  recentReviewsByReviewer,
  reviewerStats,
  type ReviewerStats,
} from "../lib/db.js";
import { resolveDiff } from "../lib/git.js";
import { invokeReviewer } from "../lib/reviewer.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampReviewersDir,
  stampStateDbPath,
} from "../lib/paths.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
} from "../lib/reviewerHash.js";
import {
  checkReviewerDrift,
  formatDriftReport,
  LOCK_DRIFT_EXIT,
  LOCK_FILE_VERSION,
  lockFilePath,
  writeLockFile,
  type DriftResult,
  type LockFile,
} from "../lib/reviewerLock.js";

// Names are interpolated into filesystem paths and URL segments. Keep the
// allowed alphabet tight so there's no path-traversal ('../../evil') or
// URL-injection surface. Matches the pattern reviewersAdd has historically
// enforced (alphanumerics + underscore + hyphen), with an added length cap.
const VALID_REVIEWER_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

function requireValidReviewerName(name: string): void {
  if (!VALID_REVIEWER_NAME.test(name)) {
    throw new Error(
      `invalid reviewer name '${name}'. Names must match ${VALID_REVIEWER_NAME.source} ` +
        `— letters, digits, underscores, hyphens; max 64 chars; no leading hyphen.`,
    );
  }
}

export function reviewersList(): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  const names = Object.keys(config.reviewers);
  if (names.length === 0) {
    console.log("No reviewers configured in .stamp/config.yml.");
    return;
  }

  const bar = "─".repeat(72);
  console.log(bar);
  console.log("configured reviewers");
  console.log(bar);

  const maxNameLen = Math.max(...names.map((n) => n.length));
  for (const name of names) {
    const def = config.reviewers[name]!;
    const abs = resolve(repoRoot, def.prompt);
    let annotation = "";
    if (!existsSync(abs)) {
      annotation = "  MISSING";
    } else {
      const size = statSync(abs).size;
      annotation = `  (${size} bytes)`;
    }
    console.log(`  ${name.padEnd(maxNameLen)}   ${def.prompt}${annotation}`);
  }

  console.log(bar);
  console.log("branch rules:");
  for (const [branch, rule] of Object.entries(config.branches)) {
    console.log(`  ${branch}  required: [${rule.required.join(", ")}]`);
  }
  console.log(bar);
}

export function reviewersEdit(name: string): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  const def = config.reviewers[name];
  if (!def) {
    throw new Error(
      `reviewer "${name}" is not configured. Run \`stamp reviewers list\` to see available reviewers.`,
    );
  }

  const target = resolve(repoRoot, def.prompt);
  launchEditor(target);
}

export function reviewersAdd(name: string, opts: { noEdit?: boolean } = {}): void {
  requireValidReviewerName(name);
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  const config = loadConfig(configPath);

  if (config.reviewers[name]) {
    throw new Error(
      `reviewer "${name}" already exists. Use \`stamp reviewers edit ${name}\` to change its prompt.`,
    );
  }

  const promptRel = `.stamp/reviewers/${name}.md`;
  const promptAbs = resolve(repoRoot, promptRel);

  if (existsSync(promptAbs)) {
    // A stale file without a config entry. Prefer not to stomp — prompt the user.
    throw new Error(
      `${promptRel} already exists on disk but is not in config. Either delete the file or add it to config manually.`,
    );
  }

  writeFileSync(
    promptAbs,
    `# ${name}\n\n${EXAMPLE_REVIEWER_PROMPT.split("\n").slice(2).join("\n")}`,
  );

  config.reviewers[name] = { prompt: promptRel };
  writeFileSync(configPath, stringifyConfig(config));

  console.log(`reviewer "${name}" added.`);
  console.log(`  prompt file: ${promptRel}`);
  console.log(`  registered in .stamp/config.yml`);
  console.log();
  console.log(
    "Next: customize the prompt, then add this reviewer to a branch's `required` list",
  );
  console.log("if you want it to gate merges.");

  if (!opts.noEdit) {
    console.log(`\nOpening ${promptRel} in $EDITOR...`);
    launchEditor(promptAbs);
  }
}

export function reviewersRemove(
  name: string,
  opts: { deleteFile?: boolean } = {},
): void {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  const config = loadConfig(configPath);

  const def = config.reviewers[name];
  if (!def) {
    throw new Error(
      `reviewer "${name}" is not configured. Nothing to remove.`,
    );
  }

  // Warn if the reviewer is referenced by any branch rule.
  const referencedBy: string[] = [];
  for (const [branch, rule] of Object.entries(config.branches)) {
    if (rule.required.includes(name)) referencedBy.push(branch);
  }
  if (referencedBy.length > 0) {
    throw new Error(
      `reviewer "${name}" is required by branch(es): ${referencedBy.join(", ")}. ` +
        `Remove it from those branches' \`required\` list in .stamp/config.yml before removing.`,
    );
  }

  delete config.reviewers[name];
  writeFileSync(configPath, stringifyConfig(config));
  console.log(`reviewer "${name}" removed from .stamp/config.yml`);

  if (opts.deleteFile) {
    const promptAbs = resolve(repoRoot, def.prompt);
    if (existsSync(promptAbs)) {
      unlinkSync(promptAbs);
      console.log(`deleted ${def.prompt}`);
    }
  } else {
    console.log(
      `(prompt file ${def.prompt} kept; pass --delete-file to remove it too)`,
    );
  }
}

export async function reviewersTest(
  name: string,
  diff: string,
): Promise<void> {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  if (!config.reviewers[name]) {
    throw new Error(
      `reviewer "${name}" is not configured. Run \`stamp reviewers list\`.`,
    );
  }

  const resolved = resolveDiff(diff, repoRoot);
  if (!resolved.diff.trim()) {
    console.log("No changes in diff; nothing to test.");
    return;
  }

  const bar = "─".repeat(72);
  console.log(`testing "${name}" against ${diff} (not recorded to DB)`);
  console.log(
    `  diff: ${resolved.base_sha.slice(0, 8)} → ${resolved.head_sha.slice(0, 8)}`,
  );
  console.log(`  prompt sourced from working tree (test/iteration use case)`);
  console.log();

  // INTENTIONALLY reads from disk, not base_sha tree. `stamp reviewers test`
  // is the prompt-iteration loop ("$EDITOR security.md → test → re-edit"),
  // so the on-disk version is exactly what the user wants invoked. The
  // base-tree security boundary belongs to `stamp review` / `stamp merge`.
  const def = config.reviewers[name]!;
  const promptPath = join(repoRoot, def.prompt);
  const systemPrompt = readFileSync(promptPath, "utf8");

  const result = await invokeReviewer({
    reviewer: name,
    config,
    repoRoot,
    diff: resolved.diff,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    systemPrompt,
  });

  console.log(bar);
  console.log(`reviewer: ${result.reviewer}`);
  console.log(bar);
  console.log(result.prose);
  console.log(bar);
  console.log(`verdict: ${result.verdict}  (test run — not recorded)`);
  console.log(bar);
}

export function reviewersShow(name: string, opts: { limit: number }): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  if (!config.reviewers[name]) {
    throw new Error(
      `reviewer "${name}" is not configured. Run \`stamp reviewers list\`.`,
    );
  }

  const dbPath = stampStateDbPath(repoRoot);
  if (!existsSync(dbPath)) {
    console.log("No reviews recorded yet (no state.db).");
    return;
  }

  const db = openDb(dbPath);
  let stats: ReviewerStats;
  let recent;
  try {
    stats = reviewerStats(db, name);
    recent = recentReviewsByReviewer(db, name, opts.limit);
  } finally {
    db.close();
  }

  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`reviewer: ${name}`);
  console.log(`prompt:   ${config.reviewers[name]!.prompt}`);
  console.log(bar);
  if (stats.total === 0) {
    console.log("  no verdicts recorded yet");
  } else {
    console.log(`  total verdicts:     ${stats.total}`);
    console.log(
      `  approved:           ${stats.approved}  (${pct(stats.approved, stats.total)}%)`,
    );
    console.log(
      `  changes_requested:  ${stats.changes_requested}  (${pct(stats.changes_requested, stats.total)}%)`,
    );
    console.log(
      `  denied:             ${stats.denied}  (${pct(stats.denied, stats.total)}%)`,
    );
    console.log(`  first seen:         ${stats.first_seen}`);
    console.log(`  last seen:          ${stats.last_seen}`);
  }
  if (recent.length > 0) {
    console.log(bar);
    console.log(`last ${recent.length} verdict${recent.length === 1 ? "" : "s"}:`);
    for (const r of recent) {
      const mark =
        r.verdict === "approved"
          ? "✓"
          : r.verdict === "changes_requested"
            ? "⟳"
            : "✗";
      console.log(
        `  ${mark} ${r.verdict.padEnd(18)} ${r.base_sha.slice(0, 8)} → ${r.head_sha.slice(0, 8)}   ${r.created_at}`,
      );
    }
  }
  console.log(bar);
}

function pct(n: number, total: number): number {
  if (total === 0) return 0;
  return Math.round((n / total) * 100);
}

// --------------------------------------------------------------------------
// fetch + verify (plan Step 3 — remote canonical personas + lock files)
// --------------------------------------------------------------------------

export interface ReviewersFetchOptions {
  /** Value of the --from flag: <source>@<ref>. Source is <owner>/<repo> or
   *  a full GitHub URL; ref is any git ref (tag, branch, commit). */
  from: string;
}

export async function reviewersFetch(
  reviewerName: string,
  opts: ReviewersFetchOptions,
): Promise<void> {
  requireValidReviewerName(reviewerName);
  const repoRoot = findRepoRoot();
  const { source, ref } = parseSourceSpec(opts.from);

  const reviewersDir = stampReviewersDir(repoRoot);
  if (!existsSync(reviewersDir)) {
    throw new Error(
      `${reviewersDir} does not exist — run \`stamp init\` first.`,
    );
  }

  console.log(`fetching reviewer '${reviewerName}' from ${source}@${ref}...`);

  const promptUrl = buildRawUrl(source, ref, `personas/${reviewerName}/prompt.md`);
  const configUrl = buildRawUrl(source, ref, `personas/${reviewerName}/config.yaml`);

  const promptText = await fetchRequired(promptUrl, "prompt.md");
  const configYaml = await fetchOptional(configUrl, "config.yaml");

  // Parse optional tool/MCP config. Keep unknown-shape at the network
  // boundary; validate shape before it reaches the hash. parseToolsLoose
  // accepts both string-shorthand and the object form
  // `{ name, allowed_hosts? }` (see lib/config.ts ToolSpec) without
  // enforcing SAFE_TOOLS — that policy fires when the config is loaded
  // for invocation, not at fetch time.
  let tools: ToolSpec[] | undefined;
  let mcpServers: Record<string, McpServerDef> | undefined;
  if (configYaml !== null) {
    const parsed = (parseYaml(configYaml) ?? {}) as Record<string, unknown>;
    if (Array.isArray(parsed.tools)) {
      tools = parseToolsLoose(parsed.tools);
    }
    if (parsed.mcp_servers !== undefined) {
      mcpServers = validateMcpServersFromSource(parsed.mcp_servers, source, ref);
    }
  }

  // Write prompt to .stamp/reviewers/<name>.md
  const promptPath = join(reviewersDir, `${reviewerName}.md`);
  const promptBytes = Buffer.from(promptText, "utf8");
  writeFileSync(promptPath, promptBytes);

  // Compute hashes from the bytes we just wrote (identical to what verifiers
  // will hash later).
  const lock: LockFile = {
    version: LOCK_FILE_VERSION,
    source,
    ref,
    reviewer: reviewerName,
    prompt_sha256: hashPromptBytes(promptBytes),
    tools_sha256: hashTools(tools),
    mcp_sha256: hashMcpServers(mcpServers),
    fetched_at: new Date().toISOString(),
  };
  writeLockFile(repoRoot, reviewerName, lock);

  // Report.
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`fetched reviewer '${reviewerName}'`);
  console.log(bar);
  console.log(`  source:     ${source}@${ref}`);
  console.log(`  prompt:     ${relative(repoRoot, promptPath)}`);
  console.log(`  lock file:  ${relative(repoRoot, lockFilePath(repoRoot, reviewerName))}`);
  console.log(`  prompt sha: sha256:${lock.prompt_sha256.slice(0, 16)}...`);
  console.log(`  tools sha:  sha256:${lock.tools_sha256.slice(0, 16)}...`);
  console.log(`  mcp sha:    sha256:${lock.mcp_sha256.slice(0, 16)}...`);
  console.log(bar);

  // Tell the user how to wire the reviewer into their config (we deliberately
  // don't auto-modify .stamp/config.yml — the config is the user's declared
  // intent and we don't want fetches to silently rewrite it).
  console.log();
  console.log(`Next: ensure .stamp/config.yml has this reviewer entry:`);
  console.log();
  const yamlBlock = buildConfigYamlHint(reviewerName, tools, mcpServers);
  for (const line of yamlBlock.split("\n")) console.log(`    ${line}`);
  console.log();
  console.log(
    `Run \`stamp reviewers verify\` to check that the on-disk prompt + tools + mcp_servers match the lock (exit ${LOCK_DRIFT_EXIT} on drift).`,
  );
}

export interface ReviewersVerifyOptions {
  /** Optional reviewer name to restrict the check to. */
  only?: string;
}

export function reviewersVerify(opts: ReviewersVerifyOptions): void {
  if (opts.only) requireValidReviewerName(opts.only);
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  const names = opts.only
    ? [opts.only]
    : Object.keys(config.reviewers);

  if (names.length === 0) {
    console.log("No reviewers configured.");
    return;
  }

  console.log(
    `verifying ${names.length} reviewer${names.length === 1 ? "" : "s"} against lock files...`,
  );
  console.log();

  // Compute drift once per reviewer, reuse for the summary and the drift-
  // report pass. Hashing a prompt file + tools/mcp config is cheap, but
  // doing the file I/O twice is sloppy and drifts behavior if the user
  // edits the prompt between the two passes.
  const results = new Map<string, DriftResult>();
  let anyDrift = false;
  let anyLocked = false;

  for (const name of names) {
    const def = config.reviewers[name];
    if (!def) {
      console.error(
        `error: reviewer '${name}' is not in .stamp/config.yml. ` +
          `Add it with \`stamp reviewers add ${name}\` or remove its lock file.`,
      );
      process.exit(1);
    }
    const result = checkReviewerDrift(repoRoot, name, def);
    results.set(name, result);
    if (!result.hasLock) {
      console.log(`  ${name.padEnd(16)} (no lock file — unpinned)`);
      continue;
    }
    anyLocked = true;
    if (result.mismatches.length === 0) {
      console.log(
        `  ✓ ${name.padEnd(16)} clean (${result.lock.source}@${result.lock.ref})`,
      );
    } else {
      anyDrift = true;
      console.log(
        `  ✗ ${name.padEnd(16)} DRIFT (${result.mismatches.map((m) => m.field).join(", ")})`,
      );
    }
  }

  if (!anyLocked) {
    console.log(
      "\nNo lock files present. Run `stamp reviewers fetch <name> --from <source>@<ref>` to pin a reviewer.",
    );
    return;
  }

  if (anyDrift) {
    console.error();
    for (const [name, result] of results) {
      if (result.hasLock && result.mismatches.length > 0) {
        console.error(formatDriftReport(name, result));
        console.error();
      }
    }
    process.exit(LOCK_DRIFT_EXIT);
  }
}

// --------------------------------------------------------------------------
// fetch/verify internals
// --------------------------------------------------------------------------

function parseSourceSpec(from: string): { source: string; ref: string } {
  const at = from.lastIndexOf("@");
  if (at < 1 || at === from.length - 1) {
    throw new Error(
      `--from must be '<source>@<ref>' (e.g. 'acme/stamp-personas@v3.2'); got '${from}'`,
    );
  }
  return { source: from.slice(0, at), ref: from.slice(at + 1) };
}

function buildRawUrl(source: string, ref: string, path: string): string {
  // Refs can legally contain slashes (e.g. 'release/v3.2', 'feature/foo') —
  // don't encodeURIComponent them, since git raw endpoints expect literal
  // slashes in the path segment. Tag and sha refs are slash-free anyway, so
  // skipping encoding is safe for all documented inputs.
  //
  // Shorthand <owner>/<repo> → GitHub raw.
  if (/^[A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*$/.test(source)) {
    return `https://raw.githubusercontent.com/${source}/${ref}/${path}`;
  }
  // Full URL: https only. http:// is rejected because the first fetch is the
  // trust-anchor step — an MITM at that moment pins the attacker's prompt
  // into the lock file and every subsequent fetch of the same (source, ref)
  // would validate against the poisoned hash.
  if (/^https:\/\//.test(source)) {
    return `${source.replace(/\/$/, "")}/${ref}/${path}`;
  }
  if (/^http:\/\//.test(source)) {
    throw new Error(
      `--from source '${source}' uses http://. Plain HTTP is rejected because the initial fetch is MITM-able and pins into the lock file. Use https://.`,
    );
  }
  throw new Error(
    `unsupported --from source '${source}'. Use '<owner>/<repo>' (GitHub) or a full 'https://' URL.`,
  );
}

async function fetchRequired(url: string, label: string): Promise<string> {
  const res = await doFetch(url, label);
  if (res.status === 404) {
    throw new Error(
      `${label} not found at ${url} (HTTP 404). Check the source/ref/reviewer name.`,
    );
  }
  if (!res.ok) {
    throw new Error(
      `failed to fetch ${label} from ${url}: HTTP ${res.status} ${res.statusText}`,
    );
  }
  return await res.text();
}

async function fetchOptional(
  url: string,
  label: string,
): Promise<string | null> {
  const res = await doFetch(url, label);
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(
      `failed to fetch ${label} from ${url}: HTTP ${res.status} ${res.statusText}`,
    );
  }
  return await res.text();
}

async function doFetch(url: string, label: string): Promise<Response> {
  try {
    return await fetch(url);
  } catch (err) {
    throw new Error(
      `failed to fetch ${label} from ${url}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function validateMcpServersFromSource(
  raw: unknown,
  source: string,
  ref: string,
): Record<string, McpServerDef> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(
      `config.yaml from ${source}@${ref}: 'mcp_servers' must be a map of server name → config`,
    );
  }
  const out: Record<string, McpServerDef> = {};
  for (const [name, entry] of Object.entries(raw)) {
    if (!entry || typeof entry !== "object") {
      throw new Error(
        `config.yaml from ${source}@${ref}: mcp_servers.${name} must be an object`,
      );
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.command !== "string" || !e.command) {
      throw new Error(
        `config.yaml from ${source}@${ref}: mcp_servers.${name}.command must be a non-empty string`,
      );
    }
    const def: McpServerDef = { command: e.command };
    if (e.args !== undefined) {
      if (!Array.isArray(e.args)) {
        throw new Error(
          `config.yaml from ${source}@${ref}: mcp_servers.${name}.args must be an array of strings`,
        );
      }
      def.args = e.args.map(String);
    }
    if (e.env !== undefined) {
      if (!e.env || typeof e.env !== "object" || Array.isArray(e.env)) {
        throw new Error(
          `config.yaml from ${source}@${ref}: mcp_servers.${name}.env must be a map of string → string`,
        );
      }
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(e.env)) {
        env[k] = String(v);
      }
      def.env = env;
    }
    if (e.allowed_env !== undefined) {
      if (!Array.isArray(e.allowed_env)) {
        throw new Error(
          `config.yaml from ${source}@${ref}: mcp_servers.${name}.allowed_env must be an array of POSIX env-var identifier strings`,
        );
      }
      const allowed: string[] = [];
      for (const [i, v] of e.allowed_env.entries()) {
        if (typeof v !== "string") {
          throw new Error(
            `config.yaml from ${source}@${ref}: mcp_servers.${name}.allowed_env[${i}] must be a string`,
          );
        }
        if (!ENV_IDENTIFIER_REGEX.test(v)) {
          throw new Error(
            `config.yaml from ${source}@${ref}: mcp_servers.${name}.allowed_env[${i}] "${v}" is not a valid POSIX env-var identifier (must match [A-Za-z_][A-Za-z0-9_]*)`,
          );
        }
        allowed.push(v);
      }
      def.allowed_env = allowed;
    }
    out[name] = def;
  }
  return out;
}

function buildConfigYamlHint(
  reviewerName: string,
  tools: ToolSpec[] | undefined,
  mcpServers: Record<string, McpServerDef> | undefined,
): string {
  const reviewerBlock: Record<string, unknown> = {
    prompt: `.stamp/reviewers/${reviewerName}.md`,
  };
  if (tools && tools.length > 0) reviewerBlock.tools = tools;
  if (mcpServers && Object.keys(mcpServers).length > 0) {
    reviewerBlock.mcp_servers = mcpServers;
  }
  return stringifyYaml({ reviewers: { [reviewerName]: reviewerBlock } }).trimEnd();
}

function launchEditor(path: string): void {
  const editor =
    process.env["EDITOR"] ??
    process.env["VISUAL"] ??
    (process.platform === "win32" ? "notepad" : "vi");
  const result = spawnSync(editor, [path], { stdio: "inherit" });
  if (result.error) {
    throw new Error(
      `failed to launch editor "${editor}": ${result.error.message}`,
    );
  }
  if (result.status !== 0 && result.status !== null) {
    process.exit(result.status);
  }
}

// Keep the old name for backward compatibility in case any external code imports.
export { launchEditor as _launchEditor };
// Silence unused helper import warnings; readFileSync is reserved for future
// features like validating prompt-file syntax. Keep the import surface small.
void readFileSync;
