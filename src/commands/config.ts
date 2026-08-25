/**
 * `stamp config reviewers <set|clear|show>` — manage the per-user
 * reviewer-model selections in `~/.stamp/config.yml` without making
 * the operator hand-edit YAML.
 *
 * Three subcommands:
 *
 *   stamp config reviewers set <reviewer> <model-id>   pin a reviewer's model
 *   stamp config reviewers clear <reviewer>            remove the pin (or `--all`)
 *   stamp config reviewers show                        print resolved per-reviewer config
 *
 * `show` reports the resolved BACKEND per reviewer, not just a model id: a
 * value with the `local:` scheme (or `STAMP_REVIEWER_BACKEND=local` in the
 * environment) routes to an OpenAI-compatible endpoint rather than the
 * Anthropic agent SDK, and before AGT-1137 nothing on this surface said so.
 *
 * Reviewer names are validated against the same regex `stamp reviewers add`
 * uses (alphanumerics + _ -; max 64 chars; no leading hyphen). Model IDs
 * are accepted as opaque strings — the agent SDK takes any string and we
 * don't want to lag every Anthropic release with a hardcoded enum — but
 * shape-checked to reject obviously-broken inputs (whitespace, control
 * chars) at config-write rather than at API-call time.
 *
 * `~/.stamp/config.yml` is per-user, mode 0o600 under a 0o700 ~/.stamp.
 * It's intentionally NOT committed, NOT hash-pinned by reviewer
 * attestations, and lives separately from per-repo `.stamp/config.yml`
 * because cost/speed tradeoffs are operator infrastructure rather than
 * committed review policy. (See the AGT-109 design notes for the full
 * rationale.)
 */

import { existsSync } from "node:fs";
import {
  DEFAULT_REVIEWER_MODELS,
  deleteUserConfig,
  isValidModelId,
  isValidReviewerName,
  loadUserConfig,
  resolveReviewerBackendFrom,
  writeUserConfig,
  type ReviewerBackend,
  type UserConfig,
} from "../lib/userConfig.js";
import { LOCAL_DEFAULT_BASE_URL } from "../lib/localReviewClient.js";
import { userConfigPath } from "../lib/paths.js";
import { UsageError } from "./serverRepo.js";

export interface ReviewersSetOptions {
  reviewer: string;
  modelId: string;
}

export interface ReviewersClearOptions {
  reviewer?: string;
  all?: boolean;
}

export function runConfigReviewersSet(opts: ReviewersSetOptions): void {
  if (!isValidReviewerName(opts.reviewer)) {
    throw new UsageError(
      `invalid reviewer name '${opts.reviewer}'. Names must be alphanumerics + ` +
        `'_' / '-', max 64 chars, no leading hyphen — same shape as ` +
        `\`stamp reviewers add\` accepts.`,
    );
  }
  const id = opts.modelId.trim();
  if (id === "") {
    throw new UsageError(
      `model id is required and must be a non-empty string ` +
        `(e.g. 'claude-sonnet-4-6' or 'claude-opus-4-7')`,
    );
  }
  if (!isValidModelId(id)) {
    throw new UsageError(
      `model id '${opts.modelId}' has an invalid shape — expected a token like ` +
        `'claude-sonnet-4-6' or 'claude-opus-4-7'. The agent SDK treats this as an ` +
        `opaque string, so a typo here will fail at API-call time rather than at ` +
        `config-write — but stamp rejects shapes with whitespace or control chars.`,
    );
  }

  const existing = loadOrEmpty();
  const prior = existing.reviewers[opts.reviewer];
  const next: UserConfig = {
    ...existing,
    reviewers: { ...existing.reviewers, [opts.reviewer]: id },
  };
  const path = writeUserConfig(next);

  if (prior === id) {
    console.log(`reviewers.${opts.reviewer} = ${id} (unchanged)`);
  } else if (prior) {
    console.log(`reviewers.${opts.reviewer}: ${prior} -> ${id}`);
  } else {
    console.log(`reviewers.${opts.reviewer} = ${id} (new)`);
  }
  console.log(`wrote ${path}`);
}

export function runConfigReviewersClear(opts: ReviewersClearOptions): void {
  if (opts.all && opts.reviewer) {
    throw new UsageError(
      `\`stamp config reviewers clear\`: pass either <reviewer> or --all, not both`,
    );
  }
  if (!opts.all && !opts.reviewer) {
    throw new UsageError(
      `\`stamp config reviewers clear\`: pass <reviewer> to clear one entry or --all to remove the whole config`,
    );
  }

  if (opts.all) {
    const removed = deleteUserConfig();
    const path = userConfigPath();
    if (removed) {
      console.log(`removed ${path}`);
    } else {
      console.log(`note: ${path} does not exist; nothing to remove`);
    }
    return;
  }

  const reviewer = opts.reviewer!;
  if (!isValidReviewerName(reviewer)) {
    throw new UsageError(
      `invalid reviewer name '${reviewer}'. Names must be alphanumerics + ` +
        `'_' / '-', max 64 chars, no leading hyphen — same shape as ` +
        `\`stamp reviewers add\` accepts.`,
    );
  }
  const existing = loadOrEmpty();
  if (!(reviewer in existing.reviewers)) {
    console.log(`note: reviewers.${reviewer} is not set; nothing to clear`);
    return;
  }
  const next: UserConfig = { ...existing, reviewers: { ...existing.reviewers } };
  delete next.reviewers[reviewer];
  const path = writeUserConfig(next);
  console.log(`cleared reviewers.${reviewer}`);
  console.log(`wrote ${path}`);
}

export function runConfigReviewersShow(): void {
  const path = userConfigPath();
  const exists = existsSync(path);
  // Re-load with throw-on-malformed semantics — the operator explicitly
  // asked to see the config, so a parse error is exactly what they need
  // to see (vs. the resolver's silent fall-through).
  const cfg = exists ? loadUserConfig() ?? { reviewers: {} } : null;

  // What `stamp review` will actually resolve against. With no file yet, the
  // next review calls `loadOrCreateUserConfig` and writes the defaults BEFORE
  // resolving — so resolving against those defaults is what makes this
  // command answer "what will run" rather than "what have I typed" (AGT-1137
  // AC3).
  const effective: UserConfig = cfg ?? {
    reviewers: { ...DEFAULT_REVIEWER_MODELS },
  };

  if (!exists) {
    console.log(`note: no per-user stamp config (${path} does not exist).`);
    console.log(
      `      Defaults will apply on next \`stamp init\` or \`stamp review\`:`,
    );
    for (const [name, id] of Object.entries(DEFAULT_REVIEWER_MODELS)) {
      console.log(
        `        ${name}: ${id}  ${backendTag(resolveReviewerBackendFrom(effective, name))}  (default)`,
      );
    }
    console.log(
      `      Pin a different model: \`stamp config reviewers set <reviewer> <model-id>\``,
    );
    printBackendFooter(effective);
    return;
  }

  console.log(`config: ${path}`);
  const names = Object.keys(effective.reviewers).sort();
  if (names.length === 0) {
    console.log(`(no reviewer overrides; SDK default model in use for every reviewer)`);
    console.log(
      `Pin one with: \`stamp config reviewers set <reviewer> <model-id>\``,
    );
    printBackendFooter(effective);
    return;
  }
  console.log(`reviewers:`);
  const maxNameLen = Math.max(...names.map((n) => n.length));
  for (const name of names) {
    const id = effective.reviewers[name]!;
    const tag =
      DEFAULT_REVIEWER_MODELS[name] === id
        ? "  (matches default)"
        : DEFAULT_REVIEWER_MODELS[name]
        ? `  (default: ${DEFAULT_REVIEWER_MODELS[name]})`
        : "";
    const backend = backendTag(resolveReviewerBackendFrom(effective, name));
    console.log(`  ${name.padEnd(maxNameLen)}  ${id}  ${backend}${tag}`);
  }
  // Surface defaults the operator hasn't pinned, so `show` is a complete
  // picture of "what's about to happen" rather than just "what I've
  // touched."
  const unpinned = Object.keys(DEFAULT_REVIEWER_MODELS).filter(
    (n) => !(n in effective.reviewers),
  );
  if (unpinned.length > 0) {
    console.log(`unpinned (will use default at review time):`);
    for (const name of unpinned) {
      // Resolved against the config as it stands, which is the honest answer
      // for an unpinned name: the resolver sees no entry, so the kind is
      // whatever the environment forces (agent SDK unless
      // STAMP_REVIEWER_BACKEND says otherwise) — the model column keeps
      // reporting the default this line has always reported.
      const backend = backendTag(resolveReviewerBackendFrom(effective, name));
      console.log(
        `  ${name.padEnd(maxNameLen)}  ${DEFAULT_REVIEWER_MODELS[name]}  ${backend}  (default)`,
      );
    }
  }
  printBackendFooter(effective);
}

/**
 * Compact render of the backend a reviewer will ACTUALLY run on (AGT-1137
 * AC3). Before this, `show` printed a bare model id under a command
 * description that said "Anthropic model" — which was simply wrong for any
 * reviewer configured with the `local:` scheme or running under
 * `STAMP_REVIEWER_BACKEND=local`.
 *
 * The endpoint is printed for the OpenAI-compatible path because it is the
 * operator-visible part of "what reviewed this" — and the EFFECTIVE endpoint
 * at that, with the adapter's own default already resolved, so an unset
 * `local_endpoint:` shows the URL that will be hit rather than a blank. The
 * Agent SDK path has no such handle: the SDK owns its transport.
 */
function backendTag(backend: ReviewerBackend): string {
  if (backend.kind === "anthropic") return "[anthropic]";
  const endpoint = backend.endpoint ?? LOCAL_DEFAULT_BASE_URL;
  return `[local model=${backend.model} @ ${endpoint}]`;
}

/**
 * Footer notes that apply to the whole listing: the per-run env override (if
 * armed) and the quality asymmetry of the non-Anthropic path.
 *
 * The asymmetry note fires only when at least one reviewer actually resolves
 * to the local backend. It is deliberately printed rather than left implicit:
 * the one-shot path has no tool loop and no repo reads, so a verdict from it
 * is not the same artifact as an Agent-SDK verdict even at an identical
 * model tier, and a provenance UI that implied equivalence would be worse
 * than none.
 */
function printBackendFooter(cfg: UserConfig): void {
  const override = process.env.STAMP_REVIEWER_BACKEND?.trim();
  if (override) {
    console.log(
      `note: STAMP_REVIEWER_BACKEND=${override} is set in this environment — ` +
        `it overrides the per-reviewer choice above for every run from this shell.`,
    );
  }
  const anyLocal = Object.keys(cfg.reviewers).some(
    (name) => resolveReviewerBackendFrom(cfg, name).kind === "local",
  );
  if (anyLocal) {
    console.log(
      `note: [local ...] reviewers run one shot against an OpenAI-compatible ` +
        `endpoint — no tool loop, no repo reads, no MCP. Their verdicts gate ` +
        `\`stamp merge\` exactly like Anthropic ones; the review is not equivalent.`,
    );
  }
}

function loadOrEmpty(): UserConfig {
  return loadUserConfig() ?? { reviewers: {} };
}
