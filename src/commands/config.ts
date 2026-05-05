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
  writeUserConfig,
  type UserConfig,
} from "../lib/userConfig.js";
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
  const next: UserConfig = { reviewers: { ...existing.reviewers } };
  delete next.reviewers[reviewer];
  const path = writeUserConfig(next);
  console.log(`cleared reviewers.${reviewer}`);
  console.log(`wrote ${path}`);
}

export function runConfigReviewersShow(): void {
  const path = userConfigPath();
  if (!existsSync(path)) {
    console.log(`note: no per-user stamp config (${path} does not exist).`);
    console.log(
      `      Defaults will apply on next \`stamp init\` or \`stamp review\`:`,
    );
    for (const [name, id] of Object.entries(DEFAULT_REVIEWER_MODELS)) {
      console.log(`        ${name}: ${id}  (default)`);
    }
    console.log(
      `      Pin a different model: \`stamp config reviewers set <reviewer> <model-id>\``,
    );
    return;
  }
  // Re-load with throw-on-malformed semantics — the operator explicitly
  // asked to see the config, so a parse error is exactly what they need
  // to see (vs. the resolver's silent fall-through).
  const cfg = loadUserConfig() ?? { reviewers: {} };
  console.log(`config: ${path}`);
  const names = Object.keys(cfg.reviewers).sort();
  if (names.length === 0) {
    console.log(`(no reviewer overrides; SDK default model in use for every reviewer)`);
    console.log(
      `Pin one with: \`stamp config reviewers set <reviewer> <model-id>\``,
    );
    return;
  }
  console.log(`reviewers:`);
  const maxNameLen = Math.max(...names.map((n) => n.length));
  for (const name of names) {
    const id = cfg.reviewers[name]!;
    const tag =
      DEFAULT_REVIEWER_MODELS[name] === id
        ? "  (matches default)"
        : DEFAULT_REVIEWER_MODELS[name]
        ? `  (default: ${DEFAULT_REVIEWER_MODELS[name]})`
        : "";
    console.log(`  ${name.padEnd(maxNameLen)}  ${id}${tag}`);
  }
  // Surface defaults the operator hasn't pinned, so `show` is a complete
  // picture of "what's about to happen" rather than just "what I've
  // touched."
  const unpinned = Object.keys(DEFAULT_REVIEWER_MODELS).filter(
    (n) => !(n in cfg.reviewers),
  );
  if (unpinned.length > 0) {
    console.log(`unpinned (will use default at review time):`);
    for (const name of unpinned) {
      console.log(`  ${name.padEnd(maxNameLen)}  ${DEFAULT_REVIEWER_MODELS[name]}  (default)`);
    }
  }
}

function loadOrEmpty(): UserConfig {
  return loadUserConfig() ?? { reviewers: {} };
}
