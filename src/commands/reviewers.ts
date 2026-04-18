import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadConfig } from "../lib/config.js";
import { findRepoRoot, stampConfigFile } from "../lib/paths.js";

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
  const editor =
    process.env["EDITOR"] ??
    process.env["VISUAL"] ??
    (process.platform === "win32" ? "notepad" : "vi");

  const result = spawnSync(editor, [target], {
    stdio: "inherit",
  });

  if (result.error) {
    throw new Error(
      `failed to launch editor "${editor}": ${result.error.message}`,
    );
  }

  if (result.status !== 0 && result.status !== null) {
    process.exit(result.status);
  }
}
