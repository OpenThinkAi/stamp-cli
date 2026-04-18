import { existsSync, mkdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

export function findRepoRoot(startFrom: string = process.cwd()): string {
  let current = resolve(startFrom);
  while (true) {
    if (existsSync(join(current, ".git"))) return current;
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(
        `not inside a git repository (searched up from ${startFrom})`,
      );
    }
    current = parent;
  }
}

export function stampConfigDir(repoRoot: string): string {
  return join(repoRoot, ".stamp");
}

export function stampReviewersDir(repoRoot: string): string {
  return join(repoRoot, ".stamp", "reviewers");
}

export function stampTrustedKeysDir(repoRoot: string): string {
  return join(repoRoot, ".stamp", "trusted-keys");
}

export function stampConfigFile(repoRoot: string): string {
  return join(repoRoot, ".stamp", "config.yml");
}

export function stampStateDbPath(repoRoot: string): string {
  return join(repoRoot, ".git", "stamp", "state.db");
}

export function userKeysDir(): string {
  return join(homedir(), ".stamp", "keys");
}

export function ensureDir(path: string, mode = 0o755): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true, mode });
  }
}

export function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}
