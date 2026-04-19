import { spawnSync } from "node:child_process";
import { readPackageVersion } from "../lib/version.js";

const PKG_NAME = "stamp-cli";

// Strips prerelease/build suffix and compares as numeric major.minor.patch.
// Returns >0 if a > b, <0 if a < b, 0 if equal. Good enough for stamp's
// release shape (no weird prerelease semantics in shipping versions).
function compareSemver(a: string, b: string): number {
  const parse = (v: string) =>
    (v.split("-")[0] ?? "0.0.0").split(".").map((n) => parseInt(n, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const ai = pa[i] ?? 0;
    const bi = pb[i] ?? 0;
    if (ai !== bi) return ai - bi;
  }
  return 0;
}

export function runUpdate(): void {
  const current = readPackageVersion();
  process.stdout.write(`current: ${PKG_NAME}@${current}\n`);
  process.stdout.write(`checking npm registry for latest...\n`);

  const viewResult = spawnSync("npm", ["view", PKG_NAME, "version"], {
    encoding: "utf8",
  });
  if (viewResult.error || viewResult.status !== 0) {
    const stderr = (viewResult.stderr ?? "").trim();
    throw new Error(
      `npm view ${PKG_NAME} version failed` +
        (viewResult.status !== null ? ` (exit ${viewResult.status})` : "") +
        `.\n` +
        (stderr ? `${stderr}\n` : "") +
        `Is 'npm' on your PATH?`,
    );
  }
  const latest = viewResult.stdout.trim();
  if (!latest) {
    throw new Error(
      `npm view returned an empty version for ${PKG_NAME}. Registry may be unreachable.`,
    );
  }
  process.stdout.write(`latest:  ${PKG_NAME}@${latest}\n`);

  const cmp = compareSemver(current, latest);
  if (cmp === 0) {
    process.stdout.write(`already up to date.\n`);
    return;
  }
  if (cmp > 0) {
    process.stdout.write(
      `current is newer than the latest published release — nothing to do.\n`,
    );
    return;
  }

  process.stdout.write(`installing ${PKG_NAME}@${latest}...\n`);
  const installResult = spawnSync(
    "npm",
    ["install", "-g", `${PKG_NAME}@${latest}`],
    { stdio: "inherit" },
  );
  if (installResult.error || installResult.status !== 0) {
    throw new Error(
      `npm install -g ${PKG_NAME}@${latest} failed` +
        (installResult.status !== null
          ? ` (exit ${installResult.status})`
          : "") +
        `.\n` +
        `If this is a permissions error (EACCES):\n` +
        `  (a) re-run with elevated permissions: sudo stamp update\n` +
        `  (b) configure npm to use a user-writable prefix — see npm's docs for\n` +
        `      "Resolving EACCES permissions errors when installing packages globally"\n` +
        `If 'stamp-cli' was installed via a different tool (pnpm, yarn), upgrade\n` +
        `through that tool instead — this command only uses 'npm install -g'.`,
    );
  }

  process.stdout.write(`upgraded ${PKG_NAME}: ${current} → ${latest}\n`);
}
