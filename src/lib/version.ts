import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Read version from the package.json that ships alongside the installed bundle.
// Walk up from the current module's directory until we find the @openthink/stamp
// package.json — robust to both the bundled shape (dist/...js → ../package.json)
// and dev (tsx src/index.ts → ../../package.json).
export function readPackageVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (let dir = here, i = 0; i < 6; i++) {
    try {
      const raw = readFileSync(join(dir, "package.json"), "utf8");
      const pkg = JSON.parse(raw) as { name?: string; version?: string };
      if (pkg.name === "@openthink/stamp" && pkg.version) return pkg.version;
    } catch {
      // not this directory
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("could not locate @openthink/stamp package.json to read version");
}
