/**
 * Working-tree reader for `.stamp/mirror.yml`'s branch list, used by
 * `stamp provision` to derive the GitHub Ruleset's target branches
 * (AGT-2245). The strict, canonical parser is the post-receive hook's
 * readMirrorConfig (src/hooks/post-receive.ts), which reads from a git
 * ref and reports malformed configs at push time.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

/**
 * The `github.branches` list from `<repoRoot>/.stamp/mirror.yml`, or []
 * when the file is absent or malformed. The post-receive hook
 * (readMirrorConfig) is the strict, canonical parser and reports
 * malformed configs at push time; this reader only feeds the Ruleset's
 * include list, where "no extra branches" safely degrades to the
 * default-branch-only protection stamp has always applied.
 */
export function readMirrorYmlBranches(repoRoot: string): string[] {
  const path = join(repoRoot, ".stamp", "mirror.yml");
  if (!existsSync(path)) return [];
  try {
    const parsed = parseYaml(readFileSync(path, "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
    const gh = (parsed as Record<string, unknown>)["github"];
    if (!gh || typeof gh !== "object" || Array.isArray(gh)) return [];
    const branches = (gh as Record<string, unknown>)["branches"];
    if (!Array.isArray(branches)) return [];
    return branches.map(String).filter((b) => b.length > 0);
  } catch {
    return [];
  }
}
