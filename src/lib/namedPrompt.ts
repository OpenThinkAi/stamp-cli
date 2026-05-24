/**
 * Named prompt resolver for `stamp pr listen` (AGT-430).
 *
 * Resolves `decision.prompt` → `~/.stamp/personal/peers/<name>.md` (AC #3).
 * Name validation prevents path traversal from a Haiku-chosen name.
 *
 * Injection seam: `_readFileForTest` replaces real fs.readFileSync in tests.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// ─── Name validation ─────────────────────────────────────────────────

/**
 * Accept only names that are safe to use as a single filename segment.
 * Rejects `.`, `..`, slashes, and any character outside `[A-Za-z0-9._-]`.
 */
const NAME_REGEX = /^[A-Za-z0-9._-]+$/;

function isValidPromptName(name: string): boolean {
  if (!NAME_REGEX.test(name)) return false;
  if (name === "." || name === "..") return false;
  // Belt-and-suspenders: reject if it contains any separator after normalization.
  if (name.includes("/") || name.includes("\\")) return false;
  return true;
}

// ─── Input / output types ────────────────────────────────────────────

export interface ResolveNamedPromptInput {
  name: string;
  /**
   * Test-only injection seam: replace real `readFileSync` for the prompt
   * file. Receives the resolved absolute path and must return file contents
   * or throw (e.g. ENOENT) to simulate a missing file.
   */
  _readFileForTest?: (path: string) => string;
}

export type ResolveNamedPromptResult =
  | { ok: true; body: string; resolvedPath: string }
  | { ok: false; reason: "invalid_name" | "missing_file" | "read_error" };

// ─── Resolver ────────────────────────────────────────────────────────

/**
 * Resolve a named prompt to its file contents.
 *
 * Returns `{ ok: true, body, resolvedPath }` on success.
 * Returns `{ ok: false, reason }` when:
 *   - `name` fails validation (`"invalid_name"`) — path traversal attempt.
 *   - the file does not exist (`"missing_file"`) — AC #3 skip path.
 *   - the file exists but cannot be read (`"read_error"`).
 *
 * Callers are responsible for logging `✗` and treating the decision as
 * `{ claim_seat: "skip" }` on any `ok: false` result (AC #3).
 */
export function resolveNamedPrompt(
  input: ResolveNamedPromptInput,
): ResolveNamedPromptResult {
  const { name } = input;

  if (!isValidPromptName(name)) {
    return { ok: false, reason: "invalid_name" };
  }

  const resolvedPath = join(homedir(), ".stamp", "personal", "peers", `${name}.md`);

  try {
    const readFn = input._readFileForTest ?? ((p: string) => readFileSync(p, "utf8"));
    const body = readFn(resolvedPath);
    return { ok: true, body, resolvedPath };
  } catch (err) {
    // Distinguish ENOENT (missing file) from other read errors.
    if (
      err instanceof Error &&
      "code" in err &&
      (err as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return { ok: false, reason: "missing_file" };
    }
    return { ok: false, reason: "read_error" };
  }
}
