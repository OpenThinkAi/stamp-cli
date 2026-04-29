/**
 * Glob matching for git ref names — used by `.stamp/mirror.yml`'s `tags:`
 * and `branches:` fields, and by `.stamp/config.yml`'s `branches:` map keys.
 *
 * Operators write patterns like `v*`, `release/*`, or `team-?` and expect
 * shell-style glob semantics, not regex. We accept exactly two metacharacters:
 *
 *   *   matches zero or more characters (including `/`)
 *   ?   matches exactly one character
 *
 * Everything else is escaped, so a literal pattern like `v1.0.0` matches
 * the tag named `v1.0.0` and not `v1x0x0`. We deliberately do not support
 * `**`, character classes, or `{a,b}` alternation — ref names rarely
 * benefit from them and the more elaborate the syntax, the more surprising
 * the failure modes are when an operator writes the wrong thing.
 *
 * Lives in lib/ (not the hook) so unit tests can pin the pattern semantics
 * without booting the whole post-receive flow.
 */

/**
 * Convert a single glob pattern to an anchored regex. Escapes regex
 * metacharacters in the literal portions so a pattern like `v1.0.0`
 * doesn't accidentally match `v1x0x0` via the `.`.
 */
export function globToRegex(pattern: string): RegExp {
  // Escape every regex metachar except `*` and `?`, which we then
  // translate. Order matters: escape first, translate after.
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const translated = escaped.replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${translated}$`);
}

/**
 * Resolve the `tags:` field from mirror.yml into a normalized list of
 * patterns. Accepts the three operator-natural forms:
 *
 *   tags: true              → ["*"]   (mirror all tags)
 *   tags: ["v*", "rc-*"]    → as written
 *   tags: <absent or false> → []      (no tag mirroring)
 *
 * Anything else (a string, a number, a non-array object) is treated as
 * "config error → no mirroring" and the caller is expected to surface
 * a warning. Returning `null` distinguishes "operator wrote something
 * malformed" from "operator opted out (empty array)".
 */
export function resolveTagPatterns(raw: unknown): string[] | null {
  if (raw === undefined || raw === null || raw === false) return [];
  if (raw === true) return ["*"];
  if (Array.isArray(raw)) {
    const out: string[] = [];
    for (const item of raw) {
      if (typeof item !== "string" || item.length === 0) return null;
      out.push(item);
    }
    return out;
  }
  return null;
}

/**
 * Test whether a ref name matches any of the configured glob patterns.
 * Empty pattern list returns false (= no match).
 *
 * Used for both branch and tag matching — a literal entry like `main`
 * still works (no metachars → exact-string regex), so callers don't need
 * to special-case literal vs. pattern entries.
 */
export function matchesAnyPattern(name: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (globToRegex(pattern).test(name)) return true;
  }
  return false;
}

/** Back-compat alias — predates the branch use case. New callers should
 *  use `matchesAnyPattern`, which is the same function under a name-agnostic
 *  spelling. */
export const matchesAnyTagPattern = matchesAnyPattern;

/** True if a config key/entry is a glob pattern (contains `*` or `?`)
 *  rather than a literal ref name. Used by config.yml branch lookup to
 *  distinguish exact-match keys from pattern keys. */
export function isGlobPattern(s: string): boolean {
  return s.includes("*") || s.includes("?");
}
