/**
 * Glob matching for git ref names in `.stamp/mirror.yml`'s `tags:` field.
 *
 * Operators write patterns like `v*` or `release-*` and expect shell-style
 * glob semantics, not regex. We accept exactly two metacharacters:
 *
 *   *   matches zero or more characters (including `/`)
 *   ?   matches exactly one character
 *
 * Everything else is escaped, so a literal pattern like `v1.0.0` matches
 * the tag named `v1.0.0` and not `v1x0x0`. We deliberately do not support
 * `**`, character classes, or `{a,b}` alternation — tag names rarely
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
 * Test whether a tag name matches any of the configured patterns.
 * Empty pattern list returns false (= no tag mirroring).
 */
export function matchesAnyTagPattern(tagName: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (globToRegex(pattern).test(tagName)) return true;
  }
  return false;
}
