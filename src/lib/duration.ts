/**
 * Parse a retention-duration string of the shape `<n><unit>` where `<n>` is
 * a positive integer and `<unit>` is one of `d` (days), `h` (hours), `m`
 * (minutes). Returns:
 *
 * - `sqliteModifier` — a string suitable for SQLite's `datetime('now', ?)`
 *   modifier slot (e.g. `-30 days`). The leading minus is included so the
 *   caller passes it directly: `datetime('now', '-30 days')`.
 * - `humanLabel` — the input echoed back, used in user-facing output.
 *
 * Strict on input shape: no whitespace, no leading `+`, no zero or
 * negative counts. Anything else throws with a message naming the accepted
 * shapes — caller is expected to surface this verbatim and exit non-zero.
 *
 * Cap of 9999999 on `<n>` keeps the parsed value comfortably below SQLite's
 * datetime-modifier overflow point and prevents accidental "100000000d"
 * pasted from a script confusing things.
 */
export function parseRetentionDuration(
  input: string,
): { sqliteModifier: string; humanLabel: string } {
  const match = /^([1-9][0-9]{0,6})(d|h|m)$/.exec(input);
  if (!match) {
    throw new Error(
      `invalid duration "${input}". Accepted shapes: <n>d (days), <n>h (hours), <n>m (minutes), where <n> is a positive integer (no whitespace, no leading +, no zero). Examples: 30d, 12h, 90m.`,
    );
  }
  const n = match[1]!;
  const unit = match[2]!;
  const unitWord =
    unit === "d" ? "days" : unit === "h" ? "hours" : "minutes";
  return {
    sqliteModifier: `-${n} ${unitWord}`,
    humanLabel: `${n}${unit}`,
  };
}
