/**
 * Bridge-release deprecation banner.
 *
 * The stamp 1.x line is the operator-trust track and is moving into
 * maintenance now that 2.x (server-attested reviews) is the active line.
 * The bridge release ships with a one-line deprecation banner wired into
 * the user-facing CLI entry points (`stamp init`, `stamp merge`) so any
 * operator running the bridge release sees the pointer to the migration
 * guide on every authoritative invocation.
 *
 * The banner goes to stderr (not stdout) for two reasons:
 *   1. It's informational, not part of the command's structured output.
 *      Operators piping `stamp merge` output to a tool stay unaffected.
 *   2. stderr is the convention for "the command worked, here's a note
 *      you should also see" — same channel `maybePrintLlmNotice` uses.
 *
 * Suppression: set `STAMP_SUPPRESS_DEPRECATION=1` in the environment.
 * CI runs, scripted automations, and operators who've internalised the
 * migration timeline can opt out. The variable is documented inline (in
 * the banner itself) and in `docs/migration-1.x-to-2.x.md` next to the
 * deprecation-timeline section, so a discoverer of either surface can
 * trace it to the other.
 *
 * Sister env var: `STAMP_SUPPRESS_LLM_NOTICE` (see `llmNotice.ts`) suppresses
 * a different, narrower notice on `stamp review`. Both follow the same
 * `STAMP_SUPPRESS_*` shape so an operator who's set one will recognise the
 * other.
 */
export function maybePrintDeprecationNotice(): void {
  if (process.env.STAMP_SUPPRESS_DEPRECATION === "1") return;

  // Prefix is lowercase `warning:` to match the rest of stamp's stderr
  // convention (`error:`, `warning:`, `note:` — see `maybePrintLlmNotice`,
  // `requireHumanMerge`, and the CLI's error paths). Agents / operator
  // scripts that classify stderr lines by prefix can route this one
  // alongside other advisories without a special case.
  process.stderr.write(
    "warning: stamp 1.x is in maintenance — the server-attested 2.x line is active. " +
      "See docs/migration-1.x-to-2.x.md. " +
      "Suppress: STAMP_SUPPRESS_DEPRECATION=1.\n",
  );
}
