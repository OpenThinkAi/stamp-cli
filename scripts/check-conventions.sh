#!/usr/bin/env bash
#
# scripts/check-conventions.sh — grep-based regression checks that catch
# the half-fix-rot pattern reviewers shouldn't have to.
#
# When a command/flag/concept gets renamed, the rename touches multiple
# files. This script catches the dribble — references to the old name in
# docstrings, error messages, comments, help text — that escape an Edit
# pass but break agent self-help when the operator hits the error path.
#
# Each check is a `grep -rn <pattern>` over a scoped fileset. A non-empty
# match prints the offending file:line + the pattern + a fix hint, and
# the script exits non-zero. Append new checks here whenever a rename or
# convention change has just bitten you in review.
#
# Run via:  npm run check-conventions   (or: npm test, which chains it)

set -e

cd "$(dirname "$0")/.."

failures=0

# Helper: grep for <pattern> under <paths>, exclude allowed files. If
# anything matches, print and bump the failure counter. Always continues
# so a single run reports every check at once.
#
# Args:
#   1 label      - human-readable name for the check
#   2 pattern    - extended regex passed to `grep -E`
#   3 paths      - space-separated list of dirs/files to grep over
#   4 excludes   - newline-separated list of `grep -v -E` patterns to
#                  apply to the matches (e.g. file paths to ignore).
#                  Each line is one regex. Empty string means no
#                  excludes beyond the default dist/ + node_modules/ filter.
#   5 fix_hint   - actionable hint printed under the matches when any.
fail_on_match() {
  local label="$1"
  local pattern="$2"
  local paths="$3"
  local excludes="$4"
  local fix_hint="$5"

  # shellcheck disable=SC2086
  matches=$(grep -rn -E "$pattern" $paths 2>/dev/null \
    | grep -v -E "(^|/)dist/" \
    | grep -v -E "(^|/)node_modules/" \
    | grep -v -E "/\.git/" \
    || true)
  if [ -n "$excludes" ]; then
    while IFS= read -r excl; do
      [ -z "$excl" ] && continue
      matches=$(printf '%s\n' "$matches" | grep -v -E "$excl" || true)
    done <<EOF
$excludes
EOF
  fi
  matches=$(printf '%s' "$matches" | sed '/^$/d')
  if [ -n "$matches" ]; then
    echo "✗ $label"
    printf '%s\n' "$matches" | sed 's/^/    /'
    [ -n "$fix_hint" ] && echo "    fix: $fix_hint"
    failures=$((failures + 1))
  else
    echo "✓ $label"
  fi
}

# 1. No CLI references to `list-trash` as a stamp subcommand. The CLI
#    surface in 0.7.3+ is `stamp server-repos list --trash`; the
#    server-side script is still named `list-trash` (binary), which is
#    fine — what's stale is `stamp ... list-trash` references in
#    docstrings/help text/error messages. Pattern matches "stamp" plus
#    anything plus `list-trash`, which catches the prose drift without
#    flagging the binary name.
fail_on_match \
  "no stale 'stamp ... list-trash' command references in docs/messages" \
  'stamp.{0,40}list-trash' \
  "src docs server" \
  "scripts/check-conventions.sh" \
  "rewrite as 'stamp server-repos list --trash'"

# 2. No `server-repo` (singular) outside the `list-trash` filename and
#    legitimate mid-word usage. The plural `server-repos` is the CLI
#    surface (matching `stamp reviewers`).
fail_on_match \
  "no singular 'server-repo' command references (plural is canonical)" \
  '([[:space:]]|`)stamp server-repo([[:space:]]|`|$)' \
  "src docs server scripts" \
  "" \
  "use 'stamp server-repos' (plural)"

# 3. Errors must use lowercase `error:` prefix on stderr per the
#    documented output convention. Reject `WARNING:` (uppercase) and
#    `ERROR:` (uppercase) in TypeScript console.* calls.
fail_on_match \
  "no uppercase 'WARNING:' or 'ERROR:' in console.* output" \
  'console\.(log|error)\("(WARNING|ERROR):' \
  "src" \
  "" \
  "use lowercase 'warning:' / 'error:' to match the convention"

# 4. No `actor_type: "User"` hardcoded in fresh ruleset payload code
#    paths. We learned in 0.7.2 that User type silently no-ops on org
#    repos; lookupRepoOwnerType + BypassActor selection is the right
#    path. The literal in `docs/github-ruleset-template.json` is OK
#    (it's a template the operator edits).
fail_on_match \
  "no hardcoded 'actor_type: \"User\"' in client code (use BypassActor)" \
  'actor_type:\s*"User"' \
  "src" \
  "" \
  "use BypassActor type from lib/ghRuleset.ts; pick OrganizationAdmin for org repos"

# 5. The `→` glyph is not in the documented status-mark set
#    (✓ / ✗ / ⟳). Reject it as a console.log line prefix in TypeScript.
fail_on_match \
  "no '→' line-prefix in console output (not in documented mark set)" \
  'console\.log\("→' \
  "src" \
  "" \
  "drop the glyph or use one of the documented marks (✓/✗/⟳)"

if [ $failures -gt 0 ]; then
  echo
  echo "✗ $failures convention check(s) failed."
  echo "  Fix the matches above (or update scripts/check-conventions.sh if a check is now wrong)."
  exit 1
fi

echo
echo "✓ all convention checks passed"
