#!/bin/sh
#
# check-prompts-dir.sh — sourceable boot-time guard for STAMP_PROMPTS_DIR.
#
# AGT-411: Enforce production refusal when the Phase A STAMP_PROMPTS_DIR
# override is non-default.  The trust property — that the operator controls
# the exact prompt bytes signed into each attestation — requires prompts to
# be baked into the image, not supplied at runtime via an env var.
#
# Usage (from entrypoint.sh):
#
#   . "$(dirname "$0")/lib/check-prompts-dir.sh"
#   check_prompts_dir
#
# Returns 0 (allowed) or exits non-zero with an error to stderr.
#
# Design decisions (AGT-411 plan-approval, 2026-05-23):
#
#   - Absent STAMP_ENV is treated as production (fail-closed).  Operators
#     who want to use the Phase A override in CI/dev MUST set STAMP_ENV to
#     a non-production value ("dev" or "test") AND set the explicit
#     insecure-test toggle.
#
#   - Phase B carve-out: when STAMP_PROMPTS_REPO_URL is set the resolver
#     ignores STAMP_PROMPTS_DIR entirely, so a stale Phase A var left in
#     the environment MUST NOT cause a spurious refusal.  The guard is a
#     no-op in Phase B mode.
#
#   - The default path is the single constant below; it is shared with the
#     TypeScript resolver (DEFAULT_PROMPTS_DIR in reviewPipeline.ts) via
#     documentation contract — both must stay in sync.

DEFAULT_PROMPTS_DIR="/etc/stamp/reviewers"

check_prompts_dir() {
  # Phase B carve-out: resolver ignores STAMP_PROMPTS_DIR when
  # STAMP_PROMPTS_REPO_URL is set, so no need to refuse here.
  if [ -n "$STAMP_PROMPTS_REPO_URL" ]; then
    return 0
  fi

  # Nothing to check if STAMP_PROMPTS_DIR is unset or equals the default.
  if [ -z "$STAMP_PROMPTS_DIR" ] || [ "$STAMP_PROMPTS_DIR" = "$DEFAULT_PROMPTS_DIR" ]; then
    return 0
  fi

  # STAMP_PROMPTS_DIR is set to a non-default value.  Determine whether we
  # are in a production context.  Absent STAMP_ENV → treat as production
  # (fail-closed per the AGT-411 plan approval).
  if [ "$STAMP_ENV" = "dev" ] || [ "$STAMP_ENV" = "test" ]; then
    # Non-production: allow ONLY when the explicit insecure-test toggle is set.
    if [ -z "$STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY" ]; then
      echo "error: STAMP_PROMPTS_DIR is set to a non-default path ('$STAMP_PROMPTS_DIR') in a non-production environment, but STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY is not set. Set both to use a custom prompts directory in dev/test." >&2
      exit 1
    fi
    # Both vars set in non-prod: allowed.
    return 0
  fi

  # Production (STAMP_ENV=production or absent): refuse unconditionally.
  echo "error: STAMP_PROMPTS_DIR is set to a non-default path ('$STAMP_PROMPTS_DIR') in a production context (STAMP_ENV='${STAMP_ENV:-<unset>}'). The prompt-bytes trust property requires prompts to be baked into the image. Remove STAMP_PROMPTS_DIR or set STAMP_ENV=dev/test with STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY to override in non-production environments only." >&2
  exit 1
}
