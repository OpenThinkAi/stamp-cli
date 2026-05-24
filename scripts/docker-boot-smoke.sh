#!/usr/bin/env bash
#
# docker-boot-smoke.sh — AGT-425
#
# Build the stamp-server image AND verify the container actually BOOTS —
# not just that the image builds. This catches the AGT-411 incident class:
# a Dockerfile/entrypoint regression that compiles + builds cleanly but
# crash-loops at container start (AGT-411 was an entrypoint that sourced a
# script the Dockerfile forgot to COPY — `docker build` succeeded, the
# container died under `set -e` at boot, and because stamp-server
# self-deploys from `main` on Railway, prod crash-looped).
#
# Two call paths:
#   1. As a stamp `required_check` (runs during `stamp merge`, the only gate
#      that fires BEFORE the push → GitHub-mirror → Railway redeploy). To
#      keep client-side merges fast it SKIPS the build+boot when the merge
#      changes no boot-relevant files. The merge commit is HEAD at check
#      time (two parents), so `git diff HEAD^1 HEAD` is the merged-in change.
#   2. In GitHub Actions, invoked with STAMP_SMOKE_FORCE=1 so it builds +
#      boots unconditionally (backstop / PR visibility — Railway does not
#      gate its deploy on CI, so CI is post-hoc, not blocking).
#
# Env knobs:
#   STAMP_SMOKE_FORCE=1     build+boot unconditionally (skip the skip)
#   STAMP_SMOKE_BOOT_WAIT   seconds to wait before asserting "still up" (default 10)
set -euo pipefail

IMAGE_TAG="stamp-server-smoke:$(date +%s)-$$"
CONTAINER_NAME="stamp-smoke-$$"
BOOT_WAIT_SECS="${STAMP_SMOKE_BOOT_WAIT:-10}"

# Files that affect how the image BUILDS or BOOTS. A pure `src/lib/*` change
# (the client-side surface) cannot regress container boot and is already
# covered by build/typecheck/test, so it is intentionally NOT listed here —
# that is what lets the conditional skip keep client-side merges fast. The
# GitHub Actions backstop builds unconditionally, covering the rare case
# where a lib-only change does affect boot.
BOOT_RELEVANT_RE='^(server/|src/server/|Dockerfile|\.dockerignore|package\.json|package-lock\.json|tsup\.config\.ts|tsconfig\.json)'

should_skip() {
  [ "${STAMP_SMOKE_FORCE:-}" = "1" ] && return 1
  local changed
  # HEAD^1 is the target branch as it was before this merge commit; the diff
  # to HEAD is exactly what the merge lands. If there is no second parent
  # (non-merge context), git errors → don't skip (fail toward running).
  if ! changed=$(git diff --name-only HEAD^1 HEAD 2>/dev/null); then
    return 1
  fi
  printf '%s\n' "$changed" | grep -qE "$BOOT_RELEVANT_RE" && return 1
  return 0
}

if should_skip; then
  echo "docker-boot-smoke: no boot-relevant files changed in this merge — skipping image build+boot."
  echo "  (boot-relevant = server/, src/server/, Dockerfile, package*.json, tsup/tsconfig; STAMP_SMOKE_FORCE=1 forces a run.)"
  exit 0
fi

# A boot-relevant change with no Docker available must FAIL, not silently
# pass: signing a merge that changes the image without proving it boots is
# exactly the hole this check closes.
if ! command -v docker >/dev/null 2>&1; then
  echo "error: this merge changes boot-relevant files but 'docker' is not on PATH, so the boot-smoke cannot run." >&2
  echo "       Re-run the merge on a machine with Docker, or run scripts/docker-boot-smoke.sh there first." >&2
  exit 1
fi

# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT`
cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rmi "$IMAGE_TAG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "docker-boot-smoke: building $IMAGE_TAG from server/Dockerfile…"
docker build -f server/Dockerfile -t "$IMAGE_TAG" .

echo "docker-boot-smoke: starting container; asserting it stays up for ${BOOT_WAIT_SECS}s…"
# Minimal env on purpose: AUTHORIZED_KEYS / ANTHROPIC_API_KEY /
# STAMP_PROMPTS_REPO_URL are all unset, so the optional bootstrap phases
# (review-key, prompts-cache) are skipped and a CLEAN entrypoint reaches the
# sshd exec and stays up. A structural Dockerfile/entrypoint regression
# crashes under `set -e` regardless of env — which is the signal we want.
docker run -d --name "$CONTAINER_NAME" "$IMAGE_TAG" >/dev/null

sleep "$BOOT_WAIT_SECS"

running=$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || echo "false")
if [ "$running" != "true" ]; then
  status=$(docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
  echo "error: container did NOT stay up — boot crashed (AGT-411 class). state: $status" >&2
  echo "---- last 40 lines of container logs ----" >&2
  docker logs "$CONTAINER_NAME" 2>&1 | tail -40 >&2 || true
  exit 1
fi

health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
echo "docker-boot-smoke: container up after ${BOOT_WAIT_SECS}s ✓  (healthcheck: $health)"
exit 0
