# shellcheck shell=sh
#
# prompts-cache-config.sh — sourceable boot-time helpers for the Phase B
# prompts cache (AGT-2277). Sourced by entrypoint.sh.
#
# The same two answers are resolved in TypeScript by
# src/server/promptsCachePaths.ts (bootstrap, stamp-workers, stamp-review);
# the defaults below MUST match DEFAULT_PROMPTS_CACHE_ROOT and
# DEFAULT_PROMPTS_DEPLOY_KEY_PATH there (tests/promptsCacheConfigShell.test.ts
# diffs them).

DEFAULT_PROMPTS_CACHE_ROOT=/srv/git/.prompts-cache
DEFAULT_PROMPTS_DEPLOY_KEY_PATH=/srv/git/.ssh-client-keys/prompts_repo_key

# check_prompts_cache_root
#
# Refuse a STAMP_PROMPTS_CACHE_ROOT that isn't a plain dot-dir directly under
# /srv/git. Returns 0 when unset/empty (the default is used) or valid; prints
# an error: line and returns 1 otherwise.
#
# Why so narrow:
#   - The SSH gate (AGT-2265) serves any /srv/git/<name>.git and refuses
#     dot-dirs. A cache at /srv/git/prompts.git would be cloneable by every
#     enrolled key; a dot-dir never is.
#   - The boot sweep (AGT-2263) skips dot-dirs, and the entrypoint
#     `chown -R git:git`s the cache root (and <root>.old) as root. Pointing it
#     at .stamp-state, a key dir or .trash would hand those to git, so the
#     server's own dot-dirs are reserved.
#   - It must live on the persistent volume anyway (the cache is
#     rebuilt from the network otherwise).
check_prompts_cache_root() {
  _pcr=$STAMP_PROMPTS_CACHE_ROOT
  [ -n "$_pcr" ] || return 0
  _pcr_name=${_pcr#/srv/git/}
  _pcr_ok=1
  [ "$_pcr_name" != "$_pcr" ] || _pcr_ok=0
  case "$_pcr_name" in
    .[A-Za-z0-9_-]*) ;;
    *) _pcr_ok=0 ;;
  esac
  case "$_pcr_name" in
    *[!A-Za-z0-9._-]*|*..*) _pcr_ok=0 ;;
  esac
  case "$_pcr_name" in
    .ssh-host-keys|.ssh-client-keys|.stamp-state|.trash|*.old|*.tmp) _pcr_ok=0 ;;
    .ssh-host-keys.*|.ssh-client-keys.*|.stamp-state.*|.trash.*) _pcr_ok=0 ;;
  esac
  if [ "$_pcr_ok" -ne 1 ]; then
    echo "error: STAMP_PROMPTS_CACHE_ROOT='$_pcr' is not allowed; use a dot-dir directly under /srv/git (e.g. /srv/git/.prompts-cache) that isn't one of the server's own (.ssh-host-keys, .ssh-client-keys, .stamp-state, .trash). Only dot-dirs are never served by the SSH gate." >&2
    return 1
  fi
  return 0
}

# resolve_prompts_deploy_key — print the deploy key the bootstrap and the
# workers will use: STAMP_PROMPTS_DEPLOY_KEY_PATH when set, else the default
# path if something exists there (`-e`, i.e. existsSync — same test as the
# TypeScript side), else nothing.
resolve_prompts_deploy_key() {
  if [ -n "$STAMP_PROMPTS_DEPLOY_KEY_PATH" ]; then
    printf '%s' "$STAMP_PROMPTS_DEPLOY_KEY_PATH"
  elif [ -e "$DEFAULT_PROMPTS_DEPLOY_KEY_PATH" ]; then
    printf '%s' "$DEFAULT_PROMPTS_DEPLOY_KEY_PATH"
  fi
}
