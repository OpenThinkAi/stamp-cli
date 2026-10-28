# shellcheck shell=sh
#
# Explicit environment allowlists for the stamp server's long-running
# background processes (AGT-2264). Sourced by entrypoint.sh.
#
# The container env carries every operator secret (GITHUB_BOT_TOKEN,
# ANTHROPIC_API_KEY, platform variables, ...). Earlier images started the
# HTTP listener with `su -p`, so the internet-facing process inherited all of
# it. Now each background process starts from `env -i` and receives only the
# variables named below — the ones its code actually reads (enumerated from
# src/server/http-server.ts and the modules it imports). A variable that is
# unset in the container stays unset in the child, so "unset means default /
# disabled" semantics are unchanged.
#
# Adding a variable here hands it to that process. NEVER add a credential the
# process doesn't itself use: the listener legitimately holds only
# STAMP_PROMPTS_WEBHOOK_SECRET (it verifies the webhook HMAC).

# stamp-http-server — the public listener (runs as stamp-http).
STAMP_HTTP_SERVER_ENV="STAMP_HTTP_PORT STAMP_SERVER_DB_PATH STAMP_PROMPTS_WEBHOOK_SECRET STAMP_PROMPTS_REFRESH_TRIGGER STAMP_PEER_REVIEWS_ENABLED STAMP_PEER_EVENTS_POLL_INTERVAL_SEC SEAT_TTL_SECONDS CLAIM_SEAT_RATE_CAP REGISTER_EXTRA_RATE_CAP"

# stamp-workers — prompts poll / webhook-trigger refresh, trash sweep and the
# users.db retention sweep (runs as git, opens no socket).
STAMP_WORKERS_ENV="STAMP_SERVER_DB_PATH STAMP_PEER_EVENT_RETENTION_DAYS STAMP_SERVER_VERDICT_RETENTION_DAYS STAMP_PROMPTS_REPO_URL STAMP_PROMPTS_REPO_REF STAMP_PROMPTS_CACHE_ROOT STAMP_PROMPTS_DEPLOY_KEY_PATH STAMP_PROMPTS_POLL_INTERVAL_SEC STAMP_PROMPTS_REFRESH_TRIGGER GIT_SSH_KNOWN_HOSTS STAMP_TRASH_DIR STAMP_TRASH_TTL_DAYS STAMP_TRASH_SWEEP_INTERVAL_SEC"

STAMP_MINIMAL_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# _exec_allowlisted_env HOME_DIR "NAME1 NAME2 ..." CMD [ARGS...]
#
# exec CMD with an environment of exactly PATH (fixed), HOME=HOME_DIR and
# every listed NAME that is set in the current environment (set-but-empty
# is passed through as empty). Names must be plain identifiers; anything
# else is refused (exit 2) rather than eval'd. Never returns on success.
_exec_allowlisted_env() {
  _ae_home=$1
  _ae_names=$2
  shift 2
  if [ "$#" -eq 0 ]; then
    echo "error: _exec_allowlisted_env: no command given" >&2
    return 2
  fi
  _ae_cmdc=$#
  for _ae_name in $_ae_names; do
    case "$_ae_name" in
      [A-Za-z_]*) ;;
      *) echo "error: _exec_allowlisted_env: bad variable name '$_ae_name'" >&2; return 2 ;;
    esac
    case "$_ae_name" in
      *[!A-Za-z0-9_]*) echo "error: _exec_allowlisted_env: bad variable name '$_ae_name'" >&2; return 2 ;;
    esac
    case "$_ae_name" in
      PATH|HOME) continue ;;
    esac
    eval "_ae_isset=\${$_ae_name+x}"
    if [ -n "$_ae_isset" ]; then
      eval "set -- \"\$@\" \"$_ae_name=\${$_ae_name}\""
    fi
  done
  # "$@" is now CMD... NAME=VALUE...; rotate the command words to the end so
  # env sees the assignments first.
  _ae_i=0
  while [ "$_ae_i" -lt "$_ae_cmdc" ]; do
    set -- "$@" "$1"
    shift
    _ae_i=$((_ae_i + 1))
  done
  exec env -i "PATH=$STAMP_MINIMAL_PATH" "HOME=$_ae_home" "$@"
}
