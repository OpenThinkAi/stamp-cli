#!/bin/sh
# Sourceable library: _inject_sshd_setenv <VAR_NAME>
#
# Injects `SetEnv <NAME>=<VALUE>` into sshd_config for a named env var, so
# SSH-invoked stamp-* commands (mint-invite, etc.) see container env vars that
# sshd would otherwise strip.  Called by entrypoint.sh for each name in
# $STAMP_SSH_PASS_ENV.
#
# !!! SECURITY: NON-SECRET VALUES ONLY !!!
# The sshd_config file is written with mode 0644 (world-readable) — every
# process on the host can read it.  STAMP_SSH_PASS_ENV is for non-secret
# configuration values like STAMP_PUBLIC_URL — NEVER for API tokens, secrets,
# or credentials.  Use the /etc/stamp/env pattern (write_env_var in
# entrypoint.sh, mode 0640 root:git) for anything sensitive.
#
# Caller controls which sshd_config file to write via $SSHD_CONFIG (default:
# /etc/ssh/sshd_config).  The override exists solely for unit-test isolation —
# production callers leave the var unset.

: "${SSHD_CONFIG:=/etc/ssh/sshd_config}"

_inject_sshd_setenv() {
  local name="$1"

  # Defensive name validation — only [A-Za-z_][A-Za-z0-9_]*. POSIX env var
  # names already satisfy this; rejecting non-conforming names closes a
  # latent attack surface (the value lookup runs in a subshell and the grep
  # pattern interpolates $name, so an attacker-controlled name with shell
  # metacharacters or regex specials could otherwise smuggle behavior).
  case "$name" in
    ""|*[!A-Za-z0-9_]*|[0-9]*)
      echo "error: invalid env var name '${name}' in STAMP_SSH_PASS_ENV (must match [A-Za-z_][A-Za-z0-9_]*)" >&2
      return 1
      ;;
  esac

  # Indirect lookup via printenv — reads the named env var WITHOUT invoking
  # a shell interpreter on $name. Preferred over `eval "...\$$name..."`
  # because it eliminates any eval-injection surface even before the
  # defensive name check above. printenv ships with coreutils (present in
  # the Alpine base image; the Dockerfile already relies on it elsewhere).
  local value
  value="$(printenv "$name")"
  [ -n "$value" ] || return 0   # var unset or empty — skip silently

  # Whole-stream charset check: strip every allowed byte; if anything
  # remains the value contains an illegal character that could create a
  # new sshd directive when injected into sshd_config.  The tr-based
  # check is immune to the newline-splitting edge case that would let a
  # line-anchored regex pass a multi-line value whose first line looks
  # legitimate.
  if [ -n "$(printf '%s' "$value" | tr -d 'A-Za-z0-9.:/_@=+-')" ]; then
    echo "error: ${name} contains illegal characters (allowed: [A-Za-z0-9.:/_@=+-]); refusing to inject into sshd_config" >&2
    return 1
  fi

  # STAMP_PUBLIC_URL: additional semantic check — must be an HTTP(S) URL.
  if [ "$name" = "STAMP_PUBLIC_URL" ]; then
    case "$value" in
      http://*|https://*) ;;
      *)
        echo "error: STAMP_PUBLIC_URL must start with http:// or https://; refusing to inject into sshd_config" >&2
        return 1
        ;;
    esac
  fi

  # Filter any stale `SetEnv <NAME>=` line, then append the fresh value.
  # `grep -F` (fixed-string match) so a name containing characters that
  # are regex metacharacters cannot accidentally match a similarly-named
  # neighbor (the name validation above already restricts the charset,
  # but fixed-string is the correct semantic regardless).
  # Atomic write-then-rename avoids a window where sshd reads a partially-
  # written file during a concurrent connection fork.
  { grep -F -v "SetEnv ${name}=" "$SSHD_CONFIG" || true; \
    printf 'SetEnv %s=%s\n' "$name" "$value"; \
  } > "${SSHD_CONFIG}.new"
  mv "${SSHD_CONFIG}.new" "$SSHD_CONFIG"
  chmod 0644 "$SSHD_CONFIG"
}
