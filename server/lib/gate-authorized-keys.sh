#!/bin/sh
# Sourceable library: _gate_authorized_keys
#
# Reads authorized_keys lines on stdin and writes them to stdout with the
# SSH-gate forced command prepended (AGT-2265):
#
#   command="stamp-gate legacy",restrict <line>
#
# entrypoint.sh pipes $AUTHORIZED_KEYS through this before writing the
# legacy AuthorizedKeysFile, so a key sshd matches from that file goes
# through the same gate as one the AuthorizedKeysCommand resolver emits.
# Without it, a key in AUTHORIZED_KEYS would skip the gate entirely (no
# forced command) and could read any path the git user can, .trash and
# .prompts-cache included. The gate resolves the caller from SSH_USER_AUTH
# against users.db, so a legacy-file key that is not enrolled (seeding
# failed, or the user was removed) is refused rather than let through.
#
# Blank lines and `#` comments are dropped. A line that already carries
# options (anything not starting with a key algorithm) gets ours joined
# with a comma; if it has its own `command=`, sshd rejects the line as a
# duplicate option, which fails closed.

_gate_authorized_keys() {
  awk '
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }
    {
      sub(/^[[:space:]]+/, "")
      sub(/[[:space:]]+$/, "")
      if ($0 ~ /^(ssh-|ecdsa-|sk-)/) {
        print "command=\"stamp-gate legacy\",restrict " $0
      } else {
        print "command=\"stamp-gate legacy\",restrict," $0
      }
    }
  '
}
