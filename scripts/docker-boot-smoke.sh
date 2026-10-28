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
REVOKE_CONTAINER="stamp-smoke-revoke-$$"
REVOKE_KEYS=""
SIGN_CONTAINER="stamp-smoke-sign-$$"
SIGN_KEYS=""
HOOKS_CONTAINER="stamp-smoke-hooks-$$"
HOOKS_TMP=""
LISTEN_CONTAINER="stamp-smoke-listen-$$"
BOOT_WAIT_SECS="${STAMP_SMOKE_BOOT_WAIT:-10}"

# Files that affect how the image BUILDS or BOOTS. AGT-2270 added
# `scripts/` (setup-repo.sh is COPYed into the image), `src/hooks/` (the
# pre/post-receive bundles ship in it) and `.npmrc` (changes `npm ci` in
# the builder). A pure `src/lib/*` change
# (the client-side surface) cannot regress container boot and is already
# covered by build/typecheck/test, so it is intentionally NOT listed here —
# that is what lets the conditional skip keep client-side merges fast. The
# GitHub Actions backstop builds unconditionally, covering the rare case
# where a lib-only change does affect boot.
BOOT_RELEVANT_RE='^(server/|src/server/|src/hooks/|scripts/|Dockerfile|\.dockerignore|\.npmrc|package\.json|package-lock\.json|tsup\.config\.ts|tsconfig\.json)'

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
  echo "  (boot-relevant = server/, src/server/, src/hooks/, scripts/, Dockerfile, .npmrc, package*.json, tsup/tsconfig; STAMP_SMOKE_FORCE=1 forces a run.)"
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
  docker rm -f "$REVOKE_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$SIGN_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$HOOKS_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$LISTEN_CONTAINER" >/dev/null 2>&1 || true
  [ -n "${HOOKS_TMP:-}" ] && rm -rf "$HOOKS_TMP"
  [ -n "${REVOKE_KEYS:-}" ] && rm -rf "$REVOKE_KEYS"
  [ -n "${SIGN_KEYS:-}" ] && rm -rf "$SIGN_KEYS"
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
#
# STAMP_FORBID_AI_ATTRIBUTION=1 is the one deliberate exception (AGT-1724):
# it's a non-secret flag that must survive sshd's env stripping via
# /etc/stamp/env, and the hook-env assertion below proves it does.
docker run -d --name "$CONTAINER_NAME" -e STAMP_FORBID_AI_ATTRIBUTION=1 "$IMAGE_TAG" >/dev/null

sleep "$BOOT_WAIT_SECS"

running=$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || echo "false")
if [ "$running" != "true" ]; then
  status=$(docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
  echo "error: container did NOT stay up — boot crashed (AGT-411 class). state: $status" >&2
  echo "---- last 40 lines of container logs ----" >&2
  docker logs "$CONTAINER_NAME" 2>&1 | tail -40 >&2 || true
  exit 1
fi

# AGT-1724: prove a container env var reaches the pre-receive hook the way
# an SSH push session would see it — as the git user with the environment
# wiped (sshd strips container env), so the only route is the
# /etc/stamp/env file the entrypoint writes and the hook reloads. Seeds a
# scratch bare repo, installs the image's hook, pushes a commit carrying a
# Claude-Session trailer, and requires the policy rejection.
echo "docker-boot-smoke: asserting STAMP_FORBID_AI_ATTRIBUTION reaches the pre-receive hook via /etc/stamp/env…"
hook_env_script='set -e
d=$(mktemp -d)
cd "$d"
git init -q --bare -b main s.git
git clone -q s.git w 2>/dev/null
cd w
git config user.email smoke@example.invalid
git config user.name smoke
git checkout -q -b main
mkdir -p .stamp
printf "branches:\n  main:\n    required: [security]\nreviewers:\n  security:\n    prompt: x\n" > .stamp/config.yml
git add -A
git commit -qm seed
git push -q origin main
git checkout -q -b scratch
git push -q origin scratch
cp /etc/stamp/pre-receive.cjs ../s.git/hooks/pre-receive
chmod 0755 ../s.git/hooks/pre-receive
echo x > x
git add -A
git commit -qm "smoke

Claude-Session: smoke"
if git push origin scratch 2>push.err; then
  echo "pushed: hook did NOT see STAMP_FORBID_AI_ATTRIBUTION" >&2
  exit 1
fi
grep -q "AI-agent attribution is not allowed" push.err || { cat push.err >&2; exit 1; }
'
if ! docker exec "$CONTAINER_NAME" su -s /bin/sh git -c "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp sh -c '$hook_env_script'"; then
  echo "error: STAMP_FORBID_AI_ATTRIBUTION set on the container did not reach the pre-receive hook (expected via /etc/stamp/env)." >&2
  exit 1
fi
echo "docker-boot-smoke: hook sees STAMP_FORBID_AI_ATTRIBUTION via /etc/stamp/env ✓"

# AGT-2271: the sftp subsystem must be gone. A subsystem request is not
# routed through the login shell, so with Alpine's stock `Subsystem sftp`
# line any enrolled key got a file session as the git user — bypassing
# git-shell, pre-receive and the review gate. Drive real SSH sessions from
# inside the container to its own sshd (no published port, so concurrent
# smoke runs can't clash): a throwaway key is enrolled in users.db with the
# root-only stamp-break-glass CLI (AGT-2260), then
#   - positive controls: a git-shell-commands verb, git push and git clone
#     over SSH all still work (so the refusal below isn't just "auth broke");
#   - the assertion: an sftp session is refused with sshd's
#     "subsystem request failed", via both `sftp` and `ssh -s … sftp`.
echo "docker-boot-smoke: asserting the sftp subsystem is refused while git + git-shell-commands still work…"
sftp_probe_script='set -e
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-sftp -f "$k/id" >/dev/null
# Enroll through users.db, the only source of SSH access (AGT-2260).
/usr/local/sbin/stamp-break-glass add "$k/id.pub" >/dev/null
SSH_OPTS="-i $k/id -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
export GIT_SSH_COMMAND="ssh $SSH_OPTS"

out=$(ssh $SSH_OPTS git@127.0.0.1 list-stamp-repos) || { echo "git-shell-commands verb (list-stamp-repos) failed over SSH" >&2; exit 1; }

su -s /bin/sh git -c "git init -q --bare -b main /srv/git/sftp-smoke.git"
w="$k/w"
git init -q -b main "$w"
git -C "$w" -c user.email=smoke@example.invalid -c user.name=smoke commit -q --allow-empty -m smoke
git -C "$w" push -q git@127.0.0.1:/srv/git/sftp-smoke.git main || { echo "git push over SSH failed" >&2; exit 1; }
git clone -q git@127.0.0.1:/srv/git/sftp-smoke.git "$k/c" || { echo "git clone over SSH failed" >&2; exit 1; }
[ "$(git -C "$k/c" rev-parse HEAD)" = "$(git -C "$w" rev-parse HEAD)" ] || { echo "cloned HEAD does not match pushed HEAD" >&2; exit 1; }

if echo pwd | sftp $SSH_OPTS -b - git@127.0.0.1 >"$k/sftp.out" 2>&1; then
  echo "sftp session OPENED as git — the sftp subsystem bypasses git-shell:" >&2
  cat "$k/sftp.out" >&2
  exit 1
fi
grep -qi "subsystem request failed" "$k/sftp.out" || { echo "sftp failed, but not with a subsystem refusal:" >&2; cat "$k/sftp.out" >&2; exit 1; }

if ssh $SSH_OPTS -s git@127.0.0.1 sftp </dev/null >"$k/ssh-s.out" 2>&1; then
  echo "ssh -s sftp was accepted:" >&2
  cat "$k/ssh-s.out" >&2
  exit 1
fi
grep -qi "subsystem request failed" "$k/ssh-s.out" || { echo "ssh -s sftp failed, but not with a subsystem refusal:" >&2; cat "$k/ssh-s.out" >&2; exit 1; }

rm -rf /srv/git/sftp-smoke.git "$k"
'
if ! docker exec "$CONTAINER_NAME" sh -c "$sftp_probe_script"; then
  echo "error: sftp-subsystem assertion failed (AGT-2271) — see above." >&2
  exit 1
fi
echo "docker-boot-smoke: sftp refused; git push/clone + git-shell-commands work ✓"

# AGT-2259: the repo-management verbs are role-gated. Every SSH user runs
# them as the Unix user `git`, so before the fix any enrolled key —
# including role=member — could create, delete, purge or restore any repo.
# Enroll two throwaway keys in users.db (added as admin with
# stamp-break-glass, the second then demoted to member) and drive the
# verbs over real SSH sessions:
#   - member: new / delete / delete --purge / restore are each refused with
#     exit 3 and leave the repo and its trash copy untouched;
#   - admin: the same four verbs succeed (create → soft delete → restore →
#     purge), so the gate isn't just refusing everyone.
echo "docker-boot-smoke: asserting repo verbs refuse role=member and admit admin…"
role_gate_script='set -e
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-admin -f "$k/admin" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C smoke-member -f "$k/member" >/dev/null
cat "$k/admin.pub" "$k/member.pub" | /usr/local/sbin/stamp-break-glass add - >/dev/null
member_fp=$(ssh-keygen -lf "$k/member.pub" | awk "{print \$2}")
node -e "const {DatabaseSync}=require(\"node:sqlite\");const db=new DatabaseSync(\"/srv/git/.stamp-state/users.db\");const r=db.prepare(\"UPDATE users SET role=? WHERE ssh_fp=?\").run(\"member\",process.argv[1]);if(r.changes!==1)process.exit(1)" "$member_fp"
# new-stamp-repo seeds the operator key as the first trusted signer; the
# smoke container has no OPERATOR_PUB_KEY, so mint a throwaway one.
node -e "process.stdout.write(require(\"node:crypto\").generateKeyPairSync(\"ed25519\").publicKey.export({type:\"spki\",format:\"pem\"}))" > /etc/stamp/operator.pub
chmod 0444 /etc/stamp/operator.pub
OPTS="-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
as() { who=$1; shift; ssh $OPTS -i "$k/$who" git@127.0.0.1 "$@"; }
expect_denied() {
  set +e; as member "$@" >"$k/out" 2>&1; rc=$?; set -e
  if [ $rc -ne 3 ] || ! grep -q "role member is not permitted" "$k/out"; then
    echo "member was NOT refused for: $* (exit $rc)" >&2; cat "$k/out" >&2; exit 1
  fi
}
as admin new-stamp-repo gate-smoke >/dev/null || { echo "admin new-stamp-repo failed" >&2; exit 1; }
[ -d /srv/git/gate-smoke.git ] || { echo "admin create did not create the repo" >&2; exit 1; }

expect_denied new-stamp-repo gate-smoke-member
[ ! -e /srv/git/gate-smoke-member.git ] || { echo "member create left a repo behind" >&2; exit 1; }
expect_denied delete-stamp-repo gate-smoke
expect_denied delete-stamp-repo gate-smoke --purge
[ -d /srv/git/gate-smoke.git ] || { echo "member delete/purge removed the live repo" >&2; exit 1; }

as admin delete-stamp-repo gate-smoke >/dev/null || { echo "admin soft delete failed" >&2; exit 1; }
[ ! -e /srv/git/gate-smoke.git ] || { echo "admin soft delete left the live repo" >&2; exit 1; }
expect_denied restore-stamp-repo gate-smoke
expect_denied delete-stamp-repo gate-smoke --purge
ls /srv/git/.trash | grep -q -- "-gate-smoke.git\$" || { echo "member purge removed the trash copy" >&2; exit 1; }

as admin restore-stamp-repo gate-smoke >/dev/null || { echo "admin restore failed" >&2; exit 1; }
[ -d /srv/git/gate-smoke.git ] || { echo "admin restore did not bring the repo back" >&2; exit 1; }
as admin delete-stamp-repo gate-smoke --purge >/dev/null || { echo "admin purge failed" >&2; exit 1; }
[ ! -e /srv/git/gate-smoke.git ] || { echo "admin purge left the live repo" >&2; exit 1; }

rm -rf "$k" /etc/stamp/operator.pub
'
if ! docker exec "$CONTAINER_NAME" sh -c "$role_gate_script"; then
  echo "error: repo-verb role-gate assertion failed (AGT-2259) — see above." >&2
  exit 1
fi
echo "docker-boot-smoke: member refused new/delete/purge/restore; admin admitted ✓"

# AGT-2265: every session runs through the stamp-gate forced command, which
# only serves live /srv/git/<name>.git repos and applies the member grant
# rule. Over real SSH sessions:
#   - member (no grants): can clone a live repo and push to one, but not
#     .trash, .prompts-cache or a traversal path; list-trash / resync-mirror
#     are refused (exit 3); an interactive login is refused;
#   - admin: create, clone, push, list-trash, resync-mirror all work, and
#     dot-dirs are refused for admins too;
#   - member with a repo grant: only the repo whose .stamp/mirror.yml maps
#     to the grant; other repos and list-stamp-repos are refused.
echo "docker-boot-smoke: asserting the SSH gate scopes reads and keeps git + verbs working…"
read_gate_script='set -e
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-radmin -f "$k/admin" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C smoke-rmember -f "$k/member" >/dev/null
cat "$k/admin.pub" "$k/member.pub" | /usr/local/sbin/stamp-break-glass add - >/dev/null
member_fp=$(ssh-keygen -lf "$k/member.pub" | awk "{print \$2}")
node -e "const {DatabaseSync}=require(\"node:sqlite\");const db=new DatabaseSync(\"/srv/git/.stamp-state/users.db\");const r=db.prepare(\"UPDATE users SET role=? WHERE ssh_fp=?\").run(\"member\",process.argv[1]);if(r.changes!==1)process.exit(1)" "$member_fp"
node -e "process.stdout.write(require(\"node:crypto\").generateKeyPairSync(\"ed25519\").publicKey.export({type:\"spki\",format:\"pem\"}))" > /etc/stamp/operator.pub
chmod 0444 /etc/stamp/operator.pub
OPTS="-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
as() { who=$1; shift; ssh $OPTS -i "$k/$who" git@127.0.0.1 "$@"; }
gitas() { who=$1; shift; GIT_SSH_COMMAND="ssh $OPTS -i $k/$who" git "$@"; }
fail() { echo "$*" >&2; [ -f "$k/out" ] && cat "$k/out" >&2; exit 1; }
expect_rc() { want=$1; who=$2; shift 2; set +e; as "$who" "$@" >"$k/out" 2>&1; rc=$?; set -e; [ $rc -eq $want ] || fail "$who: expected exit $want for: $* (got $rc)"; }
expect_clone_refused() { who=$1; path=$2; pat=$3; rm -rf "$k/c"; if gitas "$who" clone -q "git@127.0.0.1:$path" "$k/c" >"$k/out" 2>&1; then fail "$who cloned $path through the gate"; fi; grep -q "$pat" "$k/out" || fail "$who clone of $path failed, but not with: $pat"; }

# Fixtures: a stamp repo (admin create), a trashed copy, a prompts cache,
# a plain bare repo for pushes, and a repo whose mirror.yml maps to acme/granted.
as admin new-stamp-repo rg-live >/dev/null || fail "admin new-stamp-repo failed"
as admin new-stamp-repo rg-doomed >/dev/null || fail "admin new-stamp-repo (2) failed"
as admin delete-stamp-repo rg-doomed >/dev/null || fail "admin soft delete failed"
trashed=$(ls /srv/git/.trash | grep -- "-rg-doomed.git\$" | head -1)
[ -n "$trashed" ] || fail "no trash entry for rg-doomed"
su -s /bin/sh git -c "git init -q --bare -b main /srv/git/.prompts-cache"
su -s /bin/sh git -c "git init -q --bare -b main /srv/git/rg-plain.git"
w="$k/w"
git init -q -b main "$w"
mkdir -p "$w/.stamp"
printf "github:\n  repo: acme/granted\n" > "$w/.stamp/mirror.yml"
git -C "$w" add -A
git -C "$w" -c user.email=smoke@example.invalid -c user.name=smoke commit -q -m smoke

# Admin: git + verbs through the gate.
gitas admin -C "$w" push -q git@127.0.0.1:/srv/git/rg-plain.git main || fail "admin push through the gate failed"
gitas admin clone -q git@127.0.0.1:/srv/git/rg-live.git "$k/admin-live" || fail "admin clone failed"
gitas admin clone -q git@127.0.0.1:/srv/git/rg-plain "$k/admin-plain" || fail "admin clone without .git suffix failed"
[ "$(git -C "$k/admin-plain" rev-parse HEAD)" = "$(git -C "$w" rev-parse HEAD)" ] || fail "admin clone HEAD mismatch"
expect_rc 0 admin list-trash
grep -q "rg-doomed" "$k/out" || fail "admin list-trash did not show the trash entry"
expect_rc 0 admin list-stamp-repos
expect_rc 0 admin resync-mirror rg-live
expect_clone_refused admin "/srv/git/.trash/$trashed" "not allowed"
expect_clone_refused admin "/srv/git/.prompts-cache" "not allowed"

# Member with no grants: live repos only.
gitas member clone -q git@127.0.0.1:/srv/git/rg-live.git "$k/member-live" || fail "member clone of a live repo failed"
gitas member -C "$w" push -q git@127.0.0.1:/srv/git/rg-plain.git main:refs/heads/member || fail "member push through the gate failed"
expect_clone_refused member "/srv/git/.trash/$trashed" "not allowed"
expect_clone_refused member "/srv/git/.prompts-cache" "not allowed"
expect_clone_refused member "/srv/git/../../srv/git/.trash/$trashed" "not allowed"
expect_clone_refused member "~git/../../srv/git/.trash/$trashed" "not allowed"
expect_rc 2 member "git-upload-pack /srv/git/.trash/$trashed"
expect_rc 2 member "sh -c id"
expect_rc 3 member list-trash
grep -q "role member is not permitted" "$k/out" || fail "member list-trash: wrong refusal"
expect_rc 3 member resync-mirror rg-live
expect_rc 0 member list-stamp-repos
set +e; ssh $OPTS -i "$k/member" git@127.0.0.1 </dev/null >"$k/out" 2>&1; rc=$?; set -e
[ $rc -ne 0 ] && grep -q "interactive sessions are not available" "$k/out" || fail "interactive login was not refused (exit $rc)"

# Member with a grant: only the mapped repo.
su -s /bin/sh git -c "git init -q --bare -b main /srv/git/rg-mapped.git"
gitas admin -C "$w" push -q git@127.0.0.1:/srv/git/rg-mapped.git main || fail "admin push to rg-mapped failed"
member_id=$(node -e "const {DatabaseSync}=require(\"node:sqlite\");const db=new DatabaseSync(\"/srv/git/.stamp-state/users.db\");process.stdout.write(String(db.prepare(\"SELECT id FROM users WHERE ssh_fp=?\").get(process.argv[1]).id))" "$member_fp")
node -e "const {DatabaseSync}=require(\"node:sqlite\");const db=new DatabaseSync(\"/srv/git/.stamp-state/users.db\");db.prepare(\"INSERT INTO user_repo_grants (user_id, org, repo, granted_by, created_at) VALUES (?, ?, ?, NULL, 0)\").run(Number(process.argv[1]),\"acme\",\"granted\")" "$member_id"
gitas member clone -q git@127.0.0.1:/srv/git/rg-mapped.git "$k/member-mapped" || fail "granted member could not clone the mapped repo"
expect_clone_refused member "/srv/git/rg-live.git" "not found or not permitted"
expect_clone_refused member "/srv/git/rg-nope.git" "not found or not permitted"
expect_rc 3 member list-stamp-repos

as admin delete-stamp-repo rg-live --purge >/dev/null
as admin delete-stamp-repo rg-doomed --purge >/dev/null
rm -rf /srv/git/rg-plain.git /srv/git/rg-mapped.git /srv/git/.prompts-cache "$k" /etc/stamp/operator.pub
'
if ! docker exec "$CONTAINER_NAME" sh -c "$read_gate_script"; then
  echo "error: SSH-gate read-scoping assertion failed (AGT-2265) — see above." >&2
  exit 1
fi
echo "docker-boot-smoke: gate refuses .trash/.prompts-cache/ungranted repos; git + verbs work ✓"

# AGT-2260: users.db is the only source of SSH access, and a removed user
# stays removed across reboots. A second container boots with
# AUTHORIZED_KEYS listing two keys (op, gone), so the first boot bootstraps
# both as admins. Over real SSH sessions:
#   - the root-only stamp-break-glass CLI works as root, but is not
#     reachable as git (not executable) nor over SSH (not a verb);
#   - op (promoted to owner with stamp-break-glass) removes gone with
#     `stamp-users remove`, and gone is refused at authentication;
#   - a key only in /home/git/.ssh/authorized_keys{,2} is refused
#     (AuthorizedKeysFile none);
#   - after `docker restart` with AUTHORIZED_KEYS unchanged, the entrypoint
#     re-runs the seeder: gone is still refused, op still works, and the
#     stale authorized_keys file is deleted.
echo "docker-boot-smoke: asserting key revocation survives a reboot and break-glass is root-only…"
REVOKE_KEYS=$(mktemp -d)
for who in op gone fileonly; do
  ssh-keygen -q -t ed25519 -N "" -C "smoke-$who" -f "$REVOKE_KEYS/$who" >/dev/null
done
docker run -d --name "$REVOKE_CONTAINER" \
  -e AUTHORIZED_KEYS="$(cat "$REVOKE_KEYS/op.pub" "$REVOKE_KEYS/gone.pub")" \
  "$IMAGE_TAG" >/dev/null

wait_sshd() {
  local c="${1:-$REVOKE_CONTAINER}"
  for _ in $(seq 1 60); do
    if docker exec "$c" nc -z 127.0.0.1 22 >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "error: sshd in $c did not come up" >&2
  docker logs "$c" 2>&1 | tail -40 >&2 || true
  return 1
}
wait_sshd
docker exec "$REVOKE_CONTAINER" mkdir -m 0700 /root/rk
for f in op op.pub gone gone.pub fileonly fileonly.pub; do
  docker cp "$REVOKE_KEYS/$f" "$REVOKE_CONTAINER:/root/rk/$f" >/dev/null
done

revoke_common='set -e
k=/root/rk
chown root:root $k/*
chmod 0600 $k/op $k/gone $k/fileonly
OPTS="-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
as() { who=$1; shift; ssh $OPTS -i "$k/$who" git@127.0.0.1 "$@"; }
fail() { echo "$*" >&2; [ -f "$k/out" ] && cat "$k/out" >&2; exit 1; }
expect_authfail() {
  who=$1
  set +e; as "$who" list-stamp-repos >"$k/out" 2>&1; rc=$?; set -e
  [ $rc -eq 255 ] && grep -q "Permission denied (publickey" "$k/out" || fail "$who was NOT refused at authentication (exit $rc)"
}
fp() { ssh-keygen -lf "$k/$1.pub" | awk "{print \$2}"; }
'

revoke_boot1="$revoke_common"'
as op list-stamp-repos >/dev/null || fail "bootstrapped key op cannot connect"
as gone list-stamp-repos >/dev/null || fail "bootstrapped key gone cannot connect"

# Break-glass: works as root, not as git, not over SSH.
/usr/local/sbin/stamp-break-glass list >"$k/out" || fail "stamp-break-glass list failed as root"
grep -q "$(fp gone)" "$k/out" || fail "break-glass list does not show the bootstrapped keys"
[ "$(stat -c "%U:%G %a" /usr/local/sbin/stamp-break-glass)" = "root:root 700" ] || fail "stamp-break-glass is not root:root 0700"
if su -s /bin/sh git -c "/usr/local/sbin/stamp-break-glass add --role owner /dev/null" >"$k/out" 2>&1; then fail "git user could run stamp-break-glass"; fi
set +e; as op stamp-break-glass list >"$k/out" 2>&1; rc=$?; set -e
[ $rc -eq 2 ] || fail "stamp-break-glass was reachable over SSH (exit $rc)"
set +e; as op /usr/local/sbin/stamp-break-glass list >"$k/out" 2>&1; rc=$?; set -e
[ $rc -eq 2 ] || fail "/usr/local/sbin/stamp-break-glass was reachable over SSH (exit $rc)"
/usr/local/sbin/stamp-break-glass add --role owner "$k/op.pub" >/dev/null || fail "break-glass promote failed"
[ "$(stat -c "%U:%G %a" /srv/git/.stamp-state/users.db)" = "root:stamp-db 660" ] || fail "users.db not root:stamp-db 0660 after break-glass"

# Revoke gone through the documented CLI path.
gone_name=$(/usr/local/sbin/stamp-break-glass list | awk -F"\t" -v fp="$(fp gone)" "\$4==fp {print \$5}")
[ -n "$gone_name" ] || fail "could not resolve gone short_name"
as op stamp-users remove "$gone_name" >"$k/out" 2>&1 || fail "owner could not remove gone"
expect_authfail gone

# A key only in the per-user authorized_keys files is refused.
cp "$k/fileonly.pub" /home/git/.ssh/authorized_keys
cp "$k/fileonly.pub" /home/git/.ssh/authorized_keys2
chown git:git /home/git/.ssh/authorized_keys /home/git/.ssh/authorized_keys2
chmod 0600 /home/git/.ssh/authorized_keys /home/git/.ssh/authorized_keys2
expect_authfail fileonly
'
if ! docker exec "$REVOKE_CONTAINER" sh -c "$revoke_boot1"; then
  echo "error: key-revocation / break-glass assertion failed (AGT-2260, first boot) — see above." >&2
  exit 1
fi

echo "docker-boot-smoke: restarting the container with AUTHORIZED_KEYS unchanged…"
docker restart "$REVOKE_CONTAINER" >/dev/null
wait_sshd
revoke_boot2="$revoke_common"'
expect_authfail gone
as op list-stamp-repos >/dev/null || fail "op lost access after reboot"
/usr/local/sbin/stamp-break-glass list >"$k/out"
grep -q "$(fp gone)" "$k/out" && fail "removed key gone was re-seeded on reboot"
[ ! -e /home/git/.ssh/authorized_keys ] || fail "stale /home/git/.ssh/authorized_keys survived the reboot"
'
if ! docker exec "$REVOKE_CONTAINER" sh -c "$revoke_boot2"; then
  echo "error: removed key came back after reboot (AGT-2260) — see above." >&2
  exit 1
fi
# Capture first: `docker logs | grep -q` can SIGPIPE docker under pipefail.
revoke_logs=$(docker logs "$REVOKE_CONTAINER" 2>&1)
printf '%s\n' "$revoke_logs" | grep "already bootstrapped" >/dev/null || {
  echo "error: second boot did not report the bootstrap marker (AGT-2260)." >&2
  printf '%s\n' "$revoke_logs" | tail -40 >&2
  exit 1
}
docker rm -f "$REVOKE_CONTAINER" >/dev/null 2>&1 || true
echo "docker-boot-smoke: removed key stays refused across reboot; file-only key refused; break-glass root-only ✓"

# AGT-2263: the review-signing key is root:root 0600, never readable by
# git, and survives a restart that way; stamp-review's signing path (the
# git user → `sudo -n stamp-sign-approval`) works; the helper refuses a
# non-approval payload and any argument; it is not reachable over SSH; the
# scoped boot chown never follows a symlink planted in a repo; and a key a
# pre-AGT-2263 image left git-owned is re-owned at boot. ANTHROPIC_API_KEY
# is a dummy: it only switches on the key bootstrap — nothing here calls
# the model.
echo "docker-boot-smoke: asserting the review-signing key is root-only and signing goes through the root helper (AGT-2263)…"
SIGN_KEYS=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C "smoke-signer" -f "$SIGN_KEYS/op" >/dev/null
docker run -d --name "$SIGN_CONTAINER" \
  -e ANTHROPIC_API_KEY=smoke-dummy-not-a-real-key \
  -e AUTHORIZED_KEYS="$(cat "$SIGN_KEYS/op.pub")" \
  "$IMAGE_TAG" >/dev/null
wait_sshd "$SIGN_CONTAINER"
docker exec "$SIGN_CONTAINER" mkdir -m 0700 /root/sk
docker cp "$SIGN_KEYS/op" "$SIGN_CONTAINER:/root/sk/op" >/dev/null
# Signs a fresh canonical approval through the helper exactly as
# stamp-review does (as git, sudo -n, payload on stdin), verifies the
# signature against the .pub, then checks the refusals.
cat > "$SIGN_KEYS/signcheck.cjs" <<'JS'
const c = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const pem = fs.readFileSync("/srv/git/.stamp-state/review-signing-key.pub", "utf8");
const pub = c.createPublicKey(pem);
const fp = "sha256:" + c.createHash("sha256").update(pub.export({ type: "spki", format: "der" })).digest("hex");
const sortKeys = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));
const approval = {
  reviewer: "security", verdict: "approved",
  prompt_sha256: "a".repeat(64), diff_sha256: "b".repeat(64),
  base_sha: "0".repeat(40), head_sha: "1".repeat(40),
  issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  server_key_id: fp, repo_id: "acme/widget",
};
const bytes = Buffer.from(JSON.stringify(sortKeys(approval)));
const helper = ["-n", "/usr/local/sbin/stamp-sign-approval"];
const ok = spawnSync("sudo", helper, { input: bytes });
if (ok.status !== 0) { console.error("helper failed:", ok.status, String(ok.stderr)); process.exit(1); }
const sig = String(ok.stdout).trim();
if (!c.verify(null, bytes, pub, Buffer.from(sig, "base64"))) { console.error("signature does not verify"); process.exit(1); }
const bad = spawnSync("sudo", helper, { input: Buffer.from('{"msg":"sign me"}') });
if (bad.status !== 2 || String(bad.stdout) !== "") { console.error("helper did not refuse a non-approval payload:", bad.status); process.exit(1); }
const raw = spawnSync("sudo", helper, { input: Buffer.from("arbitrary bytes") });
if (raw.status !== 2 || String(raw.stdout) !== "") { console.error("helper did not refuse arbitrary bytes:", raw.status); process.exit(1); }
const args = spawnSync("sudo", [...helper, "--x"], { input: bytes });
if (args.status === 0) { console.error("sudo admitted the helper with an argument"); process.exit(1); }
console.log("signcheck ok");
JS
docker cp "$SIGN_KEYS/signcheck.cjs" "$SIGN_CONTAINER:/tmp/signcheck.cjs" >/dev/null
docker exec "$SIGN_CONTAINER" chmod 0644 /tmp/signcheck.cjs

sign_common='set -e
k=/root/sk
chmod 0600 $k/op
K=/srv/git/.stamp-state/review-signing-key.pem
P=/srv/git/.stamp-state/review-signing-key.pub
OPTS="-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
fail() { echo "$*" >&2; [ -f "$k/out" ] && cat "$k/out" >&2; exit 1; }
[ "$(stat -c "%U:%G %a" $K)" = "root:root 600" ] || fail "review-signing key is $(stat -c "%U:%G %a" $K), want root:root 600"
[ "$(stat -c "%U:%G %a" $P)" = "root:root 644" ] || fail "review-signing pub is $(stat -c "%U:%G %a" $P), want root:root 644"
if su -s /bin/sh git -c "cat $K" >/dev/null 2>&1; then fail "git user can read the review-signing key"; fi
su -s /bin/sh git -c "cat $P" >/dev/null || fail "git user cannot read the review-signing pub"
su -s /bin/sh git -c "node /tmp/signcheck.cjs" >"$k/out" 2>&1 || fail "signing through stamp-sign-approval failed"
set +e; ssh $OPTS -i $k/op git@127.0.0.1 stamp-sign-approval </dev/null >"$k/out" 2>&1; rc=$?; set -e
[ $rc -eq 2 ] || fail "stamp-sign-approval was reachable over SSH (exit $rc)"
set +e; ssh $OPTS -i $k/op git@127.0.0.1 /usr/local/sbin/stamp-sign-approval </dev/null >"$k/out" 2>&1; rc=$?; set -e
[ $rc -eq 2 ] || fail "/usr/local/sbin/stamp-sign-approval was reachable over SSH (exit $rc)"
[ ! -e /home/git/git-shell-commands/stamp-sign-approval ] || fail "stamp-sign-approval is in git-shell-commands"
# AGT-2276: the capability probe answers through the gate (an enrolled
# key over SSH), reporting that this image signs repo_id into approvals.
caps=$(ssh $OPTS -i $k/op git@127.0.0.1 stamp-server-pubkey --capabilities 2>"$k/out") || fail "stamp-server-pubkey --capabilities failed over SSH"
[ "$caps" = "{\"approval_repo_id\":true}" ] || fail "capability probe answered: $caps"
'
sign_boot1="$sign_common"'
# Plant a symlink to a root-only file inside a repo; the next boot chown
# must re-own the link, not its target.
su -s /bin/sh git -c "git init -q --bare /srv/git/smoke.git"
echo sentinel > /root/sentinel && chmod 0600 /root/sentinel
ln -s /root/sentinel /srv/git/smoke.git/evil-link
# Simulate a key left git-owned by a pre-AGT-2263 image.
chown git:git $K $P
'
if ! docker exec "$SIGN_CONTAINER" sh -c "$sign_boot1"; then
  echo "error: review-signing key / helper assertion failed (AGT-2263, first boot) — see above." >&2
  docker logs "$SIGN_CONTAINER" 2>&1 | tail -40 >&2 || true
  exit 1
fi
echo "docker-boot-smoke: restarting the signing container (legacy git-owned key planted)…"
docker restart "$SIGN_CONTAINER" >/dev/null
wait_sshd "$SIGN_CONTAINER"
sign_boot2="$sign_common"'
[ "$(stat -c "%U:%G" /root/sentinel)" = "root:root" ] || fail "boot chown followed a symlink planted in a repo"
[ "$(stat -c "%U" /srv/git/smoke.git/HEAD)" = "git" ] || fail "boot chown did not re-own repo contents to git"
'
if ! docker exec "$SIGN_CONTAINER" sh -c "$sign_boot2"; then
  echo "error: review-signing key / helper assertion failed after restart (AGT-2263) — see above." >&2
  docker logs "$SIGN_CONTAINER" 2>&1 | tail -40 >&2 || true
  exit 1
fi
sign_logs=$(docker logs "$SIGN_CONTAINER" 2>&1)
printf '%s\n' "$sign_logs" | grep "re-owned legacy git-owned" >/dev/null || {
  echo "error: second boot did not report re-owning the legacy git-owned key (AGT-2263)." >&2
  printf '%s\n' "$sign_logs" | tail -40 >&2
  exit 1
}
printf '%s\n' "$sign_logs" | grep "stamp-sign-approval: signed reviewer=security" >/dev/null || {
  echo "error: stamp-sign-approval did not write its audit line to the container log (AGT-2263)." >&2
  printf '%s\n' "$sign_logs" | tail -40 >&2
  exit 1
}
docker rm -f "$SIGN_CONTAINER" >/dev/null 2>&1 || true
echo "docker-boot-smoke: review-signing key root:root 0600 across restart; git signs only via the helper; helper refuses non-approvals; not reachable over SSH ✓"

# AGT-2261: the boot-time hook refresh runs as root over git-owned repos and
# must never follow a symlink the git user planted there. As git, plant
#   - hooks/pre-receive + hooks/post-receive as symlinks to root-only files,
#     and (in a second repo) to a root-only directory,
#   - a whole hooks/ dir as a symlink to a root-only dir,
#   - a repo path /srv/git/<x>.git as a symlink to a dir outside the volume,
#   - a symlink at the refresh's staging path,
#   - core.hooksPath in h1.git/config pointing at an accept-all hook dir
#     (AGT-2249),
# restart, and require: core.hooksPath stripped (and logged), every target untouched (bytes, owner, mode, dir
# listing), real root:root 0755 hooks byte-identical to /etc/stamp/*.cjs in
# their place, and a push to the repo still running the stamp pre-receive
# hook (unsigned main rejected; a fast-forward of an unprotected branch
# seeded before the hooks went in is accepted).
echo "docker-boot-smoke: asserting the boot hook refresh never follows planted symlinks (AGT-2261)…"
HOOKS_TMP=$(mktemp -d)
cat > "$HOOKS_TMP/plant.sh" <<'SH'
set -e
mkdir -m 0700 /root/hs
printf 'sentinel-pre\n' > /root/hs/pre-target
printf 'sentinel-post\n' > /root/hs/post-target
mkdir -m 0700 /root/hs/dir-target /root/hs/repo-target /root/hs/repo-target/hooks /root/hs/linkdir-target
printf 'marker\n' > /root/hs/dir-target/marker
chmod 0600 /root/hs/pre-target /root/hs/post-target /root/hs/dir-target/marker
# Seed a stamp-configured repo as git, before any stamp hook is installed.
su -s /bin/sh git -c "
  set -e
  export HOME=/tmp/hs-home; mkdir -p \$HOME
  git init -q --bare -b main /srv/git/h1.git
  git clone -q /srv/git/h1.git \$HOME/w 2>/dev/null
  cd \$HOME/w
  git config user.email smoke@example.invalid; git config user.name smoke
  git checkout -q -b main
  mkdir -p .stamp
  printf 'branches:\n  main:\n    required: [security]\nreviewers:\n  security:\n    prompt: x\n' > .stamp/config.yml
  git add -A; git commit -qm seed; git push -q origin main
  git push -q origin main:scratch
  git init -q --bare -b main /srv/git/h2.git
  git init -q --bare -b main /srv/git/h4.git
  # The plants — all done by the git user, the foothold being modelled.
  rm -f /srv/git/h1.git/hooks/pre-receive /srv/git/h1.git/hooks/post-receive
  ln -s /root/hs/pre-target  /srv/git/h1.git/hooks/pre-receive
  ln -s /root/hs/post-target /srv/git/h1.git/hooks/post-receive
  rm -rf /srv/git/h2.git/hooks
  ln -s /root/hs/dir-target /srv/git/h2.git/hooks
  ln -s /root/hs/repo-target /srv/git/h3.git
  ln -s /root/hs/linkdir-target /srv/git/h4.git/hooks/pre-receive
  ln -s /root/hs/linkdir-target /srv/git/h4.git/hooks/post-receive
  ln -s /root/hs/dir-target /srv/git/.stamp-hook-staging
  # AGT-2249: redirect h1's hooks to an accept-all dir via its config.
  mkdir -p \$HOME/evil-hooks
  printf '#!/bin/sh\nexit 0\n' > \$HOME/evil-hooks/pre-receive
  chmod 0755 \$HOME/evil-hooks/pre-receive
  git --git-dir=/srv/git/h1.git config core.hooksPath \$HOME/evil-hooks
"
SH
cat > "$HOOKS_TMP/check.sh" <<'SH'
set -e
fail() { echo "$*" >&2; exit 1; }
want() { [ "$(stat -c '%U:%G %a' "$1")" = "$2" ] || fail "$1 is $(stat -c '%U:%G %a' "$1"), want $2"; }
[ "$(cat /root/hs/pre-target)" = sentinel-pre ] || fail "refresh wrote through hooks/pre-receive symlink"
[ "$(cat /root/hs/post-target)" = sentinel-post ] || fail "refresh wrote through hooks/post-receive symlink"
want /root/hs/pre-target "root:root 600"
want /root/hs/post-target "root:root 600"
want /root/hs/dir-target/marker "root:root 600"
[ "$(ls -A /root/hs/dir-target)" = marker ] || fail "refresh wrote into a symlinked hooks/ dir: $(ls -A /root/hs/dir-target)"
[ -z "$(ls -A /root/hs/repo-target/hooks)" ] || fail "refresh wrote into a symlinked repo path"
[ -z "$(ls -A /root/hs/linkdir-target)" ] || fail "refresh moved a hook into the directory a hooks/<name> symlink points at"
[ -L /srv/git/h3.git ] || fail "symlinked repo path was not left alone"
[ ! -e /srv/git/.stamp-hook-staging ] && [ ! -L /srv/git/.stamp-hook-staging ] || fail "staging dir left behind"
for r in h1 h2 h4; do
  [ ! -L /srv/git/$r.git/hooks ] && [ -d /srv/git/$r.git/hooks ] || fail "$r hooks/ is not a real directory"
  want /srv/git/$r.git/hooks "git:git 755"
  for hk in pre-receive post-receive; do
    f=/srv/git/$r.git/hooks/$hk
    [ ! -L "$f" ] && [ -f "$f" ] || fail "$f is not a regular file"
    want "$f" "root:root 755"
    cmp -s "$f" /etc/stamp/$hk.cjs || fail "$f is not the image bundle"
  done
done
# AGT-2249: the planted core.hooksPath is gone, so the push below meets
# the stamp pre-receive rather than the accept-all one.
if git config --file /srv/git/h1.git/config --get core.hooksPath >/dev/null; then
  fail "core.hooksPath survived the boot refresh in h1.git/config"
fi
# The installed hooks still run on a normal push.
su -s /bin/sh git -c "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp/hs-home sh -c '
  set -e
  cd /tmp/hs-home/w
  echo x > x; git add -A; git commit -qm unsigned
  if git push origin HEAD:main 2>push.err; then echo \"unsigned push to main was accepted\" >&2; exit 1; fi
  grep -q \"stamp-verify: rejecting refs/heads/main\" push.err || { cat push.err >&2; exit 1; }
  git push -q origin HEAD:scratch || { echo \"push to an unprotected branch failed\" >&2; exit 1; }
'" || fail "push through the refreshed hooks did not behave"
SH
docker run -d --name "$HOOKS_CONTAINER" "$IMAGE_TAG" >/dev/null
wait_sshd "$HOOKS_CONTAINER"
docker cp "$HOOKS_TMP/plant.sh" "$HOOKS_CONTAINER:/root/plant.sh" >/dev/null
docker cp "$HOOKS_TMP/check.sh" "$HOOKS_CONTAINER:/root/check.sh" >/dev/null
if ! docker exec "$HOOKS_CONTAINER" sh /root/plant.sh; then
  echo "error: could not plant the hook symlinks (AGT-2261) — see above." >&2
  exit 1
fi
docker restart "$HOOKS_CONTAINER" >/dev/null
wait_sshd "$HOOKS_CONTAINER"
if ! docker exec "$HOOKS_CONTAINER" sh /root/check.sh; then
  echo "error: boot hook refresh followed a planted symlink or left broken hooks (AGT-2261) — see above." >&2
  docker logs "$HOOKS_CONTAINER" 2>&1 | tail -40 >&2 || true
  exit 1
fi
hooks_logs=$(docker logs "$HOOKS_CONTAINER" 2>&1)
for want_line in "was a symlink; replacing the link" "is not a real directory; replacing it" "skipping symlinked repo path" "removed 'core.hookspath' from /srv/git/h1.git/config"; do
  printf '%s\n' "$hooks_logs" | grep -F "$want_line" >/dev/null || {
    echo "error: boot log is missing the refresh warning '$want_line' (AGT-2261)." >&2
    printf '%s\n' "$hooks_logs" | tail -40 >&2
    exit 1
  }
done
docker rm -f "$HOOKS_CONTAINER" >/dev/null 2>&1 || true
echo "docker-boot-smoke: hook refresh replaces planted symlinks without touching their targets; refreshed hooks still gate pushes ✓"

# AGT-2264: the internet-facing HTTP listener runs as the unprivileged
# stamp-http user with an explicit allowlisted environment, and the
# git-file workers (prompts refresh, trash sweep) run as git in a separate
# stamp-workers process. A dedicated container boots with fake secrets in its
# env and Phase B pointed at a local file:// prompts repo, then asserts:
#   - the listener's uid is stamp-http, it is not in the git group, and its
#     /proc/<pid>/environ holds none of the container secrets (bot token,
#     API key, AUTHORIZED_KEYS, platform vars, the prompts repo URL) — only
#     its allowlist, incl. the webhook HMAC secret it needs;
#   - stamp-workers runs as git and holds neither the secrets nor the
#     webhook secret;
#   - as stamp-http: /etc/stamp/env, the review-signing key, the mirror
#     deploy keys, the prompts cache and repos (incl. a pre-upgrade
#     world-readable one, closed on reboot) are unreadable, /srv/git can't
#     be listed, there is no sudo right — but users.db is writable;
#   - the endpoints still work: /healthz; /invite/accept writes a row the
#     git-run SSH key resolver honours (the new key logs in); a signed
#     webhook is handed to stamp-workers, which refreshes the cache; the
#     peer endpoints are live (signature check, not 404).
echo "docker-boot-smoke: asserting the HTTP listener runs as stamp-http with an allowlisted env (AGT-2264)…"
listen_pre='set -e
if [ ! -d /opt/prompts.git ]; then
  mkdir -p /opt/psrc && cd /opt/psrc && git init -q -b main w && cd w
  printf "smoke prompt\n" > security.md
  git add -A && git -c user.email=s@x.invalid -c user.name=s commit -qm init
  git clone -q --bare /opt/psrc/w /opt/prompts.git && chown -R git:git /opt/prompts.git
fi
exec /entrypoint.sh'
docker run -d --name "$LISTEN_CONTAINER" --entrypoint sh \
  -e GITHUB_BOT_TOKEN=smoke-gh-token-must-not-leak \
  -e ANTHROPIC_API_KEY=smoke-anthropic-key-must-not-leak \
  -e SMOKE_PLATFORM_VAR=smoke-platform-must-not-leak \
  -e STAMP_PROMPTS_WEBHOOK_SECRET=smoke-hook-secret \
  -e STAMP_PEER_REVIEWS_ENABLED=1 \
  -e STAMP_PROMPTS_REPO_URL=file:///opt/prompts.git \
  "$IMAGE_TAG" -c "$listen_pre" >/dev/null
wait_sshd "$LISTEN_CONTAINER"

listen_common='set -e
fail() { echo "$*" >&2; exit 1; }
asl() { su -s /bin/sh stamp-http -c "$1"; }
pid_of() {
  for p in /proc/[0-9]*; do
    c=$(tr "\0" " " <"$p/cmdline" 2>/dev/null) || continue
    case "$c" in "node $1 "*|"node $1") echo "${p#/proc/}"; return 0 ;; esac
  done
  return 1
}
for _ in $(seq 1 40); do nc -z 127.0.0.1 8080 >/dev/null 2>&1 && break; sleep 0.25; done
L=$(pid_of /usr/local/sbin/stamp-http-server) || fail "stamp-http-server is not running"
W=$(pid_of /usr/local/sbin/stamp-workers) || fail "stamp-workers is not running"
'

listen_boot1="$listen_common"'
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-op -f "$k/op" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C smoke-new -f "$k/new" >/dev/null
/usr/local/sbin/stamp-break-glass add "$k/op.pub" >/dev/null
OPTS="-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
as() { who=$1; shift; ssh $OPTS -i "$k/$who" git@127.0.0.1 "$@"; }

# --- identity -----------------------------------------------------------
[ "$(awk "/^Uid:/{print \$2}" /proc/$L/status)" = "$(id -u stamp-http)" ] || fail "listener uid is not stamp-http"
gid_git=$(getent group git | cut -d: -f3)
awk "/^(Gid|Groups):/" /proc/$L/status | tr -s " \t" "\n" | grep -qx "$gid_git" && fail "listener has the git group"
id -nG stamp-http | tr " " "\n" | grep -qx git && fail "stamp-http is a member of the git group"
[ "$(awk "/^Uid:/{print \$2}" /proc/$W/status)" = "$(id -u git)" ] || fail "stamp-workers uid is not git"

# --- environment (root lacks CAP_SYS_PTRACE here; read as the same uid) ---
asl "cat /proc/$L/environ" | tr "\0" "\n" > "$k/lenv"
grep -q "must-not-leak" "$k/lenv" && fail "a container secret reached the listener env: $(grep must-not-leak "$k/lenv" | cut -d= -f1)"
for v in GITHUB_BOT_TOKEN ANTHROPIC_API_KEY AUTHORIZED_KEYS SMOKE_PLATFORM_VAR HOSTNAME STAMP_PROMPTS_REPO_URL STAMP_PROMPTS_DEPLOY_KEY_PATH; do
  grep -q "^$v=" "$k/lenv" && fail "listener env carries $v"
done
grep -qx "STAMP_PROMPTS_WEBHOOK_SECRET=smoke-hook-secret" "$k/lenv" || fail "listener env lacks its webhook secret"
grep -qx "STAMP_PEER_REVIEWS_ENABLED=1" "$k/lenv" || fail "listener env lacks STAMP_PEER_REVIEWS_ENABLED"
grep -qx "HOME=/var/empty" "$k/lenv" || fail "listener HOME is not /var/empty"
su -s /bin/sh git -c "cat /proc/$W/environ" | tr "\0" "\n" > "$k/wenv"
grep -q "must-not-leak" "$k/wenv" && fail "a container secret reached the workers env"
grep -q "^STAMP_PROMPTS_WEBHOOK_SECRET=" "$k/wenv" && fail "workers env carries the webhook secret"
grep -qx "STAMP_PROMPTS_REPO_URL=file:///opt/prompts.git" "$k/wenv" || fail "workers env lacks STAMP_PROMPTS_REPO_URL"

# --- file access as stamp-http -------------------------------------------
node -e "process.stdout.write(require(\"node:crypto\").generateKeyPairSync(\"ed25519\").publicKey.export({type:\"spki\",format:\"pem\"}))" > /etc/stamp/operator.pub
chmod 0444 /etc/stamp/operator.pub
as op new-stamp-repo listen-smoke >/dev/null || fail "admin new-stamp-repo failed"
# A pre-upgrade repo: world-readable, closed by the next boot.
su -s /bin/sh git -c "umask 022; git init -q --bare /srv/git/legacy-smoke.git"
for f in /etc/stamp/env /srv/git/.stamp-state/review-signing-key.pem /srv/git/.ssh-client-keys/github_ed25519 /srv/git/listen-smoke.git/HEAD /srv/git/.prompts-cache/security.md; do
  [ -e "$f" ] || fail "fixture $f missing"
  asl "cat $f" >/dev/null 2>&1 && fail "stamp-http can read $f"
done
for d in /srv/git /srv/git/.ssh-client-keys /srv/git/listen-smoke.git /srv/git/.prompts-cache; do
  asl "ls $d" >/dev/null 2>&1 && fail "stamp-http can list $d"
done
asl "sudo -n -l" >/dev/null 2>&1 && fail "stamp-http has a sudo rule"
asl "sudo -n /usr/local/sbin/stamp-sign-approval \"\"" </dev/null >/dev/null 2>&1 && fail "stamp-http can run the signing helper"
asl "test -w /srv/git/.stamp-state/users.db" || fail "stamp-http cannot write users.db"
[ "$(stat -c "%U:%G %a" /srv/git/.stamp-state/users.db)" = "root:stamp-db 660" ] || fail "users.db is $(stat -c "%U:%G %a" /srv/git/.stamp-state/users.db)"
[ "$(stat -c "%U:%G %a" /srv/git/.stamp-state)" = "root:stamp-db 3770" ] || fail ".stamp-state is $(stat -c "%U:%G %a" /srv/git/.stamp-state)"

# --- endpoints still work ------------------------------------------------
node -e "fetch(\"http://127.0.0.1:8080/healthz\").then(r=>process.exit(r.status===200?0:1),()=>process.exit(1))" || fail "/healthz failed"
op_id=$(node -e "const {DatabaseSync}=require(\"node:sqlite\");const db=new DatabaseSync(\"/srv/git/.stamp-state/users.db\",{readOnly:true});process.stdout.write(String(db.prepare(\"SELECT id FROM users LIMIT 1\").get().id))")
# Minted as git: the git user still writes the DB alongside stamp-http.
cat > /tmp/mint2264.cjs <<MINT
const {DatabaseSync}=require("node:sqlite");
const db=new DatabaseSync("/srv/git/.stamp-state/users.db");
const n=Math.floor(Date.now()/1000);
db.prepare("INSERT INTO invites(token,role,invited_by,created_at,expires_at) VALUES(?,?,?,?,?)").run("smoketoken2264","member",Number(process.argv[2]),n,n+3600);
MINT
chmod 0644 /tmp/mint2264.cjs
su -s /bin/sh git -c "node /tmp/mint2264.cjs $op_id" || fail "git could not mint an invite"
node -e "
const pub=require(\"fs\").readFileSync(process.argv[1],\"utf8\").trim();
fetch(\"http://127.0.0.1:8080/invite/accept\",{method:\"POST\",headers:{\"content-type\":\"application/json\"},body:JSON.stringify({token:\"smoketoken2264\",ssh_pubkey:pub,short_name:\"smoke-new\"})})
.then(async r=>{const b=await r.text();if(r.status!==200){console.error(r.status,b);process.exit(1)}})
.catch(e=>{console.error(e);process.exit(1)})" "$k/new.pub" || fail "/invite/accept failed"
as new list-stamp-repos >/dev/null || fail "key enrolled through /invite/accept cannot log in"
node -e "
const c=require(\"crypto\");const body=Buffer.from(\"{}\");
const sig=\"sha256=\"+c.createHmac(\"sha256\",\"smoke-hook-secret\").update(body).digest(\"hex\");
fetch(\"http://127.0.0.1:8080/webhook/prompts\",{method:\"POST\",headers:{\"x-hub-signature-256\":sig,\"x-github-delivery\":\"smoke-delivery-2264\"},body})
.then(r=>process.exit(r.status===202?0:1),()=>process.exit(1))" || fail "signed webhook was not accepted"
[ "$(cat /run/stamp-http/prompts-refresh)" = "smoke-delivery-2264" ] || fail "webhook did not write the refresh trigger"
code=$(node -e "fetch(\"http://127.0.0.1:8080/peer/claim-seat\",{method:\"POST\",body:\"{}\"}).then(r=>process.stdout.write(String(r.status)),()=>process.stdout.write(\"ERR\"))")
case "$code" in 400|401|403) ;; *) fail "/peer/claim-seat returned $code (want an auth/validation refusal, not 404/5xx)" ;; esac
rm -rf "$k" /tmp/mint2264.cjs /etc/stamp/operator.pub
# Roll the DB back to the pre-upgrade layout; the next boot must convert it.
chgrp git /srv/git/.stamp-state /srv/git/.stamp-state/users.db
chmod 1770 /srv/git/.stamp-state
'
if ! docker exec "$LISTEN_CONTAINER" sh -c "$listen_boot1"; then
  echo "error: HTTP listener isolation assertion failed (AGT-2264) — see above." >&2
  docker logs "$LISTEN_CONTAINER" 2>&1 | tail -30 >&2 || true
  exit 1
fi
listen_refreshed=""
for _ in $(seq 1 40); do
  listen_logs=$(docker logs "$LISTEN_CONTAINER" 2>&1)
  if printf '%s\n' "$listen_logs" | grep "^stamp-workers .*refresh ok delivery=smoke-delivery-2264" >/dev/null; then
    listen_refreshed=1; break
  fi
  sleep 0.25
done
if [ -z "$listen_refreshed" ]; then
  echo "error: stamp-workers did not refresh the prompts cache after the webhook (AGT-2264)." >&2
  printf '%s\n' "$listen_logs" | tail -30 >&2
  exit 1
fi

echo "docker-boot-smoke: restarting the listener container (pre-upgrade world-readable repo + root:git DB planted)…"
docker restart "$LISTEN_CONTAINER" >/dev/null
wait_sshd "$LISTEN_CONTAINER"
listen_boot2="$listen_common"'
[ "$(awk "/^Uid:/{print \$2}" /proc/$L/status)" = "$(id -u stamp-http)" ] || fail "listener uid is not stamp-http after restart"
asl "cat /srv/git/legacy-smoke.git/HEAD" >/dev/null 2>&1 && fail "pre-upgrade repo still readable by stamp-http after reboot"
[ "$(stat -c "%a" /srv/git/legacy-smoke.git)" = "750" ] || fail "legacy repo mode is $(stat -c "%a" /srv/git/legacy-smoke.git), want 750"
[ "$(stat -c "%U:%G %a" /srv/git/.stamp-state)" = "root:stamp-db 3770" ] || fail "pre-upgrade .stamp-state not converted: $(stat -c "%U:%G %a" /srv/git/.stamp-state)"
[ "$(stat -c "%U:%G %a" /srv/git/.stamp-state/users.db)" = "root:stamp-db 660" ] || fail "pre-upgrade users.db not converted: $(stat -c "%U:%G %a" /srv/git/.stamp-state/users.db)"
asl "test -w /srv/git/.stamp-state/users.db" || fail "stamp-http cannot write the converted users.db"
[ "$(stat -c "%U:%G %a" /srv/git/.stamp-state/review-signing-key.pem)" = "root:root 600" ] || fail "review key is $(stat -c "%U:%G %a" /srv/git/.stamp-state/review-signing-key.pem) after restart"
node -e "fetch(\"http://127.0.0.1:8080/healthz\").then(r=>process.exit(r.status===200?0:1),()=>process.exit(1))" || fail "/healthz failed after restart"
# AGT-2270: the listener runs under a restart loop; kill it and expect a
# new process back on the port.
kill "$L"
L2=""
for _ in $(seq 1 60); do
  if P=$(pid_of /usr/local/sbin/stamp-http-server) && [ "$P" != "$L" ] && nc -z 127.0.0.1 8080 >/dev/null 2>&1; then L2=$P; break; fi
  sleep 0.25
done
[ -n "$L2" ] || fail "stamp-http-server was not restarted after it exited (AGT-2270)"
[ "$(awk "/^Uid:/{print \$2}" /proc/$L2/status)" = "$(id -u stamp-http)" ] || fail "restarted listener uid is not stamp-http"
'
if ! docker exec "$LISTEN_CONTAINER" sh -c "$listen_boot2"; then
  echo "error: HTTP listener isolation assertion failed after restart (AGT-2264) — see above." >&2
  docker logs "$LISTEN_CONTAINER" 2>&1 | tail -30 >&2 || true
  exit 1
fi
docker rm -f "$LISTEN_CONTAINER" >/dev/null 2>&1 || true
echo "docker-boot-smoke: listener runs as stamp-http with only its allowlisted env; secrets, keys and repos unreachable; invite/webhook/peer endpoints work ✓"

health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
echo "docker-boot-smoke: container up after ${BOOT_WAIT_SECS}s ✓  (healthcheck: $health)"
exit 0
