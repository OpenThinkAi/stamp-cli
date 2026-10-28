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
# smoke runs can't clash): a throwaway key goes into the git user's
# AuthorizedKeysFile fallback, then
#   - positive controls: a git-shell-commands verb, git push and git clone
#     over SSH all still work (so the refusal below isn't just "auth broke");
#   - the assertion: an sftp session is refused with sshd's
#     "subsystem request failed", via both `sftp` and `ssh -s … sftp`.
echo "docker-boot-smoke: asserting the sftp subsystem is refused while git + git-shell-commands still work…"
sftp_probe_script='set -e
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-sftp -f "$k/id" >/dev/null
# Enroll through users.db (the AuthorizedKeysCommand path): since AGT-2265
# every session runs the stamp-gate forced command, which refuses keys
# that are not in the membership DB.
AUTHORIZED_KEYS="$(cat "$k/id.pub")" /usr/local/sbin/stamp-seed-users >/dev/null
chown root:git /srv/git/.stamp-state/users.db
chmod 0660 /srv/git/.stamp-state/users.db
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
# Enroll two throwaway keys in users.db (seeded as admin, the second then
# demoted to member) and drive the verbs over real SSH sessions:
#   - member: new / delete / delete --purge / restore are each refused with
#     exit 3 and leave the repo and its trash copy untouched;
#   - admin: the same four verbs succeed (create → soft delete → restore →
#     purge), so the gate isn't just refusing everyone.
echo "docker-boot-smoke: asserting repo verbs refuse role=member and admit admin…"
role_gate_script='set -e
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-admin -f "$k/admin" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C smoke-member -f "$k/member" >/dev/null
AUTHORIZED_KEYS="$(cat "$k/admin.pub" "$k/member.pub")" /usr/local/sbin/stamp-seed-users >/dev/null
chown root:git /srv/git/.stamp-state/users.db
chmod 0660 /srv/git/.stamp-state/users.db
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
#     to the grant; other repos and list-stamp-repos are refused;
#   - a key in the legacy AuthorizedKeysFile (written by entrypoint's
#     helper) still goes through the gate, so an unenrolled one is refused.
echo "docker-boot-smoke: asserting the SSH gate scopes reads and keeps git + verbs working…"
read_gate_script='set -e
k=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -C smoke-radmin -f "$k/admin" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C smoke-rmember -f "$k/member" >/dev/null
ssh-keygen -q -t ed25519 -N "" -C smoke-legacy -f "$k/legacy" >/dev/null
AUTHORIZED_KEYS="$(cat "$k/admin.pub" "$k/member.pub")" /usr/local/sbin/stamp-seed-users >/dev/null
chown root:git /srv/git/.stamp-state/users.db
chmod 0660 /srv/git/.stamp-state/users.db
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

# Legacy AuthorizedKeysFile: gated too, so an unenrolled key gets nothing.
. /lib/gate-authorized-keys.sh
_gate_authorized_keys < "$k/legacy.pub" > /home/git/.ssh/authorized_keys
chown git:git /home/git/.ssh/authorized_keys
chmod 0600 /home/git/.ssh/authorized_keys
grep -q "^command=\"stamp-gate legacy\",restrict ssh-ed25519 " /home/git/.ssh/authorized_keys || fail "legacy file line is not gated"
expect_rc 1 legacy list-stamp-repos
grep -q "not in the membership DB" "$k/out" || fail "legacy key: wrong refusal"
expect_clone_refused legacy "/srv/git/rg-live.git" "not in the membership DB"
: > /home/git/.ssh/authorized_keys

as admin delete-stamp-repo rg-live --purge >/dev/null
as admin delete-stamp-repo rg-doomed --purge >/dev/null
rm -rf /srv/git/rg-plain.git /srv/git/rg-mapped.git /srv/git/.prompts-cache "$k" /etc/stamp/operator.pub
'
if ! docker exec "$CONTAINER_NAME" sh -c "$read_gate_script"; then
  echo "error: SSH-gate read-scoping assertion failed (AGT-2265) — see above." >&2
  exit 1
fi
echo "docker-boot-smoke: gate refuses .trash/.prompts-cache/ungranted repos; git + verbs work ✓"

health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
echo "docker-boot-smoke: container up after ${BOOT_WAIT_SECS}s ✓  (healthcheck: $health)"
exit 0
