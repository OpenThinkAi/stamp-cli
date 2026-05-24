# stamp server

A minimal Docker image that runs a bare git server with `sshd` and the
`stamp-verify` pre-receive hook installed. Any git client with SSH access
can push to it; the hook enforces stamp-cli's verification rules on the
protected branches defined in each repo's committed `.stamp/config.yml`.

## What's in the image

- `git` + `openssh-server` + `nodejs` (Alpine-based, ~200 MB)
- `/etc/stamp/pre-receive` — the built hook
- `/etc/stamp/reviewers/` — canonical reviewer prompts (`security.md`, `standards.md`, `product.md`), bundled at build time from `server/reviewers/` in the repo
- `/usr/local/bin/setup-repo.sh` — bootstrap script
- `/usr/local/bin/new-stamp-repo <name>` — one-line repo provisioner
- `/entrypoint.sh` — sets up `authorized_keys` + operator pub key from env,
  then boots sshd

## Reviewer prompts

The Docker image bundles canonical reviewer prompts at `/etc/stamp/reviewers/<name>.md`. The SSH-invoked `stamp-review` command reads them from this path at review time, computes `sha256(bytes)`, and includes that hash in the signed verdict. The hash is what gives the server its "operator controls prompt bytes" trust property — substituting a prompt at runtime would change the hash and break downstream verification.

**Path resolution.** The pipeline reads `${STAMP_PROMPTS_DIR:-/etc/stamp/reviewers}/<reviewer>.md`. The reviewer name is validated against `REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/` before path construction (`src/server/promptFetch.ts`), so `--reviewer` cannot be used to traverse out of the configured directory.

> **`STAMP_PROMPTS_DIR` is enforced at boot (AGT-411).** Setting this var to a non-default path in production is now a hard startup failure. The server will exit non-zero with an error message when `STAMP_PROMPTS_DIR` is non-default and `STAMP_ENV` is absent or `production`. To use a custom prompts directory in a non-production environment (CI, fixture runs), you must set **both** `STAMP_ENV=dev` (or `=test`) **and** `STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY=1`. Never set these on a production deployment.

**Expected permissions.** `0755` on the directory, `0644` root:root on the `*.md` files. World-readable is required so the `git-shell` user that runs `stamp-review` can read without elevation; the `chmod` is enforced by the Dockerfile at build time. Do not mount this path from a host volume in production — the trust property depends on the prompts being baked into the image, not supplied at runtime by an unprivileged actor.

**Boot inventory.** `entrypoint.sh` emits a one-line stderr inventory at startup listing which `*.md` files are present in `/etc/stamp/reviewers/` (visible via `docker logs` / Railway logs). Helpful for confirming an image variant shipped the expected prompt set without `exec`'ing into the container.

**Changing prompts.** Edit `server/reviewers/<name>.md` in your fork of this repo, then rebuild the image and redeploy. The committed source is what every container of a given image tag has — prompts are part of the image tag's identity. There is no live-edit / hot-reload path on purpose; live editing would let a server operator modify what the LLM sees AFTER an attestation was signed against a different prompt, defeating the verifier's ability to bind a verdict to a specific prompt hash.

**Adding a new reviewer.** Add `server/reviewers/<newname>.md` (the file's basename is the reviewer's name as referenced in per-repo `.stamp/config.yml`). Per-repo configs reference the reviewer by name only — there is no `prompt:` path field; the server's bundled prompt is the canonical source. Rebuild + redeploy so the image carries the new file.

**Versus the per-repo `.stamp/reviewers/` path.** In Shape 1 and Shape 2 deployments (see [`docs/migration-1.x-to-2.x.md`](../docs/migration-1.x-to-2.x.md)), reviewer prompts live in each reviewed repo under `.stamp/reviewers/<name>.md` and stamp-server fetches them from its bare clone of the repo at base_sha. In Shape 4 deployments (no code transfer), the prompts in `/etc/stamp/reviewers/` are the canonical source and the reviewed repo does NOT carry `.stamp/reviewers/*.md`. The two paths are deliberately separate file trees — operators don't mount Shape-1/2-style per-repo prompts into `/etc/stamp/reviewers/`.

## Phase B — external prompts via webhook

**Skip this section if you don't want external prompts.** Phase B is purely opt-in. If you don't set `STAMP_PROMPTS_REPO_URL`, the server keeps using the image-bundled prompts at `/etc/stamp/reviewers/` (the Phase A path documented above) with zero behavior change. Phase B layers a second prompt source on top of that fallback; nothing about Phase A's posture is removed.

### What Phase B gets you

Decouples reviewer-prompt source from the stamp-server image so you can iterate on prompts without redeploying the server. Prompts live in a separate github repo (e.g. `your-org/stamp-reviewers`); the stamp-server maintains a local cache populated automatically by a github webhook fired on every push to that repo. Per-request review latency is unchanged (server reads from local cache); freshness lag is webhook-delivery time (sub-second in normal operation).

| | Phase A (bundled) | Phase B (external repo) |
|---|---|---|
| Prompt source | `/etc/stamp/reviewers/*.md` baked into the image | Local cache at `/srv/git/.prompts-cache/` populated from a github prompts repo |
| Edit cycle | Edit `server/reviewers/<name>.md` + rebuild + redeploy | Push to the prompts repo (webhook fires; cache refreshes) |
| Latency at review time | `readFileSync` | `readFileSync` (identical — only the upstream provisioning channel differs) |
| Threat model | Operator controls prompt bytes via image build | Operator controls prompt bytes via the prompts repo + HMAC-signed webhook |
| Per-repo overrides | None | Optional `<org>/<repo>/<reviewer>.md` in the prompts repo |

The trust property carried forward from Phase A — *the server controls which prompt bytes get fed to the LLM* — extends here to: *the server controls which prompt bytes get fed to the LLM, sourced from a github repo the server operator controls.* The server's logical authority is unchanged; only the storage layer is virtualized.

### Prompts repo layout

A conventional `stamp-reviewers`-style repo looks like:

```
default/security.md
default/standards.md
default/product.md
your-org/your-repo/security.md       # optional per-repo override
your-org/your-repo/standards.md      # optional per-repo override
```

`default/<reviewer>.md` is the canonical fallback for any reviewed repo. The optional per-repo path is consulted first when the SSH verb carries `(org, repo)` context: `getPromptPath` in `src/server/prompts-cache.ts` looks for `<cacheRoot>/<org>/<repo>/<reviewer>.md`, and falls through to `<cacheRoot>/<reviewer>.md` if the override doesn't exist. Per-repo overrides are entirely optional; many deployments will only ever ship the `default/` tree.

> **Note on the `default/` prefix.** The path inside the cache is determined by `getPromptPath`'s fallback logic, which reads `<cacheRoot>/<reviewer>.md` when no per-repo override is present. The `default/` directory convention in the prompts repo therefore needs to be flattened into the cache root at populate time — see "Migrating bundled prompts" below for the recommended layout if you're seeding the repo from `server/reviewers/`.

### Webhook configuration (on the prompts repo)

On the github prompts repo, configure a webhook (Settings → Webhooks → Add webhook):

| Field | Value |
|---|---|
| Payload URL | `https://<your-stamp-server-host>/webhook/prompts` |
| Content type | `application/json` |
| Secret | Generate fresh; same value goes into `STAMP_PROMPTS_WEBHOOK_SECRET` on the server (see env-var table below). Use `openssl rand -hex 32` or equivalent. |
| SSL verification | Enable (Railway / Fly / equivalent terminate TLS at their edge proxy) |
| Events | "Just the `push` event" — no other events needed |
| Active | ✓ |

The server validates `X-Hub-Signature-256` against the request body using HMAC-SHA256 with this shared secret. A valid signature returns `202 Accepted` fast (background `git fetch` continues after the response); an invalid signature returns `401 invalid_signature` and logs the delivery ID + remote address (but never the bad signature itself). The route also coalesces deliveries within a 5-second window so burst pushes (e.g. squash-merge + tag push) don't trample each other.

### Private-repo deploy-key flow

If the prompts repo is private, the stamp-server needs SSH access via a github deploy key. The flow mirrors the existing `stamp-ensure-repo-key` posture: **operators upload the private half themselves; the server never auto-generates this key.**

1. **Generate the keypair locally** (or anywhere convenient):
   ```sh
   ssh-keygen -t ed25519 -N "" \
     -f ./prompts_repo_key \
     -C "stamp-prompts@<your-server-host>"
   ```
2. **Register the public half** as a deploy key on the prompts repo (Settings → Deploy keys → Add deploy key). **Read-only access is sufficient** — the stamp-server only ever fetches; it never pushes back.
3. **Drop the private half into the stamp-server's volume.** The default path the server checks is `/srv/git/.ssh-client-keys/prompts_repo_key`. The directory is created at boot (`server/entrypoint.sh`), owned `root:git` mode `0750`, so the git user can READ + traverse but cannot CREATE or DELETE entries. Upload the file via your platform's volume-mount mechanism (Railway: web console shell into the container; Fly: `fly ssh console`; self-hosted Docker: `docker cp`). The file itself should be mode `0600` git-owned, matching the existing `github_ed25519` mirror-push key alongside it.
4. **Set `STAMP_PROMPTS_DEPLOY_KEY_PATH`** on the server pointing at the file (or leave unset to use the default path).

If `STAMP_PROMPTS_DEPLOY_KEY_PATH` is set but the file is missing at boot, `entrypoint.sh` aborts startup with:

```
error: STAMP_PROMPTS_DEPLOY_KEY_PATH=/srv/git/.ssh-client-keys/prompts_repo_key does not exist on the volume; provision the private SSH key (mirroring the stamp-ensure-repo-key flow) and redeploy. Never auto-generated.
```

HTTPS URLs bypass the deploy key entirely — github's TLS handles host verification and you can leave `STAMP_PROMPTS_DEPLOY_KEY_PATH` unset. Use HTTPS for public prompts repos; use SSH + a deploy key for private repos.

### Env-var reference

All Phase B configuration is via env vars on the stamp-server deployment (Railway: Settings → Variables; equivalents on other platforms):

| Var | Required | Default | Purpose |
|---|---|---|---|
| `STAMP_PROMPTS_REPO_URL` | Yes (to enable Phase B) | unset | `https://github.com/owner/name.git` or `git@github.com:owner/name.git`. Unset = stay on Phase A bundled prompts. |
| `STAMP_PROMPTS_REPO_REF` | No | `main` | Branch or tag to track on the prompts repo. |
| `STAMP_PROMPTS_WEBHOOK_SECRET` | Yes (to accept webhook deliveries) | unset | HMAC-SHA256 shared secret. Must match the github webhook config. Missing = `503 webhook_secret_unconfigured` on every delivery. |
| `STAMP_PROMPTS_DEPLOY_KEY_PATH` | Conditional | `/srv/git/.ssh-client-keys/prompts_repo_key` | Private SSH key for SSH URLs to private repos. Ignored for HTTPS URLs. Path must exist at boot when set explicitly. |
| `STAMP_PROMPTS_CACHE_ROOT` | No | `/srv/git/.prompts-cache` | Absolute directory path for the local cache. The default is on the persistent volume so the cache survives container redeploys. |
| `STAMP_PROMPTS_POLL_INTERVAL_SEC` | No | `3600` (1 hour) | Periodic-poll backstop interval in seconds. Floor `5` (values 1–4 are clamped up with a warn line). Literal `"0"` disables polling entirely. Non-integer / negative / whitespace values fall back to the default with a warn line — see "Periodic-poll backstop" below. |
| `STAMP_PROMPTS_KNOWN_HOSTS_PATH` | No | `/etc/ssh/ssh_known_hosts` (bundled `server/github-known-hosts`) | Override for self-hosted github enterprise. Standard github.com deployments don't need this. |
| `STAMP_PROMPTS_DIR` | No (Phase A only) | `/etc/stamp/reviewers` | Phase A bundled-prompts fallback path. **IGNORED when `STAMP_PROMPTS_REPO_URL` is set** — Phase B mode reads from the cache root above. **Setting a non-default value fails the boot in production** (AGT-411). |
| `STAMP_ENV` | No | *(treated as `production` when absent)* | Deployment role. Set to `dev` or `test` only in non-production environments. When absent or set to `production`, the server treats itself as production and enforces all production-only restrictions (e.g. `STAMP_PROMPTS_DIR` override refusal). |
| `STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY` | No | unset | **Test environments only.** Must be set alongside `STAMP_ENV=dev` or `STAMP_ENV=test` to permit a non-default `STAMP_PROMPTS_DIR`. Rejected in production (boot failure if set). Never configure on a production deployment. |

> **Literal-`"0"` invariant for `STAMP_PROMPTS_POLL_INTERVAL_SEC`.** Only the exact string `"0"` disables polling. `"00"`, `"000"`, `"-0"`, surrounding whitespace, and any malformed value fall back to the 3600-second default with a `warn` line in the boot log. This is deliberate: silent-disable on a fat-fingered value (e.g. `" 0"` from a copy-paste) is exactly the failure mode we want to avoid. If you mean "don't poll," type `0` with no whitespace.

### First-boot expectations

After setting the env vars and triggering a redeploy, container logs should show (in order, interleaved with sshd's own startup output):

1. **Phase A inventory** (unchanged — always logged):
   ```
   reviewer prompts available: product.md,security.md,standards.md
   ```
2. **Deploy-key gate** (if `STAMP_PROMPTS_DEPLOY_KEY_PATH` is set): silent on success; if the file is missing, the boot aborts with the `error: STAMP_PROMPTS_DEPLOY_KEY_PATH=... does not exist on the volume` message documented above.
3. **Cache populate pre-flight** (`prompts-cache:` prefix):
   ```
   prompts-cache: populating cache at /srv/git/.prompts-cache from git@github.com:your-org/stamp-reviewers.git@main (deploy key: /srv/git/.ssh-client-keys/prompts_repo_key)
   ```
4. **Cache ready** (after `git clone` completes — typically sub-second to a few seconds):
   ```
   prompts-cache: ready (cacheRoot=/srv/git/.prompts-cache sha=<40-hex> files=<comma-list>.md)
   ```
   The `files=` list enumerates `*.md` files directly inside `cacheRoot` — useful for confirming the prompts repo's `default/` layout matches what the lookup expects. If you see `files=<none>` here but expected files, your prompts repo probably has a `default/` directory the cache wasn't flattened into — see "Migrating bundled prompts" below.
5. **HTTP listener up** (port 8080, unchanged from Phase A):
   ```
   stamp-http-server <ts> info listening on :8080
   ```
6. **Periodic-poll worker** (when `STAMP_PROMPTS_REPO_URL` is set AND interval > 0):
   ```
   stamp-http-server <ts> info prompts-poll: started (interval=3600s, url=..., ref=main, cacheRoot=/srv/git/.prompts-cache)
   ```
   Or, if explicitly opted out:
   ```
   stamp-http-server <ts> info prompts-poll: disabled (STAMP_PROMPTS_POLL_INTERVAL_SEC=0)
   ```

Absence of any `prompts-cache: ready` line on boot means the boot-time populate didn't run — `STAMP_PROMPTS_REPO_URL` is unset and the server is still on Phase A. Absence of any `prompts-poll: started` line on boot when `STAMP_PROMPTS_REPO_URL` IS set means the worker was gated off (interval=0) or the env-var resolution fell back to default with a warn-line first.

### Periodic-poll backstop

In addition to webhook-driven refreshes, the stamp-server runs a periodic-poll worker that calls `cloneOrFetchPromptsCache` on a configurable interval. This is a backstop for missed webhook deliveries (github can retry-then-give-up on 5xx for 24h; a network partition longer than that would otherwise strand the cache). The default interval is 3600s (one hour), tunable via `STAMP_PROMPTS_POLL_INTERVAL_SEC`.

The poll worker is a no-op unless BOTH `STAMP_PROMPTS_REPO_URL` is set AND `STAMP_PROMPTS_POLL_INTERVAL_SEC` is non-zero. Phase A deployments see no behavior change.

Production log lines (grep on `prompts-poll:`):

| Log line | Meaning |
|---|---|
| `prompts-poll: started (interval=Ns, url=..., ref=..., cacheRoot=...)` | Boot-time confirmation that the worker armed |
| `prompts-poll: disabled (STAMP_PROMPTS_POLL_INTERVAL_SEC=0)` | Explicit opt-out confirmation |
| `prompts-poll: refresh ok sha=<40-hex> at=<iso8601>` | One successful tick |
| `prompts-poll: refresh failed: <message>` | Transient failure; next tick will retry |
| `prompts-poll: skipping tick — previous refresh still in flight` | Defensive skip (e.g. a slow git fetch over a saturated link) |

The poll worker and the webhook route share the same in-process refresh state and the cache module's own coalescing — concurrent poll + webhook calls collapse to a single git fetch.

For webhook-only mode (no periodic polling, e.g. dev deploys where the hourly tick clutters logs), set `STAMP_PROMPTS_POLL_INTERVAL_SEC=0` explicitly.

### Threat model

Adapted from the project README's mitigations table:

| Threat | Mitigation |
|---|---|
| Malicious client supplies prompt bytes via SSH verb | Same as Phase A: client supplies only `--reviewer` (a name); server reads file content from its own cache. Client cannot influence file contents. |
| Attacker spoofs webhook delivery | HMAC-SHA256 validation on every request. Secret never leaves stamp-server + github webhook config. Rejected deliveries logged with delivery ID + remote address (never the bad signature itself). |
| Compromised prompts repo (e.g. github account compromise) | **Operator responsibility — see below.** Phase B inherits the prompts repo's access-control posture; a compromise there propagates into the LLM prompts the server uses. |
| Webhook delivery missed / delayed → stale cache | Periodic-poll backstop (default 3600s) refreshes from origin even without webhook traffic. Operator can also confirm freshness by grepping `prompts-poll: refresh ok` in logs. |
| MITM on the prompts-repo clone/fetch | HTTPS URL: github's TLS handles it. SSH URL: deploy key + `StrictHostKeyChecking=yes` against the pinned `server/github-known-hosts` file (overridable via `STAMP_PROMPTS_KNOWN_HOSTS_PATH` for self-hosted github enterprise). |
| Cache corruption / partial fetch | Atomic refresh: clone to `<cacheRoot>.tmp`, `rev-parse HEAD` to confirm, then POSIX `rename(2)` to commit. Mid-fetch failure leaves the existing `<cacheRoot>` untouched. |

**Operator responsibilities** (you own these — they are NOT mitigated by the stamp-server code):

- **Branch protection on the prompts repo's tracked branch** (typically `main`). The server fetches whatever the configured ref points to; any commit that lands there becomes the new reviewer prompts on the next refresh. Use github's branch protection rules + ruleset to require PR review + status checks on the prompts repo, the same way you protect your code repos.
- **Signed commits on the prompts repo (recommended).** The current Phase B implementation does NOT verify commit signatures on the prompts repo — that's an explicit deferred item in the project's scope. If your threat model depends on tamper-evident prompt history, enforce GPG/SSH commit signing via branch protection and audit it separately.
- **Webhook secret rotation.** Rotate the shared secret periodically: generate a new value, update the github webhook config FIRST (github accepts both old and new during a brief overlap if you save twice in quick succession), then update `STAMP_PROMPTS_WEBHOOK_SECRET` on the server and redeploy. No special tooling — operators rotate by editing the env var + github webhook config.
- **Deploy-key custody.** The private half on the volume is recoverable by anyone who can read the volume (e.g. platform support, anyone with `docker exec` equivalent). Treat it the same way you treat `GITHUB_BOT_TOKEN`.

### Troubleshooting

**Webhook deliveries return `401 invalid_signature`.**

The HMAC over the request body didn't match the expected digest. Most common causes:

- `STAMP_PROMPTS_WEBHOOK_SECRET` on the server doesn't match the secret you typed into the github webhook config. The values are case-sensitive and whitespace-sensitive. Regenerate fresh on both sides if in doubt.
- A reverse proxy in front of the server is rewriting the body (e.g. JSON-reformat, charset translation). The HMAC is over the raw wire bytes; any transformation breaks it. Railway / Fly's default proxy is transparent and doesn't cause this.

Server log (look in container logs, grep on `webhook/prompts`):

```
stamp-http-server <ts> warn webhook/prompts delivery=<uuid> from=<remote-addr> rejected: invalid signature
```

The delivery ID matches github's webhook delivery log (Settings → Webhooks → Recent Deliveries → click into a delivery). The supplied signature is **not** logged on purpose — it has no diagnostic value and writing attacker-controlled bytes into the log stream would be a foot-gun.

**Webhook deliveries return `503 webhook_secret_unconfigured`.**

`STAMP_PROMPTS_WEBHOOK_SECRET` env var is unset on the server. Set it, redeploy. Github will retry on 5xx for ~24 hours so the missing-secret window is recoverable.

**Webhook deliveries return `503 prompts_repo_url_unconfigured`.**

HMAC validated but `STAMP_PROMPTS_REPO_URL` is unset on the server — the secret is configured but the server doesn't know what to fetch. Set the URL, redeploy.

**Cache is stale (recent prompts repo push not reflected in reviews).**

1. Check the github webhook delivery log (Settings → Webhooks → Recent Deliveries on the prompts repo). A red ✗ here means the delivery never reached the server — check the URL, the SSL cert, and the network path.
2. Check the stamp-server's container logs. A successful delivery shows `webhook/prompts refresh ok sha=<hex> at=<iso>`; a failed refresh shows `webhook/prompts refresh failed delivery=<id>: <reason>`.
3. If both look healthy, the periodic-poll line `prompts-poll: refresh ok sha=...` should appear on the next tick (default 3600s). Grep for it; the SHA there matches the prompts repo's current `HEAD` of the tracked ref.

**Manually trigger a refresh.**

Two ways:

- **From github** — Settings → Webhooks → Recent Deliveries → pick any recent delivery → "Redeliver." The server processes it the same way as the original, including the 5-second coalescing window. This is the cleanest path because it tests the full webhook chain (signature validation, route handler, cache module).
- **From the container** — `docker exec` (or platform equivalent) into the container and run a `git fetch + checkout` against the cache directly. The atomic-refresh and coalescing guarantees still hold (the cache module's lock file at `/srv/git/.prompts-cache.refresh.lock` serializes concurrent callers cross-process). Use this only for one-off debugging — operator-driven config changes should go through the github push channel so the audit trail lives in the prompts repo.

**Boot fails with `error: STAMP_PROMPTS_DEPLOY_KEY_PATH=... does not exist on the volume`.**

The env var is set but no private key file is present at the named path. Provision the file (see the "Private-repo deploy-key flow" section above). Until the file lands on the volume, the server refuses to boot — better than booting with broken prompts.

**Boot fails with `error: prompts-cache populate failed: <git error>`.**

`STAMP_PROMPTS_REPO_URL` is set but the first-boot clone failed. Common causes:

- The deploy key's public half isn't registered on the prompts repo (or was removed). Re-register it; github responds with a clear "Repository not found" via SSH that propagates into the error message.
- The configured `STAMP_PROMPTS_REPO_REF` doesn't exist on the prompts repo. Check spelling; default is `main`.
- The prompts repo URL has a typo (HTTPS vs SSH, wrong owner/name).

The error message includes the failing git command's stderr — read it carefully before assuming a config issue.

### Migrating bundled prompts (Phase A → Phase B)

If you're starting from a Phase A deployment whose canonical prompts live in `server/reviewers/*.md` in your fork of this repo, seeding the Phase B prompts repo is straightforward:

1. Create the new github repo (e.g. `your-org/stamp-reviewers`). Public or private; both work.
2. Copy the existing `server/reviewers/*.md` files into the new repo. **Flatten or place at the top level**, not under `default/` — the cache module's `getPromptPath` reads `<cacheRoot>/<reviewer>.md` for the default-path lookup, NOT `<cacheRoot>/default/<reviewer>.md`. If your prompts repo uses the `default/` convention from the project README, the operator-side step is to flatten that into the cache root either via a post-receive script on the prompts-cache side or by laying the files out flat at the repo root from the start. The flat-at-root layout is simpler and is the recommended starting point.
3. Configure the webhook (above).
4. Set the env vars (above).
5. Redeploy. The first boot clones the cache; subsequent edits to the prompts repo trigger webhook refreshes.

Once the Phase B cache is populated and reviews are working against it, the `server/reviewers/*.md` files in your stamp-cli fork become dead weight — the bundled image-bake path still runs (`/etc/stamp/reviewers/` is still populated at build time) but the SSH verb's resolver consults the Phase B cache root instead. Removing the bundled files from the image is not required and there's no rush; the next major release of your fork can clean them up.

### `.stamp/config.yml` shape for Phase B

As of stamp-cli 2.1.0, the per-repo `.stamp/config.yml`'s `reviewers.<name>.prompt` field is **optional**. For Shape 4 / Phase B deployments where the prompts live on the server (either bundled or external-repo), the recommended convention is the empty-object form:

```yaml
reviewers:
  security: {}
  standards: {}
  product: {}
required_reviewers:
  - security
  - standards
```

The empty `{}` declares that the repo requires the reviewer to run but defers prompt-bytes to whatever the server has configured. This is what HiveDB and similar Shape 4 deployments use today. The legacy `prompt: .stamp/reviewers/<name>.md` form is still supported for Shape 1/2 deployments where the prompts live in the reviewed repo itself — see [`docs/migration-1.x-to-2.x.md`](../docs/migration-1.x-to-2.x.md) for the full topology comparison.

## Build locally

From the repo root (not from `server/`):

```sh
docker build -f server/Dockerfile -t stamp-server .
```

## Run locally (test)

```sh
docker run -d \
  --name stamp-server \
  -p 2222:22 \
  -v stamp-data:/srv/git \
  -e AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" \
  -e OPERATOR_PUB_KEY="$(cat ~/.stamp/keys/ed25519.pub)" \
  stamp-server

# create a repo
ssh -p 2222 git@localhost new-stamp-repo myproject

# clone it from your working machine
git clone ssh://git@localhost:2222/srv/git/myproject.git
```

## Deploy to Railway

1. **Push this repo to GitHub** (or fork and push your own copy).
2. **Create a new Railway project** and connect it to the repo.
3. **Configure the build**:
   - Settings → Build → Dockerfile Path: `server/Dockerfile`
   - Settings → Build → Build Context Path: leave blank (use repo root)
4. **Configure the volume**:
   - Attach a Railway volume to `/srv/git` — this persists your bare repos
     across deployments.
5. **Configure environment variables** (Settings → Variables):
   - `AUTHORIZED_KEYS` — newline-delimited list of SSH public keys allowed
     to connect. Start with your own: `cat ~/.ssh/id_ed25519.pub`. **First-boot
     bootstrap only:** these get imported into the membership sqlite as
     `role=admin`; after that, the CLI surface (`stamp invites`, `stamp users`)
     is authoritative. Adding/removing keys via this env var after the first
     boot is supported but discouraged — see "Onboarding teammates" below.
   - `OPERATOR_PUB_KEY` — the stamp-cli public key that will be seeded as
     the initial trusted signer in each new repo: `cat ~/.stamp/keys/ed25519.pub`.
   - `STAMP_PUBLIC_URL` — required for the invite flow. Set to the
     externally-reachable HTTPS URL of the HTTP listener that Railway
     assigns (Settings → Networking → Public Networking → HTTP, pointing
     at container port `8080`). Example: `https://stamp-cli-production.up.railway.app`.
     `stamp invites mint` bakes this into share URLs; without it, mint
     refuses with a clear error.
   - `GITHUB_BOT_TOKEN` — **optional**, only needed if you want to mirror
     verified commits to a GitHub repo (see "GitHub mirror" below). A
     fine-scoped GitHub PAT with `contents: write` on the target repo(s).
6. **Expose port 22** via Railway's TCP proxy:
   - Settings → Networking → Public Networking → TCP Proxy → create one
     pointing at container port 22. Railway gives you a public host +
     high-numbered port (e.g. `ssh.railway.app:12345`).
7. **Expose port 8080** via Railway's HTTP service:
   - Settings → Networking → Public Networking → HTTP → create one
     pointing at container port 8080. Railway terminates TLS at its edge
     and gives you an `https://*.up.railway.app` URL. Plug that into
     `STAMP_PUBLIC_URL`. This is where invitees POST their pubkeys when
     they run `stamp invites accept`.
8. **Point a domain at it (optional)**:
   - CNAME your domain at Railway's TCP proxy host. Note you'll still
     connect on the assigned high port; SSH doesn't do the Host header
     trick HTTP does.

### Connecting from your laptop

Point the `stamp` CLI at your server (writes `~/.stamp/server.yml`):

```sh
stamp server config ssh.railway.app:12345
```

Optionally also pin the SSH host in `~/.ssh/config` so plain
`ssh ssh.railway.app` and `git clone ssh://ssh.railway.app/...` use
the right key:

```sh
cat >> ~/.ssh/config <<EOF
Host ssh.railway.app
  Port 12345
  User git
  IdentityFile ~/.ssh/id_ed25519
EOF

# Provision a new repo
ssh ssh.railway.app new-stamp-repo myproject

# Clone it
git clone ssh://ssh.railway.app/srv/git/myproject.git
```

## Daily workflow

Once a repo exists on the server, stamp-cli handles everything from your
laptop — the server just enforces the hook on pushes.

```sh
git clone ssh://stamp/srv/git/myproject.git
cd myproject
stamp init                          # creates .git/stamp/state.db + keypair
# ...hack on a feature branch...
stamp review --diff main..HEAD      # reviewers give verdicts
stamp status --diff main..HEAD      # gate check
git checkout main
stamp merge my-feature --into main  # signed merge commit
stamp push main                     # hook verifies, main advances
```

## GitHub mirror (optional)

After a successful stamped push lands on the server, a **post-receive hook**
can automatically mirror the ref to a GitHub repo. The stamp server stays
source-of-truth; GitHub becomes a read-only public mirror that deploy
pipelines (Actions, Vercel, Netlify, etc.) can integrate with natively.

### Per-repo config

Commit `.stamp/mirror.yml` at the repo root declaring the GitHub destination:

```yaml
github:
  repo: your-user/your-repo       # GitHub "owner/repo" of the mirror destination
  branches:
    - main
    - "release/*"                  # glob patterns; literal names match exactly
  tags:                            # optional — mirror tags to GitHub too
    - "v*"                         # glob patterns (or `true` for all tags)
```

Only branches and tags whose names match an entry are mirrored — `branches:`
takes the same `*` / `?` glob grammar as `tags:`, so a literal `main` matches
just that branch and `release/*` catches every branch under that prefix.
Other refs are pushed to your stamp server but not to GitHub. The `tags:`
field is optional — when absent or empty, no tags are mirrored (the
pre-0.7.8 behavior).

Tag mirroring exists for repos that publish on tag push (npm `on: push: tags`,
Cargo, PyPI, etc.). Without it, `git push origin v1.0.0` lands on the stamp
server but the GitHub action never fires; the workaround was a parallel
`git push github v1.0.0` that bypasses the stamp gate.

### Server-side credentials

Set `GITHUB_BOT_TOKEN` as a Railway env var with a GitHub PAT (or GitHub App
installation token) that has `contents: write` on the target repo. The
post-receive hook reads it from `/etc/stamp/env` (written by the entrypoint,
chmod 600, git-owned) and constructs:

```
https://x-access-token:$GITHUB_BOT_TOKEN@github.com/<owner>/<repo>.git
```

to push the ref.

### GitHub-side protection (recommended)

On the GitHub mirror repo, restrict pushes to `main` so only your
designated mirror identity (the user/App that owns `GITHUB_BOT_TOKEN`)
can update the branch. This ensures the only way a commit lands on
GitHub's `main` is via a verified push through your stamp server.
Humans with repo access can still fork/PR via GitHub's standard flow,
but those PRs cannot merge — the ruleset blocks everyone except the
bypass actor.

GitHub is phasing out the legacy "Branch protection rules" UI in favor
of **Rulesets** (Settings → Rules → Rulesets). Many newer accounts only
see the Ruleset surface now.

See [`docs/github-ruleset-setup.md`](../docs/github-ruleset-setup.md)
for the full walkthrough (UI + CLI paths, the same-PAT-owner-bypass
footgun, and the machine-user pattern that fixes it). The repo also
ships [`docs/github-ruleset-template.json`](../docs/github-ruleset-template.json)
— a sanitized config you edit (set the bypass actor's numeric ID) and
import via `gh api -X POST /repos/<owner>/<repo>/rulesets --input ...`.

### Behaviors

- Mirror failures do **not** block the stamped push — the stamp main push
  already succeeded by the time post-receive runs. Mirror failures are
  logged to stderr (visible to the client via git's `remote:` prefix).
- A failed mirror leaves GitHub out-of-sync until the next successful push
  or a manual retry. Not data-loss, just staleness.
- First push to a fresh GitHub repo requires the GitHub repo to already
  exist (create it empty on github.com first).

## Onboarding teammates

The server tracks membership in a sqlite database (`/srv/git/.stamp-state/users.db`)
that's populated and managed entirely through the `stamp` CLI. Three roles:

| Role     | What it can do                                                       |
|----------|----------------------------------------------------------------------|
| `owner`  | Full control — invite anyone, promote/demote/remove anyone           |
| `admin`  | Invite members, manage members. Cannot create or modify admins/owners |
| `member` | Push/pull/merge (subject to per-repo trust). No user management      |

**SSH access** is gated by membership in this DB (via sshd's
`AuthorizedKeysCommand`). **Signing trust** for a stamp-gated repo is
separate: each repo's `.stamp/trusted-keys/` directory lists whose
stamp-signed merges that repo accepts. The two planes are decoupled —
`stamp users …` covers server access; `stamp trust grant …` covers
per-repo signing trust.

### First-boot bootstrap (admin → owner)

`AUTHORIZED_KEYS` entries are imported on first boot as `role=admin`. To
get a real `owner` you self-promote once, while no owners exist yet:

```sh
# As the operator whose SSH key is in AUTHORIZED_KEYS:
stamp users promote <your-short-name> --to owner
```

This works exactly once — the server allows admin self-promotion to
owner only when the owner count is zero. After that, owner promotion is
owner-gated like everything else. `<your-short-name>` is the slug
derived from your SSH key's comment (`stamp users list` shows it).

### Invite a teammate

**Admin/owner side** — mint a single-use invite (15-minute TTL):

```sh
stamp invites mint alice --role member        # or --role admin (owner only)
```

Output is a `stamp+invite://<host>/<token>` URL. Share it via whatever
secure channel you and your teammate trust. The README's recommendation
is [`magic-wormhole`](https://github.com/magic-wormhole/magic-wormhole),
which lets you transport the URL one-shot via a short, easily-spoken
code:

```sh
wormhole send --text "stamp+invite://stamp.example.com/<token>"
# tells you the code, e.g. "7-crossover-clockwork"
# the teammate runs: wormhole receive 7-crossover-clockwork
```

Any other one-shot secure channel works equally well — Signal DM,
1Password share, in-person paste from a laptop. Don't use Slack/email
without considering whether persistent logs are acceptable in your
threat model.

**Teammate side** — redeem the invite:

```sh
# Generate keys if you don't already have them.
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -C "<your-handle>@<your-host>"
stamp keys generate                            # generates ~/.stamp/keys/ed25519

# Redeem.
stamp invites accept "stamp+invite://stamp.example.com/<token>"
```

The TUI auto-detects `~/.ssh/id_ed25519.pub` and `~/.stamp/keys/ed25519.pub`,
shows the fingerprints, and asks for confirmation before POSTing to the
server. Result: an enrolled `member` row in the membership DB. Your
teammate can now `git clone`, push, pull from the server.

If they don't have a stamp signing keypair yet, the accept TUI tells
them — they can re-run later with `--stamp-pubkey <path>` once
generated, and the trust-grant step below will pick it up.

**Sanity check:**

```sh
stamp users list
```

Should show the new teammate alongside everyone else.

### Grant signing trust per-repo

SSH access doesn't grant merge authority — that requires the new
operator's stamp signing pubkey to live in each target repo's
`.stamp/trusted-keys/`. Adding a trusted signer is itself stamp-gated,
so the change goes through the usual review cycle.

```sh
cd <stamp-gated-repo>
stamp trust grant alice
# Creates a `stamp-trust/alice` branch + commit with alice's signing
# pubkey under .stamp/trusted-keys/alice.pub. The command prints
# copy-pasteable next steps:
stamp review --diff main..stamp-trust/alice
git checkout main
stamp merge stamp-trust/alice --into main
stamp push main
```

This asymmetry is deliberate: a compromised admin account can enroll a
new member at the server level, but cannot widen any repo's signing
trust without going through the gate. The first trusted-key for any new
operator is always landed by an existing one.

### Manage members

```sh
stamp users list                          # everyone enrolled, sorted by role
stamp users promote <name> --to admin     # owner only
stamp users promote <name> --to owner     # owner only
stamp users demote <name> --to member     # owner only; refuses if it'd zero out ownership
stamp users remove <name>                 # admin removes members; owner removes anyone
```

`stamp users` reads/writes the sqlite directly via SSH; no env-var
shuffle, no service restart.

## Backup

The entire state is in the Railway volume at `/srv/git/`. Back it up by
copying that directory periodically; a freshly-provisioned container
pointed at the same volume will pick up exactly where it left off.

## Updating the hooks

When stamp-cli releases new hook code, redeploy the container — the builder
stage recompiles and the fresh hook bundle lands at `/etc/stamp/pre-receive.cjs`
and `/etc/stamp/post-receive.cjs`. On container restart, `entrypoint.sh`
automatically walks `/srv/git/*.git/hooks/` and overwrites each repo's
`pre-receive` + `post-receive` with the fresh bundle from `/etc/stamp/`. No
manual step required — Railway's auto-deploy on push triggers the restart,
and the refresh loop runs before sshd starts accepting connections.

**Break-glass manual refresh** (useful if you need to push a hook update
without restarting the container, or you're debugging):

The git account uses `git-shell` and does not accept interactive commands,
so the previous `ssh git@<host> '<pipeline>'` form no longer works. Use
your platform's web console / container exec instead — Railway's
in-dashboard shell, `fly ssh console`, `docker exec`, etc.:

```sh
# Inside the container, as root:
for r in /srv/git/*.git; do
  cp /etc/stamp/pre-receive.cjs  "$r/hooks/pre-receive"
  cp /etc/stamp/post-receive.cjs "$r/hooks/post-receive"
  chown root:root "$r/hooks/pre-receive" "$r/hooks/post-receive"
  chmod 0755 "$r/hooks/pre-receive" "$r/hooks/post-receive"
done
```

## SSH access model

The `git` account is configured with `git-shell` rather than `bash`.
Authenticated pushers can:

- `git push` / `git fetch` / `git clone` (via the built-in
  `git-receive-pack`, `git-upload-pack`, `git-upload-archive` commands)
- `ssh git@<host> new-stamp-repo <name> [...]`
- `ssh git@<host> delete-stamp-repo <name> [--purge]`
- `ssh git@<host> restore-stamp-repo <name> [--from <trash-entry>] [--as <new-name>]`
- `ssh git@<host> list-trash`

…but cannot get an interactive shell, run arbitrary commands, or read
the per-deployment env file (`/etc/stamp/env`, which holds the GitHub
mirror token and is owned `root:git` mode 0640). The wrapper scripts are
symlinked under `/home/git/git-shell-commands/` at image build time.

For container-level diagnostics — log inspection, manual hook refresh,
disk usage — use your platform's web console or `<platform> exec`.

## Container runtime — runs as root (accepted trade-off)

The stamp server container runs as root in-container. `server/Dockerfile`
deliberately does not include a `USER` directive. This is an accepted
trade-off, not an oversight.

### Why root is load-bearing

Two parts of startup require root and don't have a straightforward
in-image workaround under current orchestration:

1. **sshd binds privileged port 22.** Operators connect via `ssh
   git@<host>` on a Railway TCP proxy fronting container port 22. Binding
   any port below 1024 requires `CAP_NET_BIND_SERVICE`, which in practice
   means sshd starts as root.
2. **`entrypoint.sh` manages permissions on persistent state before any
   service starts.** Each boot it `chown`s `/srv/git/` (the volume comes
   up root-owned on platform mounts) to the git user, generates/pins SSH
   host keys to `root:root` mode `0600` in `/srv/git/.ssh-host-keys/`,
   writes `/etc/stamp/operator.pub` as `root:root` mode `0444`, writes
   `/etc/stamp/env` (which holds `GITHUB_BOT_TOKEN`) as `root:git` mode
   `0640`, and refreshes every per-repo hook to `root:root` mode `0755`.
   Several of these objects must remain unwritable by the git user
   (which runs the SSH session and the hook process), so whatever sets
   them up has to outrank that user.

Both apply on every boot — not one-time setup that could happen in a
privileged init followed by a `USER git` drop.

### What this means in practice

Authenticated SSH users are constrained to the `git` account with
`git-shell` (see "SSH access model" above) — they cannot get an
interactive shell, run arbitrary commands, or read `/etc/stamp/env`. The
hardening in place (sticky bit on `/srv/git`, root-owned per-repo hooks,
mode `0640 root:git` on the env file, root-owned `.ssh-host-keys/`) is
defense in depth against the **git user**, not against in-container
root. A future sshd RCE, a bug in the stamp pre-receive hook, or a
compromised Alpine package would run with full root in the container —
including read access to `GITHUB_BOT_TOKEN`, every bare repo, and the
persistent host keys.

This is the trade-off being accepted.

### Deferred alternative

If the trade-off is ever re-evaluated, the path forward is:

1. Run sshd on an unprivileged port inside the container (e.g. `2222`).
2. Have the platform's TCP proxy front the public port — Railway TCP
   proxy 22→2222, equivalent on Fly/Docker/etc.
3. After `entrypoint.sh` finishes its privileged setup (chowns, host-key
   generation, env-file writes, hook refresh), drop to the git user —
   either via `gosu` / `su-exec` at the end of the entrypoint, or by
   structuring the entrypoint as a privileged setup phase that re-execs
   sshd under a `USER git` directive.

This is more invasive than the current shape and not currently warranted
— it couples the public-port binding to a platform proxy hop and
requires operator host config to follow. Documented so a future operator
who decides the threat model has changed has a starting point.

### Provenance

This posture was reviewed in the May 2026 audit pass — finding **L4** in
`oaudit-may-2-2026-rerun-3.md`, against repo HEAD `8e77f2f`. (The audit
doc lives in the operator's local audit archive outside this repo, not
in the repo tree; commit `8e77f2f` is the audited HEAD on `main`.) The
auditor's pragmatic recommendation was option (a): accept the trade-off
and document it. This section is that documentation; the deferred
alternative above mirrors the auditor's option (b).
