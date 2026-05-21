# Server reviewer prompts

These files are the canonical reviewer prompts bundled into the stamp-server
Docker image. The `server/Dockerfile` `COPY`s them into the runtime image at
`/etc/stamp/reviewers/<reviewer>.md` (mode `0644`, owned `root:root`), and the
SSH-invoked `stamp-review` command reads from
`${STAMP_PROMPTS_DIR:-/etc/stamp/reviewers}/<reviewer>.md` at review time.

To add or change a prompt, edit the file here and rebuild the image. There is
no host volume mount and no hot-reload — the prompt bytes are part of the
image, which is exactly how the server's trust property is preserved: the
operator controls what `docker build` runs, not what's on a mutable disk.

The prompt-cache resolver (`src/server/promptFetch.ts`) reads each file at
SSH-review time, hashes its contents, and includes the hash in the signed
verdict. A client verifying a server-attested approval can therefore confirm
which exact prompt bytes the server used — substituting a prompt at runtime
would change the hash and invalidate downstream verification.

The three reviewers (`security`, `standards`, `product`) match the names
scaffolded by `stamp init` and referenced throughout the docs. Project repos
can override them by committing their own `.stamp/reviewers/<name>.md`; these
server-bundled copies are the fallback baseline.
