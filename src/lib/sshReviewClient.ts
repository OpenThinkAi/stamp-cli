/**
 * Client-side SSH transport for the `stamp-review` server verb (AGT-332).
 *
 * The wire counterpart of `src/server/stamp-review.ts` (AGT-328): when the
 * operator's `.stamp/config.yml` configures a `review_server`, `stamp
 * review` connects via SSH, invokes `stamp-review --reviewer ... <
 * diff.patch`, and parses the JSON response back into the per-reviewer
 * `ApprovalV4` + signature pair that AGT-333 carved out columns for in
 * the local DB.
 *
 *   client                                  server (AGT-328)
 *     │                                       │
 *     ├─ spawn ssh -p <port> user@host        │
 *     │   stamp-review --reviewer security    │
 *     │   --org acme --repo widget-co         │
 *     │   --base-sha <40-hex>                 │
 *     │   --head-sha <40-hex>                 │
 *     │   --diff-sha256 <64-hex>              │
 *     ├──────── diff bytes on stdin ────────→ │
 *     │                                       │  parseRequest → resolveAuth
 *     │                                       │  → readBoundedStdin
 *     │                                       │  → runReviewPipeline
 *     │                                       │  → JSON on stdout
 *     │ ←─── { verdict, prose, approval,      │
 *     │       signature } JSON ──────────     │
 *     │                                       │
 *     ├─ parse JSON                           │
 *     ├─ verify signature against
 *     │  trusted-keys manifest @ base_sha
 *     └─ return structured result to caller
 *
 * Design knobs settled at this layer:
 *
 *   1. **Subprocess `ssh`, not a Node SSH library.** The repo's prior art
 *      (`src/commands/users.ts`, `src/commands/server.ts`,
 *      `src/commands/invites.ts`) all spawn the system `ssh` binary; the
 *      operator already has SSH set up (otherwise stamp's server-gated
 *      mode wouldn't work). Reusing `~/.ssh/config` + `~/.ssh/known_hosts`
 *      + the operator's agent for free is worth far more than a JS-native
 *      SSH dependency.
 *
 *   2. **Diff streamed via stdin.** We write the diff bytes to the
 *      child's stdin and close — the server reads `MAX_DIFF_BYTES`-bounded
 *      stdin and cross-checks the streamed sha256 against `--diff-sha256`
 *      before invoking the pipeline. Matches the AGT-328 verb's contract
 *      verbatim.
 *
 *   3. **Signature verified against the manifest at `base_sha`.** The
 *      caller passes `manifestYaml` (sourced via `git show
 *      <base_sha>:.stamp/trusted-keys/manifest.yml` upstream). We refuse
 *      any response whose `server_key_id` doesn't appear in the manifest
 *      with `capabilities: [server]`, and any signature that doesn't
 *      verify under that key's pubkey. The pubkey itself comes from
 *      `.stamp/trusted-keys/*.pub` matched by fingerprint.
 *
 *   4. **Error mapping pinned by the verb's exit-code contract.** AGT-328
 *      documented exit codes 0/1/2/3/4 with specific semantics. We map
 *      each to a clear operator-facing message so a missing config
 *      doesn't look like a JSON parse failure or vice versa.
 */

import { createHash, createPublicKey, verify } from "node:crypto";
import { spawn } from "node:child_process";

import {
  canonicalSerializeApproval,
  type ApprovalV4,
} from "./attestationV4.js";
import { fingerprintFromPem } from "./keys.js";
import {
  parseManifest,
  resolveCapability,
} from "./trustedKeysManifest.js";

// ─── URL parsing ────────────────────────────────────────────────────

/** Parsed `review_server` URL parts. */
export interface ReviewServerUrl {
  user: string;
  host: string;
  port: number;
}

/**
 * Parse a `review_server` URL of the form
 *   ssh://[user@]host[:port]
 *
 * Defaults `user` to `git` and `port` to `22`, matching the operator-
 * facing examples in `docs/plans/server-attested-reviews.md`. Rejects
 * any non-`ssh:` scheme and anything that's structurally garbage so the
 * operator sees a clean "config error" before we try to spawn ssh.
 *
 * Shape regexes are deliberately conservative: hostnames must look like
 * hostnames (alphanumerics + . - / leading-and-trailing alphanumeric),
 * and the user must match the same shape `serverConfig.ts` validates
 * elsewhere. The hostile shape we're defending against is a URL
 * containing something like `-oProxyCommand=...` which `ssh` would
 * re-interpret as an option; a hostname or user that starts with `-`
 * or contains `=` / whitespace / control chars is structurally
 * impossible by these regexes.
 */
export function parseReviewServerUrl(input: string): ReviewServerUrl {
  if (typeof input !== "string" || input.length === 0) {
    throw new Error(`review_server URL is empty`);
  }
  const SCHEME = "ssh://";
  if (!input.startsWith(SCHEME)) {
    throw new Error(
      `review_server must be an ssh:// URL (got ${JSON.stringify(input)})`,
    );
  }
  const rest = input.slice(SCHEME.length);
  if (!rest) {
    throw new Error(`review_server has no host (${JSON.stringify(input)})`);
  }

  // Split off optional path; we don't use it but reject anything past
  // the authority so a trailing /some/path doesn't get silently dropped
  // and then later cause confusion.
  const slashIdx = rest.indexOf("/");
  const authority = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
  if (slashIdx !== -1 && rest.slice(slashIdx + 1).length > 0) {
    throw new Error(
      `review_server URL must not include a path (got ${JSON.stringify(input)})`,
    );
  }

  let user = "git";
  let hostPort = authority;
  const at = authority.indexOf("@");
  if (at !== -1) {
    user = authority.slice(0, at);
    hostPort = authority.slice(at + 1);
    if (!user) {
      throw new Error(
        `review_server URL has an empty user (got ${JSON.stringify(input)})`,
      );
    }
  }

  let host = hostPort;
  let port = 22;
  const colon = hostPort.lastIndexOf(":");
  if (colon !== -1) {
    host = hostPort.slice(0, colon);
    const portStr = hostPort.slice(colon + 1);
    const n = Number(portStr);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      throw new Error(
        `review_server URL port must be 1..65535 (got ${JSON.stringify(portStr)})`,
      );
    }
    port = n;
  }
  if (!host) {
    throw new Error(
      `review_server URL has an empty host (got ${JSON.stringify(input)})`,
    );
  }

  // Shape-validate user/host. Same regexes as serverConfig.ts.
  const USER_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
  const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;
  if (!USER_RE.test(user)) {
    throw new Error(
      `review_server URL user has invalid shape (got ${JSON.stringify(user)})`,
    );
  }
  if (!HOST_RE.test(host)) {
    throw new Error(
      `review_server URL host has invalid shape (got ${JSON.stringify(host)})`,
    );
  }

  return { user, host, port };
}

// ─── Response parsing ────────────────────────────────────────────────

/**
 * Structured result returned to the caller. Mirrors
 * `ReviewPipelineResult` on the server side (and the `StampReviewResponse`
 * shape pinned in design.md "Server API surface"). The signature has
 * already been verified by the time this object is returned — callers
 * can persist the bytes directly.
 */
export interface ServerReviewResult {
  verdict: ApprovalV4["verdict"];
  prose: string;
  approval: ApprovalV4;
  signature: string;
  /** `JSON.stringify(approval)` for DB persistence. NOT the raw wire bytes
   *  the server sent — JSON.parse + re-stringify reorders keys non-
   *  deterministically. Downstream verifiers call
   *  `canonicalSerializeApproval` before checking the signature, so key
   *  order doesn't matter for verification; the field exists to give
   *  `reviews.server_approval_json` a parseable record of the approval
   *  body. AGT-334's merge folder also re-canonicalizes before checking. */
  approvalJson: string;
  /**
   * AGT-355: when the server surfaces the v3 PR-attestation payload
   * fields (`pr_attestation_v3_payload_b64` + `_signature_b64`) we
   * surface them on the result as forward-looking metadata. The
   * actual canonicalizer-drift defense-in-depth check runs inside
   * `requestServerReview` BEFORE this object is built: the wire bytes
   * are compared against locally-recomputed
   * `canonicalSerializeApproval(parsed.approval)` and the request
   * rejects on mismatch. Past that point, the trust property is
   * carried by the parsed approval + DB persistence path (AGT-332);
   * `prAttestationV3` here is informational surface for callers that
   * want to inspect the wire-format extension (e.g. logging,
   * diagnostics, future use cases).
   *
   * `stamp attest`'s `buildV3Envelope` re-canonicalizes from the
   * stored DB JSON when folding the approval — it does NOT consume
   * this field. Byte identity is guaranteed because the SSH-time
   * check already confirmed the parsed approval canonicalizes to
   * the same bytes the server signed.
   *
   * `null` when the server's response omits these fields — i.e. an
   * older 2.0.0 server that predates AGT-355's producer code. This
   * case is benign: `stamp attest` still produces a v3 envelope
   * because the legacy `approval` + `signature` fields (always
   * present) carry the same data, and the DB-persistence path
   * doesn't depend on this field.
   */
  prAttestationV3: {
    /** Canonical bytes of `ApprovalV4` — exactly the bytes the
     *  server's Ed25519 signature commits to. Same content as
     *  `canonicalSerializeApproval(approval)` recomputed locally;
     *  the wire-bytes equality is asserted at SSH-parse time. */
    payloadBytes: Buffer;
    /** Base64 Ed25519 signature over `payloadBytes`. Same value as the
     *  legacy `signature` field; surfaced under the v3-flavored name
     *  for grep-ability at the wire layer. */
    signatureB64: string;
  } | null;
}

/**
 * Validate that a parsed JSON value matches the shape design.md pins for
 * `stamp-review`. Returns the typed result on success, throws on any
 * structural mismatch — the verifier's pattern of "fail closed on
 * garbage input before doing any further work."
 */
function parseResponseJson(raw: string): {
  verdict: ApprovalV4["verdict"];
  prose: string;
  approval: ApprovalV4;
  signature: string;
  /** AGT-355: present when the server surfaces the v3 PR-attestation
   *  payload + signature fields. `null` when the server's response
   *  omits them — i.e. an older 2.0.0 server. See the
   *  `ServerReviewResult.prAttestationV3` docstring for forward-compat
   *  dispatch semantics. */
  prAttestationV3: {
    payloadBytes: Buffer;
    signatureB64: string;
  } | null;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `review_server returned malformed JSON: ${err instanceof Error ? err.message : String(err)}. ` +
        `First 200 bytes: ${JSON.stringify(raw.slice(0, 200))}`,
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      `review_server response must be a JSON object (got ${typeof parsed})`,
    );
  }
  const obj = parsed as Record<string, unknown>;
  const verdict = obj.verdict;
  if (verdict !== "approved" && verdict !== "changes_requested" && verdict !== "denied") {
    throw new Error(
      `review_server response.verdict must be approved|changes_requested|denied ` +
        `(got ${JSON.stringify(verdict)})`,
    );
  }
  if (typeof obj.prose !== "string") {
    throw new Error(`review_server response.prose must be a string`);
  }
  if (typeof obj.signature !== "string" || !obj.signature) {
    throw new Error(`review_server response.signature must be a non-empty string`);
  }
  const approval = obj.approval;
  if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
    throw new Error(`review_server response.approval must be a JSON object`);
  }
  const a = approval as Record<string, unknown>;
  for (const field of [
    "reviewer",
    "verdict",
    "prompt_sha256",
    "diff_sha256",
    "base_sha",
    "head_sha",
    "trusted_keys_snapshot_sha256",
    "issued_at",
    "server_key_id",
  ]) {
    if (typeof a[field] !== "string") {
      throw new Error(
        `review_server response.approval.${field} must be a string`,
      );
    }
  }
  if (
    a.verdict !== "approved" &&
    a.verdict !== "changes_requested" &&
    a.verdict !== "denied"
  ) {
    throw new Error(
      `review_server response.approval.verdict must be approved|changes_requested|denied ` +
        `(got ${JSON.stringify(a.verdict)})`,
    );
  }
  if (a.verdict !== verdict) {
    throw new Error(
      `review_server response: top-level verdict (${verdict}) and approval.verdict ` +
        `(${a.verdict}) disagree`,
    );
  }
  // AGT-355: extract the optional v3 PR-attestation fields. Both must
  // be present together (all-or-nothing — a half-populated response
  // would be a server bug). When absent, the result's prAttestationV3
  // is null and the caller falls back to the legacy attest path.
  let prAttestationV3: { payloadBytes: Buffer; signatureB64: string } | null = null;
  const payloadB64 = obj["pr_attestation_v3_payload_b64"];
  const sigB64 = obj["pr_attestation_v3_signature_b64"];
  if (payloadB64 !== undefined || sigB64 !== undefined) {
    if (typeof payloadB64 !== "string" || !payloadB64) {
      throw new Error(
        `review_server response.pr_attestation_v3_payload_b64 must be a non-empty string when present`,
      );
    }
    if (typeof sigB64 !== "string" || !sigB64) {
      throw new Error(
        `review_server response.pr_attestation_v3_signature_b64 must be a non-empty string when present`,
      );
    }
    prAttestationV3 = {
      payloadBytes: Buffer.from(payloadB64, "base64"),
      signatureB64: sigB64,
    };
  }
  return {
    verdict,
    prose: obj.prose,
    approval: approval as ApprovalV4,
    signature: obj.signature,
    prAttestationV3,
  };
}

// ─── Signature verification ─────────────────────────────────────────

/**
 * Verify the server's Ed25519 signature over `canonicalSerializeApproval(
 * approval)`. Returns nothing on success; throws with operator-actionable
 * prose on every refusal path.
 *
 * Trust chain:
 *   - manifest at `base_sha` lists the server's fingerprint with
 *     `capabilities: [server]` — without this, the response is from a
 *     key the repo doesn't trust to attest reviews
 *   - the corresponding .pub file exists under `.stamp/trusted-keys/`
 *     and matches the fingerprint
 *   - the signature verifies against that pubkey over the canonical
 *     bytes of the approval body
 *
 * Refusing on any link of the chain is the difference between trusting
 * the response and not — there's no graceful-degrade middle ground.
 */
function verifyServerSignature(opts: {
  approval: ApprovalV4;
  signatureB64: string;
  manifestYaml: string;
  pubkeyByFingerprint: Map<string, string>;
}): void {
  const manifest = parseManifest(opts.manifestYaml);
  if (!manifest) {
    throw new Error(
      `review_server response cannot be verified: .stamp/trusted-keys/manifest.yml at base_sha ` +
        `is missing or malformed. Trusted-mode review requires a valid manifest.`,
    );
  }
  const caps = resolveCapability(manifest, opts.approval.server_key_id);
  if (caps === null) {
    throw new Error(
      `review_server response signed by ${opts.approval.server_key_id}, but that key isn't ` +
        `in .stamp/trusted-keys/manifest.yml at base_sha. Add the server's fingerprint ` +
        `with capabilities: [server] to the manifest and re-run.`,
    );
  }
  if (!caps.includes("server")) {
    throw new Error(
      `review_server response signed by ${opts.approval.server_key_id}, but that key's ` +
        `capabilities in the manifest are [${caps.join(", ")}] — missing the required ` +
        `'server' capability. Update .stamp/trusted-keys/manifest.yml at base_sha.`,
    );
  }
  const pubPem = opts.pubkeyByFingerprint.get(opts.approval.server_key_id);
  if (!pubPem) {
    throw new Error(
      `review_server response signed by ${opts.approval.server_key_id}, but no .pub file ` +
        `in .stamp/trusted-keys/ at base_sha matches that fingerprint. Commit the server's ` +
        `pubkey alongside the manifest entry.`,
    );
  }
  const pubKey = createPublicKey(pubPem);
  const canonical = canonicalSerializeApproval(opts.approval);
  const sigBytes = Buffer.from(opts.signatureB64, "base64");
  // Ed25519 via crypto.verify(null, ...) — same call shape signing.ts uses.
  const ok = verify(null, canonical, pubKey, sigBytes);
  if (!ok) {
    throw new Error(
      `review_server response signature failed Ed25519 verification under key ${opts.approval.server_key_id}. ` +
        `The response was signed by a different key than the manifest claims, or the bytes were corrupted in transit.`,
    );
  }
}

// ─── SSH child wrapper ──────────────────────────────────────────────

/**
 * Spawn `ssh ... stamp-review ...`, stream the diff on stdin, collect
 * stdout/stderr to completion. The shape of the call mirrors the
 * existing `spawnSync("ssh", ...)` call sites in `src/commands/users.ts`
 * and `src/commands/server.ts` — `--` before the destination terminates
 * ssh's option processing (defense against any future code path that
 * lets a hostile field reach the argv).
 *
 * Returns `{ stdout, stderr, exitCode }` for the caller to interpret
 * against the verb's documented exit-code contract.
 */
export interface SshSpawnResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
}

/** Test seam: lets tests replace the SSH subprocess with a fake that
 *  reads the diff, returns canned stdout/stderr/exit-code. Production
 *  callers leave this `undefined` and the real `ssh` binary runs. */
export type SshSpawnFn = (
  url: ReviewServerUrl,
  remoteArgs: string[],
  diff: Buffer,
) => Promise<SshSpawnResult>;

async function defaultSshSpawn(
  url: ReviewServerUrl,
  remoteArgs: string[],
  diff: Buffer,
): Promise<SshSpawnResult> {
  // ssh argv layout matches users.ts: `-p <port> -- user@host <verb> <args...>`.
  // The `--` is the canonical guard against any future call site letting a
  // hostile field interpolate into argv as an option.
  const sshArgv = [
    "-p",
    String(url.port),
    "--",
    `${url.user}@${url.host}`,
    "stamp-review",
    ...remoteArgs,
  ];

  return new Promise<SshSpawnResult>((resolvePromise, rejectPromise) => {
    const child = spawn("ssh", sshArgv, {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdoutChunks.push(c));
    child.stderr.on("data", (c: Buffer) => stderrChunks.push(c));

    child.on("error", (err) => {
      // ENOENT / EACCES on the ssh binary itself — operator's PATH doesn't
      // include ssh, etc. Distinct from the verb returning non-zero (handled
      // via the close event); a spawn error is "couldn't even start ssh".
      rejectPromise(
        new Error(
          `failed to spawn ssh for review_server ssh://${url.user}@${url.host}:${url.port}: ${err.message}`,
        ),
      );
    });

    child.on("close", (exitCode, signal) => {
      resolvePromise({
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        exitCode,
        signal,
      });
    });

    // Stream the diff in one shot. The diff is already in memory (the
    // command-layer has a Buffer-backed string), so a single write +
    // end is fine — no chunked-flow back-pressure to manage here.
    // Errors writing to stdin (EPIPE if the server closed early) surface
    // via the 'error' event on the writable stream; emit them as the
    // promise rejection so the caller sees a clear "couldn't deliver diff"
    // rather than a silent empty stdout.
    child.stdin.on("error", (err) => {
      // The 'close' event will still fire after this; reject early so the
      // operator sees the EPIPE rather than a confusing exit-code-1 with
      // empty stdout.
      rejectPromise(
        new Error(
          `failed to write diff to ssh stdin for ` +
            `review_server ssh://${url.user}@${url.host}:${url.port}: ${err.message}`,
        ),
      );
    });
    child.stdin.write(diff);
    child.stdin.end();
  });
}

// ─── Public entrypoint ─────────────────────────────────────────────

export interface RequestServerReviewInput {
  reviewServerUrl: string;
  reviewer: string;
  org: string;
  repo: string;
  baseSha: string;
  headSha: string;
  diff: Buffer;
  /** Bytes of `.stamp/trusted-keys/manifest.yml` at `baseSha`. Caller
   *  resolves via `git show <baseSha>:.stamp/trusted-keys/manifest.yml`
   *  so the manifest the server signed against is the same one the
   *  client verifies against — there's no race between commit and
   *  signature verification. */
  manifestYaml: string;
  /** Map from `sha256:<hex>` fingerprint → PEM bytes for every
   *  `.stamp/trusted-keys/*.pub` file at `baseSha`. Caller resolves
   *  via `git ls-tree` + `git show`; this layer doesn't touch git
   *  directly so the same client can be unit-tested with synthetic
   *  fixtures. */
  pubkeyByFingerprint: Map<string, string>;
  /** Test-only injection seam. Production callers leave this
   *  `undefined` and the system `ssh` binary runs. */
  _sshSpawnForTest?: SshSpawnFn;
}

/**
 * The high-level operation: compute the diff sha256, invoke the verb
 * via SSH, parse the response, verify the signature, return the
 * structured result.
 *
 * Throws on every refusal path (SSH spawn failure, verb non-zero exit,
 * malformed JSON, signature verification failure). Each error message
 * names the operator-actionable next step — there's no caller-friendly
 * "return null" path because every failure here means "this review
 * cannot be trusted" and the caller MUST surface that to the operator.
 */
export async function requestServerReview(
  input: RequestServerReviewInput,
): Promise<ServerReviewResult> {
  const url = parseReviewServerUrl(input.reviewServerUrl);
  const diffSha256 = createHash("sha256").update(input.diff).digest("hex");

  const remoteArgs = [
    "--reviewer",
    input.reviewer,
    "--org",
    input.org,
    "--repo",
    input.repo,
    "--base-sha",
    input.baseSha,
    "--head-sha",
    input.headSha,
    "--diff-sha256",
    diffSha256,
  ];

  const spawnFn = input._sshSpawnForTest ?? defaultSshSpawn;
  const result = await spawnFn(url, remoteArgs, input.diff);

  if (result.exitCode !== 0) {
    // Map the verb's documented exit codes (AGT-328:
    // 1=server-config, 2=usage, 3=role-permission, 4=request-validation)
    // to operator-readable prose. Always surface the server's stderr —
    // it carries the structured `error: ...` line the verb writes,
    // which is the most actionable hint for the operator.
    const stderr = result.stderr.trim();
    const hint = exitCodeHint(result.exitCode);
    const signalNote = result.signal ? ` (killed by signal ${result.signal})` : "";
    throw new Error(
      `review_server returned exit ${result.exitCode}${signalNote} for reviewer ${input.reviewer}.\n` +
        `  url: ssh://${url.user}@${url.host}:${url.port}\n` +
        `  hint: ${hint}\n` +
        (stderr ? `  server stderr:\n    ${stderr.split("\n").join("\n    ")}` : "  (no stderr)"),
    );
  }

  const parsed = parseResponseJson(result.stdout);
  verifyServerSignature({
    approval: parsed.approval,
    signatureB64: parsed.signature,
    manifestYaml: input.manifestYaml,
    pubkeyByFingerprint: input.pubkeyByFingerprint,
  });

  // Cross-check the approval body against what the client asked for —
  // a server bug that returned a verdict for the wrong reviewer/sha pair
  // would otherwise quietly pollute the local DB. The signature already
  // covers all of these fields, so a mismatch here means we successfully
  // verified a signature over a payload that doesn't describe this
  // request — which is exactly the conditional we want to refuse.
  if (parsed.approval.reviewer !== input.reviewer) {
    throw new Error(
      `review_server returned a signed approval for reviewer ${JSON.stringify(parsed.approval.reviewer)} ` +
        `but we asked for ${JSON.stringify(input.reviewer)} — refusing.`,
    );
  }
  if (parsed.approval.base_sha !== input.baseSha) {
    throw new Error(
      `review_server returned a signed approval for base_sha ${parsed.approval.base_sha} ` +
        `but we asked for ${input.baseSha} — refusing.`,
    );
  }
  if (parsed.approval.head_sha !== input.headSha) {
    throw new Error(
      `review_server returned a signed approval for head_sha ${parsed.approval.head_sha} ` +
        `but we asked for ${input.headSha} — refusing.`,
    );
  }
  if (parsed.approval.diff_sha256 !== diffSha256) {
    throw new Error(
      `review_server returned a signed approval for diff_sha256 ${parsed.approval.diff_sha256} ` +
        `but we sent diff_sha256 ${diffSha256} — refusing.`,
    );
  }

  // AGT-355: when the server surfaced the v3 PR-attestation payload
  // fields, defensively check that the canonical bytes ride agree with
  // the bytes a fresh `canonicalSerializeApproval(parsed.approval)`
  // produces. If the server's canonicalizer ever drifts from the
  // client's, this catches it BEFORE `stamp attest` would build an
  // envelope with mismatched inner bytes and produce an attestation
  // the verifier would reject confusingly. The signature has already
  // been verified above against the canonical bytes WE compute, so
  // confirming the wire bytes match means we can ride them straight
  // into the envelope.
  if (parsed.prAttestationV3) {
    const localCanonical = canonicalSerializeApproval(parsed.approval);
    if (!parsed.prAttestationV3.payloadBytes.equals(localCanonical)) {
      throw new Error(
        `review_server returned pr_attestation_v3_payload_b64 bytes that do not match ` +
          `canonicalSerializeApproval(approval) recomputed locally — refusing. ` +
          `This indicates a server/client canonicalizer drift (server stamp version mismatch?). ` +
          `Server bytes (first 80): ${JSON.stringify(parsed.prAttestationV3.payloadBytes.toString("utf8").slice(0, 80))}; ` +
          `client bytes (first 80): ${JSON.stringify(localCanonical.toString("utf8").slice(0, 80))}.`,
      );
    }
    if (parsed.prAttestationV3.signatureB64 !== parsed.signature) {
      throw new Error(
        `review_server returned pr_attestation_v3_signature_b64 that disagrees with the top-level signature — refusing.`,
      );
    }
  }

  // Serialize the parsed approval body for DB persistence. This is a
  // re-stringification, NOT the raw wire bytes — JSON.parse + re-stringify
  // doesn't preserve key order. That's fine: downstream verifiers
  // (AGT-334's merge folder, the pre-receive hook) call
  // `canonicalSerializeApproval` before signature verification, so the
  // canonical sort makes key-order differences invisible to the check.
  return {
    verdict: parsed.verdict,
    prose: parsed.prose,
    approval: parsed.approval,
    signature: parsed.signature,
    approvalJson: JSON.stringify(parsed.approval),
    prAttestationV3: parsed.prAttestationV3,
  };
}

function exitCodeHint(exitCode: number | null): string {
  switch (exitCode) {
    case 1:
      return "server-side config error (ExposeAuthInfo missing, signing key path unreadable, ...) — check the server's startup logs.";
    case 2:
      return "usage error — likely a client/server protocol mismatch. Check that the server is running a compatible stamp version.";
    case 3:
      return "the SSH key you connected with isn't enrolled as a member on this stamp server. Run `stamp invites accept <url>` or ask an admin to enroll you.";
    case 4:
      return "request validation failed (diff size cap or sha256 mismatch) — check `stamp review` isn't being asked to review an unbounded diff.";
    default:
      return `unrecognized exit code ${exitCode} — surface the stderr verbatim and check the server logs.`;
  }
}

// ─── Pubkey-load helper ────────────────────────────────────────────

/**
 * Load every `*.pub` file from the trusted-keys directory at `baseSha`
 * (via the caller's `showAtRef`-equivalent reader) and index by
 * fingerprint. Exposed so the command layer can build the map once and
 * reuse it across N parallel reviewer requests without re-reading the
 * git tree N times.
 *
 * `readAtBase(path)` returns the file contents or throws — same shape
 * as `showAtRef`. The function silently skips files that aren't
 * parseable as PEM (a stray .pub file from an unrelated tool shouldn't
 * fail the whole load); it returns the resolvable subset.
 */
export function buildPubkeyMap(
  pubFilenames: string[],
  readAtBase: (path: string) => string,
): Map<string, string> {
  const out = new Map<string, string>();
  for (const name of pubFilenames) {
    if (!name.endsWith(".pub")) continue;
    let pem: string;
    try {
      pem = readAtBase(`.stamp/trusted-keys/${name}`);
    } catch {
      continue;
    }
    let fp: string;
    try {
      fp = fingerprintFromPem(pem);
    } catch {
      continue;
    }
    out.set(fp, pem);
  }
  return out;
}
