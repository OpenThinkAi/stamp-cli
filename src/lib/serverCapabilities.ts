/**
 * Server capability probe (AGT-2276).
 *
 * Some client-side defaults are only safe against a server new enough to
 * honour them. The case that motivated this: declaring `repo_id:` in
 * `.stamp/config.yml` (AGT-2272) makes verifiers refuse every approval
 * that lacks a server-signed `repo_id`, so writing it for a repo whose
 * server predates AGT-2272 would make every approval on that repo fail.
 *
 * The probe rides on the existing `stamp-server-pubkey` git-shell verb
 * (`stamp-server-pubkey --capabilities`) rather than a new verb: it is
 * already installed on every server image, already in stamp-gate's verb
 * table, and serves only public data. A current server answers one JSON
 * line, `{"approval_repo_id":true}`; a server that predates the mode
 * refuses the flag (exit 2). Every failure — refusal, unreachable host,
 * unparsable output, a field that is absent or not literally `true` —
 * reads as "capability not present", so the default stays the
 * pre-AGT-2276 one and an old server is never broken.
 */

import { spawnSync } from "node:child_process";

/** Argument the `stamp-server-pubkey` verb answers capabilities on. */
export const CAPABILITIES_FLAG = "--capabilities";

/** What a server reports it does. Absent features are `false`. */
export interface ServerCapabilities {
  /** stamp-review signs the reviewed `<org>/<repo>` into each approval
   *  as `repo_id` (AGT-2272). */
  approvalRepoId: boolean;
}

/** SSH coordinates of the server to probe. `ServerConfig` and a parsed
 *  `review_server` URL both satisfy it. */
export interface CapabilityProbeTarget {
  user: string;
  host: string;
  port: number;
}

export type CapabilityProbeResult =
  | { ok: true; capabilities: ServerCapabilities }
  | { ok: false; reason: string };

export type CapabilityProbe = (target: CapabilityProbeTarget) => CapabilityProbeResult;

/**
 * Parse the verb's stdout. Accepts exactly one JSON object (surrounding
 * whitespace allowed); anything else is `null`. Unknown fields are
 * ignored so a newer server can add capabilities without breaking older
 * clients; a known field counts only when it is literally `true`.
 */
export function parseCapabilitiesOutput(stdout: string): ServerCapabilities | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  return { approvalRepoId: obj["approval_repo_id"] === true };
}

/** Human label for a probe target, for notes. */
export function describeProbeTarget(t: CapabilityProbeTarget): string {
  return `${t.user}@${t.host}:${t.port}`;
}

function realProbe(target: CapabilityProbeTarget): CapabilityProbeResult {
  // `--` before the destination, as at every other ssh call site: the
  // target's fields are shape-validated upstream, this is the second layer.
  //
  // No `-o BatchMode=yes` (AGT-2243 decision). None of stamp's ssh call
  // sites set it: each lets ssh ask on the terminal for a first-contact
  // host key or a key passphrase. Setting it here alone would make the
  // probe the one call that fails on first contact, quietly leaving
  // repo_id undeclared while the same command's other ssh calls prompt
  // and succeed. Without a terminal ssh cannot prompt anyway and fails,
  // which reads as "capability not present" (the safe default), and the
  // timeout below bounds a stalled connection.
  const result = spawnSync(
    "ssh",
    ["-p", String(target.port), "--", `${target.user}@${target.host}`, "stamp-server-pubkey", CAPABILITIES_FLAG],
    // stderr is captured, not inherited: an old server's refusal of the
    // flag is the expected answer there, not an error to show.
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 60_000 },
  );
  if (result.error) {
    return { ok: false, reason: `could not run ssh: ${result.error.message}` };
  }
  if (result.status !== 0) {
    return {
      ok: false,
      reason:
        `stamp-server-pubkey ${CAPABILITIES_FLAG} exited ${result.status ?? "on a signal"} ` +
        `(a server that predates the capability probe refuses it)`,
    };
  }
  const caps = parseCapabilitiesOutput(result.stdout ?? "");
  if (!caps) {
    return { ok: false, reason: `stamp-server-pubkey ${CAPABILITIES_FLAG} printed no capability JSON` };
  }
  return { ok: true, capabilities: caps };
}

let activeProbe: CapabilityProbe = realProbe;

/** Ask `target` what it supports. Never throws. */
export function probeServerCapabilities(target: CapabilityProbeTarget): CapabilityProbeResult {
  try {
    return activeProbe(target);
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/** Test seam: replace the probe. Call the returned restore fn in a
 *  `finally` so a later test doesn't inherit the fake. */
export function __setCapabilityProbeForTests(fn: CapabilityProbe): () => void {
  const prev = activeProbe;
  activeProbe = fn;
  return () => {
    activeProbe = prev;
  };
}
