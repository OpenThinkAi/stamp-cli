/**
 * SSH verb: subscribe a listener agent to peer-review events (AGT-427).
 *
 * Accepts and records the subscribing listener's `orgs` list and
 * `fingerprint` in the in-memory registry. Delivers events synchronously
 * to subscribed listeners during the SAME PROCESS's lifetime.
 *
 * NOTE: This is an in-process stub. Because each SSH-verb invocation is its
 * own short-lived process (AGT-420 invariant), the registry is not shared
 * across processes. A real long-running subscription requires WebSocket
 * transport (Step h, AGT-434). Until then, the `subscribe` verb records
 * the listener for the duration of a single process invocation only, and
 * cross-process event delivery is a no-op in production.
 *
 * Payload fields (JSON):
 *   orgs (string[]), fingerprint, signature
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — validation / auth failure
 */

import {
  findUserBySshFingerprint,
  openServerDb,
  touchLastSeen,
} from "../lib/serverDb.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

import {
  notConfiguredResponse,
  registerListener,
  resolvePeerReviewLimit,
  resolvePeerReviewsEnabled,
  MAX_SUBSCRIBED_ORGS_DEFAULT,
} from "./peerReviews.js";

function fail(message: string, exitCode: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(exitCode);
}

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : (chunk as Buffer));
  }
  return Buffer.concat(chunks);
}

interface SubscribePayload {
  orgs: string[];
  fingerprint: string;
  signature: string;
}

function parsePayload(raw: Buffer): SubscribePayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(`subscribe payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`, 4);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("subscribe payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  if (!Array.isArray(p["orgs"]) || !p["orgs"].every((x) => typeof x === "string")) {
    fail("subscribe payload: orgs must be an array of strings", 4);
  }
  if (typeof p["fingerprint"] !== "string") fail("subscribe payload missing or invalid field: fingerprint", 4);
  if (typeof p["signature"] !== "string") fail("subscribe payload missing or invalid field: signature", 4);

  return p as unknown as SubscribePayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "note: STAMP_PEER_REVIEWS_ENABLED is not set; subscribe is a no-op\n",
    );
    process.stdout.write(notConfiguredResponse() + "\n");
    process.exit(0);
  }

  const maxOrgs = resolvePeerReviewLimit("MAX_SUBSCRIBED_ORGS", MAX_SUBSCRIBED_ORGS_DEFAULT);

  const caller = readAuthenticatedPubkey();
  if (!caller) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or " +
        "has no publickey entry). Server may be missing 'ExposeAuthInfo yes' " +
        "in sshd_config.",
      1,
    );
  }

  const db = openServerDb({ skipChmod: true });
  try {
    const callerRow = findUserBySshFingerprint(db, caller.fingerprint);
    if (!callerRow) {
      fail(`caller fingerprint ${caller.fingerprint} is not in the membership DB`, 1);
    }
    touchLastSeen(db, callerRow.id);

    const raw = await readStdin();
    const payload = parsePayload(raw);

    if (payload.orgs.length > maxOrgs) {
      fail(
        `orgs list has ${payload.orgs.length} entries — exceeds MAX_SUBSCRIBED_ORGS (${maxOrgs})`,
        4,
      );
    }

    // Register the listener in the in-memory registry.
    // For the SSH-verb spike, this is a no-op in production for cross-process
    // delivery; the registration is useful within the same process (e.g. tests).
    registerListener(payload.fingerprint, {
      orgs: payload.orgs,
      onEvent: (_event) => {
        // In a real WebSocket transport (AGT-434), this would push the event
        // over the WS connection. For the SSH stub, events are delivered
        // synchronously by the fanout caller within the same process.
      },
    });

    process.stderr.write(
      `note: listener registered (in-process stub only — cross-process delivery ` +
        `requires WebSocket transport, AGT-434)\n`,
    );

    process.stdout.write(
      JSON.stringify({
        ok: true,
        fingerprint: payload.fingerprint,
        orgs: payload.orgs,
        note: "in-process subscription only; cross-process delivery requires WebSocket transport (AGT-434)",
      }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: subscribe crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
