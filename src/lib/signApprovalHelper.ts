/**
 * Core of the root signing helper `stamp-sign-approval` (AGT-2263).
 * The entry point (`src/server/sign-approval.ts`) wires real stdio, the
 * clock and the env-resolved key path; this function holds the logic so
 * it is unit-testable without sudo.
 *
 * Contract:
 *   - no arguments (the sudoers rule admits none either);
 *   - stdin: the canonical approval bytes (see `approvalSigning.ts` for
 *     the exact checks — this helper never signs arbitrary bytes);
 *   - stdout on success: the base64 Ed25519 signature + "\n", nothing else;
 *   - exit 0 signed, 1 key unavailable / wrong posture, 2 refused payload
 *     or usage.
 */

import { sign } from "node:crypto";

import {
  ApprovalPayloadError,
  validateApprovalPayload,
} from "./approvalSigning.js";
import { loadReviewSigningKey, ReviewSigningKeyError } from "./reviewSigningKey.js";

export interface SignApprovalIo {
  argv: string[];
  stdin: Buffer;
  privateKeyPath: string;
  now?: Date;
  out: (s: string) => void;
  err: (s: string) => void;
  /** One-line audit record per signature. Production writes it to the
   *  container log; tests capture it. Best effort — never fails a sign. */
  audit?: (line: string) => void;
}

export function runSignApproval(io: SignApprovalIo): number {
  if (io.argv.length > 0) {
    io.err("error: stamp-sign-approval takes no arguments (approval JSON on stdin)\n");
    return 2;
  }

  let loaded;
  try {
    loaded = loadReviewSigningKey({ privateKeyPath: io.privateKeyPath });
  } catch (err) {
    if (err instanceof ReviewSigningKeyError) {
      io.err(`error: ${err.message}\n`);
      return 1;
    }
    io.err(`error: review-signing key could not be loaded: ${(err as Error).message}\n`);
    return 1;
  }

  let validated;
  try {
    validated = validateApprovalPayload(io.stdin, {
      expectedKeyId: loaded.fingerprint,
      now: io.now,
    });
  } catch (err) {
    if (err instanceof ApprovalPayloadError) {
      io.err(`error: refusing to sign: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  const signature = sign(null, validated.canonical, loaded.privateKey).toString("base64");
  const a = validated.approval;
  try {
    io.audit?.(
      `stamp-sign-approval: signed reviewer=${a.reviewer} verdict=${a.verdict} ` +
        `repo_id=${a.repo_id} base=${a.base_sha} head=${a.head_sha} ` +
        `diff_sha256=${a.diff_sha256} issued_at=${a.issued_at}\n`,
    );
  } catch {
    // Audit is best effort; the signature is still valid and bounded.
  }
  io.out(signature + "\n");
  return 0;
}
