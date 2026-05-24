/**
 * Boot-time entrypoint: synchronize SSH pubkeys from the legacy
 * AUTHORIZED_KEYS env var into the membership sqlite.
 *
 * Runs once per container boot, as root, from /entrypoint.sh — BEFORE
 * sshd is exec'd. Idempotent: keys already in the DB are not re-inserted,
 * and no role/short_name on existing rows is mutated. Operators who add
 * a new line to AUTHORIZED_KEYS on a redeploy will see that key picked up
 * here; operators who REMOVE a line are unaffected by this script (the
 * already-imported row stays — phase 3 surfaces a remove command).
 *
 * Why every env-imported key becomes admin (not member): under the legacy
 * model, anyone in AUTHORIZED_KEYS had full server access — push, pull,
 * merge. Importing them as members would silently downgrade their merge
 * rights. Importing them as admins preserves the existing trust posture
 * exactly. The operator can demote anyone they want via phase 3's
 * `stamp server users demote` once that ships.
 *
 * The OPERATOR_PUB_KEY env var is the operator's stamp SIGNING pubkey (PEM)
 * — distinct from their SSH pubkey. It is NOT seeded into the users table
 * here; it continues to flow through its existing path (/etc/stamp/operator.pub
 * is written by entrypoint.sh and consumed by new-stamp-repo as the seed
 * trusted signer). Phase 3 will surface a self-promote escape hatch so the
 * first operator can elevate themselves from admin to owner once they're
 * authenticated.
 */

import { openServerDb, suggestUniqueShortName, upsertUserByFingerprint } from "../lib/serverDb.js";
import {
  contentAddressedShortName,
  parseSshPubkeyList,
  sshPubkeyBody,
} from "../lib/sshKeys.js";

const AUTHORIZED_KEYS = process.env["AUTHORIZED_KEYS"] ?? "";

function main(): void {
  if (AUTHORIZED_KEYS.trim().length === 0) {
    console.log("stamp-seed-users: AUTHORIZED_KEYS env var unset or empty; nothing to sync");
    return;
  }

  const { pubkeys, errors } = parseSshPubkeyList(AUTHORIZED_KEYS);

  for (const err of errors) {
    console.error(
      `stamp-seed-users: ignoring malformed AUTHORIZED_KEYS line ${err.lineNumber}: ${err.error}`,
    );
  }

  if (pubkeys.length === 0) {
    console.log("stamp-seed-users: AUTHORIZED_KEYS parsed to 0 valid pubkeys; nothing to sync");
    return;
  }

  const db = openServerDb();

  let imported = 0;
  let skipped = 0;
  try {
    for (let i = 0; i < pubkeys.length; i++) {
      const pk = pubkeys[i]!;
      // AGT-422: default to a content-addressed, PII-free short_name and
      // persist the comment-stripped key body (the comment is decorative
      // PII; sshd matches on the blob, not the comment). A human name comes
      // only from an explicit `stamp users set-name`.
      const short_name = suggestUniqueShortName(db, contentAddressedShortName(pk));
      const result = upsertUserByFingerprint(db, {
        short_name,
        ssh_pubkey: sshPubkeyBody(pk),
        ssh_fp: pk.fingerprint,
        role: "admin",
        source: "env",
      });
      if (result.created) imported++;
      else skipped++;
    }
  } finally {
    db.close();
  }

  console.log(
    `stamp-seed-users: imported=${imported} already-present=${skipped} ` +
      `from AUTHORIZED_KEYS (${pubkeys.length} valid lines)`,
  );
}

main();
