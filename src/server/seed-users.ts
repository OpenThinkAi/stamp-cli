/**
 * Boot-time entrypoint: bootstrap the membership sqlite from the
 * AUTHORIZED_KEYS env var — ONCE, on a brand-new server (AGT-2260).
 *
 * Runs on every container boot, as root, from /entrypoint.sh — BEFORE sshd
 * is exec'd. The seeding rule:
 *
 *   - users table empty AND no bootstrap marker → import every valid
 *     AUTHORIZED_KEYS line as role=admin source=env, then record the
 *     marker (server_meta ENV_SEED_MARKER) in the same transaction.
 *   - users table already populated, no marker (a server upgraded from a
 *     version that re-seeded on every boot) → record the marker WITHOUT
 *     importing anything. Existing rows keep their access; nothing that is
 *     missing from the table is brought back.
 *   - marker present → never import again.
 *
 * Why: before AGT-2260 this script re-imported AUTHORIZED_KEYS on every
 * boot, so a user removed with `stamp users remove` came back on the next
 * restart while their key was still in the env var. users.db is now the
 * only source of SSH access (sshd_config has `AuthorizedKeysFile none`),
 * and after bootstrap it is managed only through `stamp invites` /
 * `stamp users` — or, if every admin is locked out, the root-only
 * `stamp-break-glass` CLI inside the container.
 *
 * Keys listed in AUTHORIZED_KEYS that are not in the table after bootstrap
 * are reported (fingerprint only) so an operator who expected a redeploy
 * to add one sees why it didn't.
 *
 * Why every env-imported key becomes admin (not member): under the legacy
 * model, anyone in AUTHORIZED_KEYS had full server access. Importing them
 * as admins preserves that trust posture; the operator can demote anyone
 * with `stamp users demote`.
 *
 * The OPERATOR_PUB_KEY env var is the operator's stamp SIGNING pubkey (PEM)
 * — distinct from their SSH pubkey. It is NOT seeded into the users table
 * here; entrypoint.sh writes it to /etc/stamp/operator.pub for
 * new-stamp-repo.
 */

import {
  countUsers,
  ENV_SEED_MARKER,
  findUserBySshFingerprint,
  getServerMeta,
  openServerDb,
  setServerMeta,
  suggestUniqueShortName,
  upsertUserByFingerprint,
} from "../lib/serverDb.js";
import type { DatabaseSync } from "node:sqlite";
import {
  contentAddressedShortName,
  parseSshPubkeyList,
  sshPubkeyBody,
  type SshPubkey,
} from "../lib/sshKeys.js";

const AUTHORIZED_KEYS = process.env["AUTHORIZED_KEYS"] ?? "";

function reportIgnored(db: DatabaseSync, pubkeys: SshPubkey[]): void {
  const missing = pubkeys.filter((pk) => !findUserBySshFingerprint(db, pk.fingerprint));
  if (missing.length === 0) return;
  console.error(
    `stamp-seed-users: warning: ${missing.length} AUTHORIZED_KEYS key(s) are not members and were NOT added ` +
      `(the env var only bootstraps an empty server): ${missing.map((pk) => pk.fingerprint).join(", ")}. ` +
      `Add a member with 'stamp invites mint', or as root in the container with 'stamp-break-glass add'.`,
  );
}

function main(): void {
  if (AUTHORIZED_KEYS.trim().length === 0) {
    console.log("stamp-seed-users: AUTHORIZED_KEYS env var unset or empty; nothing to bootstrap");
    return;
  }

  const { pubkeys, errors } = parseSshPubkeyList(AUTHORIZED_KEYS);
  for (const err of errors) {
    console.error(
      `stamp-seed-users: ignoring malformed AUTHORIZED_KEYS line ${err.lineNumber}: ${err.error}`,
    );
  }

  const db = openServerDb();
  try {
    const marker = getServerMeta(db, ENV_SEED_MARKER);
    if (marker !== null) {
      console.log(
        `stamp-seed-users: server already bootstrapped (${marker}); AUTHORIZED_KEYS is not re-imported`,
      );
      reportIgnored(db, pubkeys);
      return;
    }

    const existing = countUsers(db);
    if (existing > 0) {
      // Upgrade from a pre-AGT-2260 server: the table was seeded by an
      // earlier boot. Record the bootstrap as done without importing, so a
      // user removed from here on stays removed.
      setServerMeta(db, ENV_SEED_MARKER, `existing-users at upgrade (${existing})`);
      console.log(
        `stamp-seed-users: users table already has ${existing} member(s); recorded bootstrap as done. ` +
          `AUTHORIZED_KEYS is no longer re-imported on boot.`,
      );
      reportIgnored(db, pubkeys);
      return;
    }

    if (pubkeys.length === 0) {
      console.log("stamp-seed-users: AUTHORIZED_KEYS parsed to 0 valid pubkeys; nothing to bootstrap");
      return;
    }

    let imported = 0;
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const pk of pubkeys) {
        // AGT-422: content-addressed, PII-free short_name; comment-stripped
        // key body (sshd matches on the blob, not the comment).
        const short_name = suggestUniqueShortName(db, contentAddressedShortName(pk));
        const result = upsertUserByFingerprint(db, {
          short_name,
          ssh_pubkey: sshPubkeyBody(pk),
          ssh_fp: pk.fingerprint,
          role: "admin",
          source: "env",
        });
        if (result.created) imported++;
      }
      setServerMeta(db, ENV_SEED_MARKER, `seeded ${imported} key(s) from AUTHORIZED_KEYS`);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
    console.log(
      `stamp-seed-users: bootstrapped ${imported} admin(s) from AUTHORIZED_KEYS (${pubkeys.length} valid lines); ` +
        `later changes to AUTHORIZED_KEYS are not re-imported`,
    );
  } finally {
    db.close();
  }
}

main();
