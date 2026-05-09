/**
 * One-way file read + one-way file patch for ~/.open-team/config.json.
 * stamp does NOT depend on @openthink/team at runtime; this is plain
 * JSON IO so stamp continues to work standalone when oteam is not installed.
 *
 * Used by `stamp init` to offer filling oteam's `stamp.host` field when
 * the user has a local stamp server configured but hasn't wired oteam yet.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const OTEAM_CONFIG_PATH = join(homedir(), ".open-team", "config.json");

/**
 * Read ~/.open-team/config.json (or `configPath` when provided for tests)
 * and return its parsed value, or null if the file does not exist. Throws
 * (with the file path in the message) on malformed JSON so callers can
 * distinguish "not installed" from "broken".
 */
export function readOteamConfig(configPath = OTEAM_CONFIG_PATH): unknown | null {
  if (!existsSync(configPath)) return null;
  try {
    return JSON.parse(readFileSync(configPath, "utf8")) as unknown;
  } catch (err) {
    throw new Error(
      `${configPath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Set `config.stamp.host` in ~/.open-team/config.json (or `configPath` when
 * provided for tests), preserving every other key verbatim. Uses an atomic
 * tmp-file + rename so a crash mid-write never leaves a half-written file.
 *
 * Creates the file if it does not exist. Throws (with the file path in the
 * message) on any read/write/parse failure.
 */
export function patchStampHost(host: string, configPath = OTEAM_CONFIG_PATH): void {
  let config: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    try {
      const parsed = JSON.parse(readFileSync(configPath, "utf8")) as unknown;
      if (typeof parsed === "object" && parsed !== null) {
        config = parsed as Record<string, unknown>;
      }
    } catch (err) {
      throw new Error(
        `${configPath}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  const existing = config.stamp;
  const stamp: Record<string, unknown> =
    typeof existing === "object" && existing !== null
      ? { ...(existing as Record<string, unknown>) }
      : {};
  stamp["host"] = host;
  config["stamp"] = stamp;

  const tmp = `${configPath}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(config, null, 2) + "\n", "utf8");
    renameSync(tmp, configPath);
  } catch (err) {
    throw new Error(
      `${configPath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
