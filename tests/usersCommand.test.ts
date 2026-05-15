/**
 * Client-side stamp users command tests. Today this only pins the
 * ownerless-warning logic — the surface that nudges the first admin
 * to claim ownership before anyone else does.
 *
 * Pure-function unit tests over `ownerlessWarning(rows)` so the
 * triggering condition + wording stay locked. The full SSH+JSON path
 * inside `runUsersList` is exercised in production by the existing
 * users-cli e2e tests; what's load-bearing here is "do we say the
 * right thing to the right operator at the right time?"
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ownerlessWarning } from "../src/commands/users.ts";

type Row = Parameters<typeof ownerlessWarning>[0][number];

const adminRow = (name: string): Row => ({
  id: 1,
  short_name: name,
  role: "admin",
  source: "env",
  ssh_fp: `SHA256:fake-${name}`,
  has_stamp_pubkey: false,
  invited_by: null,
  created_at: 0,
  last_seen_at: null,
});

const ownerRow = (name: string): Row => ({ ...adminRow(name), role: "owner" });
const memberRow = (name: string): Row => ({ ...adminRow(name), role: "member" });

describe("ownerlessWarning", () => {
  it("returns null on an empty users list (nothing to bootstrap from)", () => {
    assert.equal(ownerlessWarning([]), null);
  });

  it("returns null when at least one owner exists", () => {
    assert.equal(
      ownerlessWarning([ownerRow("alice"), adminRow("bob")]),
      null,
    );
  });

  it("returns null when only owners are enrolled", () => {
    assert.equal(ownerlessWarning([ownerRow("alice")]), null);
  });

  it("returns a warning block when admins exist but no owner", () => {
    const w = ownerlessWarning([adminRow("alice"), memberRow("bob")]);
    assert.ok(w, "expected a warning string for ownerless server");
    assert.match(w, /^warning:/m);
    assert.match(w, /NO OWNER/);
    assert.match(w, /stamp users promote/);
    // Every line begins with `warning:` so a grep-based agent filter
    // catches the whole block.
    for (const line of w.trimEnd().split("\n")) {
      assert.match(line, /^warning:/, `line not warning-prefixed: ${JSON.stringify(line)}`);
    }
  });

  it("returns a warning when only members exist (still ownerless)", () => {
    // Edge: a server bootstrapped with member-only env-keys (impossible
    // today since seed-users imports as admin, but defensible as a
    // forward-compat property of the predicate).
    const w = ownerlessWarning([memberRow("alice")]);
    assert.ok(w);
    assert.match(w, /NO OWNER/);
  });

  it("includes the exact recovery command (so an agent can copy-paste it)", () => {
    const w = ownerlessWarning([adminRow("alice")]);
    assert.ok(w);
    // The exact form an agent would re-emit; pin it so a future
    // edit doesn't subtly change the placeholder syntax.
    assert.ok(
      w.includes("stamp users promote <your-short-name> --to owner"),
      `recovery command not present verbatim: ${JSON.stringify(w)}`,
    );
  });
});
