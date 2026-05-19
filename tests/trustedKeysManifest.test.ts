/**
 * Tests for the trusted-keys manifest parser, canonical serializer,
 * snapshot hasher, and capability resolver. Coverage walks the parse
 * failure modes documented on `parseManifest`, the determinism contract
 * documented on `serializeManifestCanonical`, the snapshot-hash
 * stability contract on `snapshotSha256`, and the lookup semantics on
 * `resolveCapability`. The AC's 4-key worked example gets its own block
 * to confirm the parsed shape and that the snapshot hash is stable.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  MANIFEST_RELATIVE_PATH,
  MAX_MANIFEST_BYTES,
  parseManifest,
  resolveCapability,
  serializeManifestCanonical,
  serializeManifestYaml,
  snapshotSha256,
  type Capability,
  type TrustedKeysManifest,
} from "../src/lib/trustedKeysManifest.ts";

const FP_ALICE = "sha256:" + "a".repeat(64);
const FP_BOB = "sha256:" + "b".repeat(64);
const FP_AGENT = "sha256:" + "c".repeat(64);
const FP_SERVER = "sha256:" + "d".repeat(64);

const WORKED_EXAMPLE_YAML = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
  bob:
    fingerprint: ${FP_BOB}
    capabilities: [admin]
  agent-bot:
    fingerprint: ${FP_AGENT}
    capabilities: [operator]
  review-server-prod:
    fingerprint: ${FP_SERVER}
    capabilities: [server]
    role_source: server
`;

describe("MANIFEST_RELATIVE_PATH", () => {
  it("is the documented location under .stamp/trusted-keys/", () => {
    assert.equal(MANIFEST_RELATIVE_PATH, ".stamp/trusted-keys/manifest.yml");
  });
});

describe("parseManifest — happy paths", () => {
  it("parses a manifest with all three capability types", () => {
    const yaml = `
keys:
  human-1:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
  ci-bot:
    fingerprint: ${FP_AGENT}
    capabilities: [operator]
  review-server:
    fingerprint: ${FP_SERVER}
    capabilities: [server]
`;
    const m = parseManifest(yaml);
    assert.ok(m, "manifest should parse");
    assert.equal(m!.entries.length, 3);

    const byName = Object.fromEntries(m!.entries.map((e) => [e.name, e]));
    assert.deepEqual(byName["human-1"]!.capabilities, ["admin"]);
    assert.deepEqual(byName["ci-bot"]!.capabilities, ["operator"]);
    assert.deepEqual(byName["review-server"]!.capabilities, ["server"]);
  });

  it("accepts additive capability sets (admin + operator on one key)", () => {
    const yaml = `
keys:
  power-user:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, operator]
`;
    const m = parseManifest(yaml);
    assert.ok(m);
    assert.deepEqual(m!.entries[0]!.capabilities, ["admin", "operator"]);
  });

  it("deduplicates capabilities within a single entry", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, admin, operator]
`;
    const m = parseManifest(yaml);
    assert.ok(m);
    assert.deepEqual(m!.entries[0]!.capabilities, ["admin", "operator"]);
  });

  it("preserves role_source: server when present", () => {
    const yaml = `
keys:
  srv:
    fingerprint: ${FP_SERVER}
    capabilities: [server]
    role_source: server
`;
    const m = parseManifest(yaml);
    assert.ok(m);
    assert.equal(m!.entries[0]!.role_source, "server");
  });

  it("omits role_source when not specified", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`;
    const m = parseManifest(yaml);
    assert.ok(m);
    assert.equal(m!.entries[0]!.role_source, undefined);
  });

  it("sorts entries by name for stable traversal", () => {
    const yaml = `
keys:
  zelda:
    fingerprint: ${FP_BOB}
    capabilities: [admin]
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`;
    const m = parseManifest(yaml);
    assert.ok(m);
    assert.deepEqual(
      m!.entries.map((e) => e.name),
      ["alice", "zelda"],
    );
  });
});

describe("parseManifest — rejection cases", () => {
  it("rejects non-string input", () => {
    // @ts-expect-error — intentional bad input
    assert.equal(parseManifest(null), null);
    // @ts-expect-error — intentional bad input
    assert.equal(parseManifest(undefined), null);
    // @ts-expect-error — intentional bad input
    assert.equal(parseManifest(42), null);
  });

  it("rejects oversized input", () => {
    const oversized = "x".repeat(MAX_MANIFEST_BYTES + 1);
    assert.equal(parseManifest(oversized), null);
  });

  it("rejects malformed YAML", () => {
    assert.equal(parseManifest("keys: [unterminated"), null);
  });

  it("rejects missing top-level keys object", () => {
    assert.equal(parseManifest("other: 1\n"), null);
  });

  it("rejects empty manifest (no entries)", () => {
    assert.equal(parseManifest("keys: {}\n"), null);
  });

  it("rejects entry missing fingerprint", () => {
    const yaml = `
keys:
  alice:
    capabilities: [admin]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects entry missing capabilities", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects empty capabilities list", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: []
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects unknown capability strings", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, superuser]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects non-string capability entries", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, 42]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects malformed fingerprint (wrong prefix)", () => {
    const yaml = `
keys:
  alice:
    fingerprint: md5:${"a".repeat(64)}
    capabilities: [admin]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects malformed fingerprint (wrong length)", () => {
    const yaml = `
keys:
  alice:
    fingerprint: sha256:deadbeef
    capabilities: [admin]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects malformed fingerprint (non-hex)", () => {
    const yaml = `
keys:
  alice:
    fingerprint: sha256:${"Z".repeat(64)}
    capabilities: [admin]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects duplicate fingerprints across two named entries", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
  alice-backup:
    fingerprint: ${FP_ALICE}
    capabilities: [operator]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects empty-string role_source", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
    role_source: ""
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects non-string role_source", () => {
    const yaml = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
    role_source: 1
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects malformed entry names", () => {
    const yaml = `
keys:
  "alice has spaces":
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`;
    assert.equal(parseManifest(yaml), null);
  });

  it("rejects keys as a list rather than a map", () => {
    const yaml = `
keys:
  - name: alice
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`;
    assert.equal(parseManifest(yaml), null);
  });
});

describe("serializeManifestCanonical — determinism", () => {
  it("produces identical bytes for two equivalent inputs (key order differs)", () => {
    const yamlA = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, operator]
  bob:
    fingerprint: ${FP_BOB}
    capabilities: [admin]
`;
    const yamlB = `
keys:
  bob:
    fingerprint: ${FP_BOB}
    capabilities: [admin]
  alice:
    capabilities: [operator, admin]
    fingerprint: ${FP_ALICE}
`;
    const a = parseManifest(yamlA);
    const b = parseManifest(yamlB);
    assert.ok(a && b);
    assert.equal(
      serializeManifestCanonical(a!).toString("utf8"),
      serializeManifestCanonical(b!).toString("utf8"),
    );
  });

  it("re-sorts entries even if a manually-constructed manifest isn't sorted", () => {
    const m: TrustedKeysManifest = {
      entries: [
        {
          name: "zelda",
          fingerprint: FP_BOB,
          capabilities: ["admin"],
        },
        {
          name: "alice",
          fingerprint: FP_ALICE,
          capabilities: ["admin"],
        },
      ],
    };
    const json = JSON.parse(serializeManifestCanonical(m).toString("utf8"));
    assert.deepEqual(Object.keys(json.keys), ["alice", "zelda"]);
  });

  it("sorts capabilities within each entry", () => {
    // Constructing manually with unsorted capabilities (parseManifest
    // would have sorted them) to confirm the serializer does its own
    // sort defensively.
    const m: TrustedKeysManifest = {
      entries: [
        {
          name: "alice",
          fingerprint: FP_ALICE,
          capabilities: ["operator", "admin"] as Capability[],
        },
      ],
    };
    const json = JSON.parse(serializeManifestCanonical(m).toString("utf8"));
    assert.deepEqual(json.keys.alice.capabilities, ["admin", "operator"]);
  });
});

describe("snapshotSha256", () => {
  it("returns the sha256:<hex> form matching the fingerprint convention", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML)!;
    const hash = snapshotSha256(m);
    assert.match(hash, /^sha256:[0-9a-f]{64}$/);
  });

  it("is stable across equivalent inputs (reorder + dedup)", () => {
    const yamlA = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
  bob:
    fingerprint: ${FP_BOB}
    capabilities: [operator]
`;
    const yamlB = `
keys:
  bob:
    capabilities: [operator, operator]
    fingerprint: ${FP_BOB}
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`;
    const a = parseManifest(yamlA)!;
    const b = parseManifest(yamlB)!;
    assert.equal(snapshotSha256(a), snapshotSha256(b));
  });

  it("changes when an entry is added", () => {
    const before = parseManifest(`
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`)!;
    const after = parseManifest(`
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
  bob:
    fingerprint: ${FP_BOB}
    capabilities: [operator]
`)!;
    assert.notEqual(snapshotSha256(before), snapshotSha256(after));
  });

  it("changes when a capability is added to an existing entry", () => {
    const before = parseManifest(`
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`)!;
    const after = parseManifest(`
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, operator]
`)!;
    assert.notEqual(snapshotSha256(before), snapshotSha256(after));
  });

  it("changes when role_source is added", () => {
    const before = parseManifest(`
keys:
  srv:
    fingerprint: ${FP_SERVER}
    capabilities: [server]
`)!;
    const after = parseManifest(`
keys:
  srv:
    fingerprint: ${FP_SERVER}
    capabilities: [server]
    role_source: server
`)!;
    assert.notEqual(snapshotSha256(before), snapshotSha256(after));
  });
});

describe("resolveCapability", () => {
  it("returns the capability list for a known fingerprint", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML)!;
    assert.deepEqual(resolveCapability(m, FP_ALICE), ["admin"]);
    assert.deepEqual(resolveCapability(m, FP_AGENT), ["operator"]);
    assert.deepEqual(resolveCapability(m, FP_SERVER), ["server"]);
  });

  it("returns null for an unknown fingerprint", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML)!;
    const unknownFp = "sha256:" + "e".repeat(64);
    assert.equal(resolveCapability(m, unknownFp), null);
  });

  it("returns a copy (mutation doesn't affect the manifest)", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML)!;
    const caps = resolveCapability(m, FP_ALICE)!;
    caps.push("server");
    const fresh = resolveCapability(m, FP_ALICE)!;
    assert.deepEqual(fresh, ["admin"]);
  });
});

describe("serializeManifestYaml — writer round-trip", () => {
  it("round-trips through parse → serialize → parse (worked example)", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML)!;
    const yaml = serializeManifestYaml(m);
    const reparsed = parseManifest(yaml);
    assert.ok(reparsed, "serialized YAML must re-parse");
    assert.deepEqual(reparsed, m);
  });

  it("snapshot hash is preserved by parse → serialize → parse", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML)!;
    const reparsed = parseManifest(serializeManifestYaml(m))!;
    assert.equal(snapshotSha256(reparsed), snapshotSha256(m));
  });

  it("emits entries sorted by name regardless of source order", () => {
    const yaml = serializeManifestYaml(
      parseManifest(`
keys:
  zelda:
    fingerprint: ${FP_BOB}
    capabilities: [admin]
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`)!,
    );
    const aliceIdx = yaml.indexOf("  alice:");
    const zeldaIdx = yaml.indexOf("  zelda:");
    assert.ok(aliceIdx >= 0 && zeldaIdx >= 0);
    assert.ok(aliceIdx < zeldaIdx, "alice should come before zelda");
  });

  it("emits capabilities sorted within each entry", () => {
    const m: TrustedKeysManifest = {
      entries: [
        {
          name: "alice",
          fingerprint: FP_ALICE,
          capabilities: ["operator", "admin"] as Capability[],
        },
      ],
    };
    const yaml = serializeManifestYaml(m);
    assert.ok(yaml.includes("capabilities: [admin, operator]"));
  });

  it("produces byte-identical output for two equivalent inputs", () => {
    const yamlA = `
keys:
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin, operator]
  bob:
    fingerprint: ${FP_BOB}
    capabilities: [admin]
`;
    const yamlB = `
keys:
  bob:
    capabilities: [admin]
    fingerprint: ${FP_BOB}
  alice:
    capabilities: [operator, admin]
    fingerprint: ${FP_ALICE}
`;
    const a = serializeManifestYaml(parseManifest(yamlA)!);
    const b = serializeManifestYaml(parseManifest(yamlB)!);
    assert.equal(a, b);
  });

  it("preserves role_source: server when present", () => {
    const yaml = serializeManifestYaml(parseManifest(WORKED_EXAMPLE_YAML)!);
    assert.ok(yaml.includes("role_source: server"));
    // And re-parse must surface it on the right entry.
    const m = parseManifest(yaml)!;
    const srv = m.entries.find((e) => e.name === "review-server-prod")!;
    assert.equal(srv.role_source, "server");
  });

  it("output ends with exactly one trailing newline", () => {
    const yaml = serializeManifestYaml(parseManifest(WORKED_EXAMPLE_YAML)!);
    assert.ok(yaml.endsWith("\n"));
    assert.ok(!yaml.endsWith("\n\n"));
  });

  it("round-trips a single-entry manifest (boundary case)", () => {
    const m = parseManifest(`
keys:
  solo-admin:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]
`)!;
    const reparsed = parseManifest(serializeManifestYaml(m))!;
    assert.deepEqual(reparsed, m);
  });
});

describe("worked example from AC (2 humans admin + 1 CI operator + 1 server)", () => {
  it("parses cleanly with the expected 4-entry shape", () => {
    const m = parseManifest(WORKED_EXAMPLE_YAML);
    assert.ok(m, "worked example should parse");
    assert.equal(m!.entries.length, 4);

    const byName = Object.fromEntries(m!.entries.map((e) => [e.name, e]));
    assert.deepEqual(byName["alice"]!.capabilities, ["admin"]);
    assert.deepEqual(byName["bob"]!.capabilities, ["admin"]);
    assert.deepEqual(byName["agent-bot"]!.capabilities, ["operator"]);
    assert.deepEqual(byName["review-server-prod"]!.capabilities, ["server"]);
    assert.equal(byName["review-server-prod"]!.role_source, "server");
    assert.equal(byName["alice"]!.role_source, undefined);
  });

  it("produces a deterministic snapshot hash", () => {
    const m1 = parseManifest(WORKED_EXAMPLE_YAML)!;
    const m2 = parseManifest(WORKED_EXAMPLE_YAML)!;
    assert.equal(snapshotSha256(m1), snapshotSha256(m2));
  });

  it("snapshot survives a benign reformat (comments + reordering)", () => {
    const reformatted = `
# trust-anchor manifest, hand-edited; server entries flagged with role_source.
keys:
  # CI bot — operator only
  agent-bot:
    capabilities: [operator]
    fingerprint: ${FP_AGENT}

  # human admins
  bob:
    capabilities: [admin]
    fingerprint: ${FP_BOB}
  alice:
    fingerprint: ${FP_ALICE}
    capabilities: [admin]

  # server (auto-published)
  review-server-prod:
    role_source: server
    capabilities: [server]
    fingerprint: ${FP_SERVER}
`;
    const original = parseManifest(WORKED_EXAMPLE_YAML)!;
    const after = parseManifest(reformatted)!;
    assert.equal(snapshotSha256(original), snapshotSha256(after));
  });
});
