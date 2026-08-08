/**
 * Tests for AGENTS.md matching the signing model actually scaffolded
 * (issue #55).
 *
 * `stamp init --mode attested-pr` deposits a LOCAL signing key and local
 * reviewer prompts, and writes no `review_server` / `manifest.yml` /
 * server pubkey. It nevertheless emitted the server-attested (Shape 4)
 * body, which pointed contributors at `review-server-prod.pub` and
 * `manifest.yml` that were never created and told them "no client-side
 * signing key is needed" when the local key is the entire trust root.
 *
 * The load-bearing assertion is AC 2: every file path the emitted doc
 * names must exist in the scaffold that produced it. That is checked
 * mechanically against a real on-disk scaffold rather than by eyeballing
 * the prose, so a future edit that reintroduces a dangling reference
 * fails here.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import {
  detectAttestedPrSigning,
  ensureAgentsMd,
  injectStampSection,
  sniffAgentsMdMode,
  SNIFF_PHRASE_ATTESTED_PR,
  STAMP_AGENTS_SECTION_ATTESTED_PR,
  STAMP_AGENTS_SECTION_ATTESTED_PR_LOCAL_SIGNING,
} from "../src/lib/agentsMd.ts";

const dirs: string[] = [];

after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), "stamp-agentsmd-"));
  dirs.push(d);
  return d;
}

/**
 * Build the artifact set `stamp init --mode attested-pr` actually writes,
 * as verified against a real run: local prompts, a local signing key, the
 * verify workflow, and a config with NO review_server.
 */
function localSigningScaffold(): string {
  const root = scratch();
  mkdirSync(join(root, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(join(root, ".stamp", "trusted-keys"), { recursive: true });
  mkdirSync(join(root, ".github", "workflows"), { recursive: true });
  for (const r of ["security", "standards", "product"]) {
    writeFileSync(join(root, ".stamp", "reviewers", `${r}.md`), `# ${r}\n`);
  }
  writeFileSync(
    join(root, ".stamp", "trusted-keys", `sha256_${"a".repeat(64)}.pub`),
    "ssh-ed25519 AAAA local@host\n",
  );
  writeFileSync(
    join(root, ".stamp", "config.yml"),
    `branches:
  main:
    required:
      - security
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`,
  );
  writeFileSync(join(root, ".github", "workflows", "stamp-verify.yml"), "name: stamp verify\n");
  return root;
}

/** The `--migrate-to-server-attested` artifact set. */
function serverAttestedScaffold(): string {
  const root = localSigningScaffold();
  writeFileSync(
    join(root, ".stamp", "trusted-keys", "manifest.yml"),
    `keys:\n  - name: review-server-prod\n    capabilities: [server]\n`,
  );
  writeFileSync(
    join(root, ".stamp", "trusted-keys", "review-server-prod.pub"),
    "ssh-ed25519 AAAA server@stamp\n",
  );
  writeFileSync(
    join(root, ".stamp", "config.yml"),
    `branches:
  main:
    required:
      - security
    review_server: ssh://git@stamp.example.test:2222
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`,
  );
  return root;
}

/**
 * Pull every repo-relative file path the doc names. Matches backtick-quoted
 * tokens that look like paths under the scaffold's directories, ignoring
 * glob/placeholder forms (`*.pub`, `<name>.md`, `{,.pub}` brace expansion)
 * which stand for a family rather than one file.
 */
function namedRepoPaths(doc: string): string[] {
  const found = new Set<string>();
  const re = /`([^`\s]+)`/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(doc)) !== null) {
    const tok = m[1]!;
    if (!/^\.(stamp|github)\//.test(tok)) continue;
    if (/[*<>{}]/.test(tok)) continue;
    found.add(tok);
  }
  return [...found];
}

describe("detectAttestedPrSigning", () => {
  it("reports local-signing for the plain --mode attested-pr scaffold", () => {
    assert.equal(detectAttestedPrSigning(localSigningScaffold()), "local-signing");
  });

  it("reports server-attested only when all three artifacts are present", () => {
    assert.equal(detectAttestedPrSigning(serverAttestedScaffold()), "server-attested");
  });

  it("does not claim server-attested when the manifest is missing", () => {
    const root = serverAttestedScaffold();
    rmSync(join(root, ".stamp", "trusted-keys", "manifest.yml"));
    assert.equal(detectAttestedPrSigning(root), "local-signing");
  });

  it("does not claim server-attested when the server pubkey is missing", () => {
    const root = serverAttestedScaffold();
    rmSync(join(root, ".stamp", "trusted-keys", "review-server-prod.pub"));
    assert.equal(detectAttestedPrSigning(root), "local-signing");
  });

  it("does not claim server-attested when config declares no review_server", () => {
    const root = serverAttestedScaffold();
    writeFileSync(
      join(root, ".stamp", "config.yml"),
      "branches:\n  main:\n    required: [security]\n",
    );
    assert.equal(detectAttestedPrSigning(root), "local-signing");
  });

  it("treats a commented-out review_server as not wired up", () => {
    const root = serverAttestedScaffold();
    writeFileSync(
      join(root, ".stamp", "config.yml"),
      "branches:\n  main:\n    # review_server: ssh://git@old:22\n    required: [security]\n",
    );
    assert.equal(detectAttestedPrSigning(root), "local-signing");
  });

  it("is local-signing on a repo with no .stamp at all", () => {
    assert.equal(detectAttestedPrSigning(scratch()), "local-signing");
  });
});

describe("ensureAgentsMd picks the body matching the scaffold", () => {
  it("emits the local-signing narrative over a local-signing scaffold", () => {
    const root = localSigningScaffold();
    ensureAgentsMd(root, "attested-pr");
    const doc = readDoc(root);

    assert.match(doc, /attested-pr mode with local-key signing/);
    // The specific false claims from issue #55 must be gone.
    assert.doesNotMatch(doc, /No client-side signing key is needed/);
    assert.doesNotMatch(doc, /review-server-prod\.pub/);
    assert.doesNotMatch(doc, /manifest\.yml/);
    // And the real trust root must be named.
    assert.match(doc, /\.stamp\/trusted-keys\//);
    assert.match(doc, /stamp attest/);
  });

  it("emits the server-attested narrative over a server scaffold", () => {
    const root = serverAttestedScaffold();
    ensureAgentsMd(root, "attested-pr");
    const doc = readDoc(root);

    assert.match(doc, /review-server-prod\.pub/);
    assert.match(doc, /manifest\.yml/);
    assert.match(doc, /holds the review-signing key/);
    assert.doesNotMatch(doc, /attested-pr mode with local-key signing/);
  });

  it("re-emits the corrected body over a stale server-attested block", () => {
    // The upgrade path for a repo already carrying the wrong doc: a
    // re-run must replace the section, not append a second one.
    const root = localSigningScaffold();
    writeFileSync(
      join(root, "AGENTS.md"),
      injectStampSection(undefined, "attested-pr", "server-attested"),
    );
    const action = ensureAgentsMd(root, "attested-pr");
    const doc = readDoc(root);

    assert.equal(action, "replaced");
    assert.doesNotMatch(doc, /review-server-prod\.pub/);
    assert.match(doc, /attested-pr mode with local-key signing/);
    assert.equal(doc.split("<!-- stamp:begin").length - 1, 1);
  });

  it("leaves the other modes untouched", () => {
    const root = localSigningScaffold();
    ensureAgentsMd(root, "local-only");
    assert.doesNotMatch(readDoc(root), /attested-pr mode/);
  });
});

describe("AC2: every file path the doc names exists in the scaffold", () => {
  it("holds for the local-signing scaffold", () => {
    const root = localSigningScaffold();
    ensureAgentsMd(root, "attested-pr");
    const missing = namedRepoPaths(readDoc(root)).filter(
      (p) => !existsSync(join(root, p)),
    );
    assert.deepEqual(missing, [], `AGENTS.md names paths that do not exist: ${missing}`);
  });

  it("holds for the server-attested scaffold", () => {
    const root = serverAttestedScaffold();
    ensureAgentsMd(root, "attested-pr");
    const missing = namedRepoPaths(readDoc(root)).filter(
      (p) => !existsSync(join(root, p)),
    );
    assert.deepEqual(missing, [], `AGENTS.md names paths that do not exist: ${missing}`);
  });

  it("the extractor actually finds paths (guards a vacuous pass)", () => {
    const root = localSigningScaffold();
    ensureAgentsMd(root, "attested-pr");
    const paths = namedRepoPaths(readDoc(root));
    assert.ok(paths.length >= 3, `expected several paths, got ${paths.length}`);
    assert.ok(paths.includes(".stamp/config.yml"));
    assert.ok(paths.includes(".github/workflows/stamp-verify.yml"));
  });

  it("would catch a dangling reference (negative control)", () => {
    // Prove the check has teeth: the server body over a local scaffold is
    // precisely the bug, and it must be detected.
    const root = localSigningScaffold();
    writeFileSync(
      join(root, "AGENTS.md"),
      injectStampSection(undefined, "attested-pr", "server-attested"),
    );
    const missing = namedRepoPaths(readDoc(root)).filter(
      (p) => !existsSync(join(root, p)),
    );
    assert.ok(
      missing.includes(".stamp/trusted-keys/review-server-prod.pub"),
      `expected the dangling server-key reference to be caught, got ${missing}`,
    );
  });
});

describe("drift-checker invariants still hold for both bodies", () => {
  it("both attested-pr bodies carry the sniffable phrase", () => {
    assert.ok(STAMP_AGENTS_SECTION_ATTESTED_PR.includes(SNIFF_PHRASE_ATTESTED_PR));
    assert.ok(
      STAMP_AGENTS_SECTION_ATTESTED_PR_LOCAL_SIGNING.includes(
        SNIFF_PHRASE_ATTESTED_PR,
      ),
    );
  });

  it("the local-signing body still sniffs as attested-pr mode", () => {
    const root = localSigningScaffold();
    ensureAgentsMd(root, "attested-pr");
    assert.equal(sniffAgentsMdMode(root), "attested-pr");
  });
});

function readDoc(root: string): string {
  return readFileSync(join(root, "AGENTS.md"), "utf8");
}
