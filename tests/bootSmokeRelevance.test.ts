/**
 * AGT-2270: the boot-smoke merge check must not skip changes that alter
 * the image build or boot (files COPYed into the image, the hook bundles,
 * npm config).
 */
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";

const script = readFileSync(path.join(import.meta.dirname, "..", "scripts", "docker-boot-smoke.sh"), "utf8");
const m = /^BOOT_RELEVANT_RE='([^']+)'/m.exec(script);
assert.ok(m, "BOOT_RELEVANT_RE not found");
const re = new RegExp(m[1]!);

describe("docker-boot-smoke BOOT_RELEVANT_RE (AGT-2270)", () => {
  it("covers every repo path the Dockerfile COPYs from outside server/ and src/", () => {
    const dockerfile = readFileSync(path.join(import.meta.dirname, "..", "server", "Dockerfile"), "utf8");
    const copies = [...dockerfile.matchAll(/^COPY (?!--from)(.+) \S+$/gm)].flatMap((x) => x[1]!.split(/\s+/));
    assert.ok(copies.length > 0);
    for (const src of copies) {
      const p = src.replace(/^\.\//, "");
      if (p === "src" || p.startsWith("src/")) continue; // builder: covered by build/typecheck + CI backstop
      assert.match(p, re, `${p} is COPYed into the image but not boot-relevant`);
    }
  });
  it("includes the hook bundles and npm config, skips docs and client lib", () => {
    for (const p of ["src/hooks/pre-receive.ts", "scripts/setup-repo.sh", ".npmrc", "server/entrypoint.sh"]) {
      assert.match(p, re, p);
    }
    for (const p of ["README.md", "docs/troubleshooting.md", "src/lib/config.ts", "src/commands/review.ts"]) {
      assert.doesNotMatch(p, re, p);
    }
  });
});
