/**
 * AGT-469: Shell-level tests for server/lib/inject-sshd-setenv.sh.
 *
 * Exercises the sourceable `_inject_sshd_setenv` function via
 * node:child_process so the STAMP_SSH_PASS_ENV injection logic can be
 * asserted without booting the whole container.
 *
 * The lib respects $SSHD_CONFIG (default: /etc/ssh/sshd_config); tests
 * point it at a tmpfile they own so no root access is needed.
 *
 * Test matrix:
 *   1. Happy path — STAMP_PUBLIC_URL injected as SetEnv line
 *   2. Idempotent — re-running replaces the old line, not accumulates
 *   3. Var unset / empty — skipped silently (exit 0, no SetEnv line added)
 *   4. Illegal charset — exit 1, clear error, file unchanged
 *   5. STAMP_PUBLIC_URL without http(s):// prefix — exit 1, clear error
 *   6. Custom var via STAMP_SSH_PASS_ENV whitelist — injected without
 *      URL prefix check
 *   7. STAMP_SSH_PASS_ENV with multiple vars — all injected
 *   8. Existing unrelated sshd_config lines are preserved
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

const INJECT_SCRIPT = path.resolve(
  import.meta.dirname,
  "..",
  "server",
  "lib",
  "inject-sshd-setenv.sh",
);

interface Harness {
  dir: string;
  sshdConfig: string;
  cleanup: () => void;
}

function setupHarness(initialContent = "# placeholder\n"): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-inject-sshd-"));
  const sshdConfig = path.join(dir, "sshd_config");
  writeFileSync(sshdConfig, initialContent, { mode: 0o644 });
  return {
    dir,
    sshdConfig,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Source inject-sshd-setenv.sh and call `_inject_sshd_setenv <name>` in a
 * subshell with the supplied environment.
 */
function runInject(
  sshdConfig: string,
  varName: string,
  env: Record<string, string | undefined>,
): { status: number | null; stderr: string } {
  // Pass varName as $1 to the snippet (not interpolated into the shell
  // string) so values containing shell metacharacters like `$` or `;`
  // reach _inject_sshd_setenv literally — exercising its defensive
  // name validation rather than getting eaten by string interpolation.
  const snippet = `. "${INJECT_SCRIPT}" && _inject_sshd_setenv "$1"`;
  const result = spawnSync("sh", ["-c", snippet, "sh", varName], {
    env: {
      PATH: process.env["PATH"],
      SSHD_CONFIG: sshdConfig,
      ...env,
    },
    encoding: "utf8",
  });
  return {
    status: result.status,
    stderr: result.stderr ?? "",
  };
}

describe("AGT-469: inject-sshd-setenv.sh", () => {
  it("case 1: injects STAMP_PUBLIC_URL as a SetEnv line", () => {
    const h = setupHarness();
    try {
      const r = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "https://stamp.example.com",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.match(content, /^SetEnv STAMP_PUBLIC_URL=https:\/\/stamp\.example\.com$/m);
    } finally {
      h.cleanup();
    }
  });

  it("case 2: idempotent — re-running replaces the old SetEnv line, not accumulates", () => {
    const h = setupHarness("# hardening\n");
    try {
      runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "https://old.example.com",
      });
      const r = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "https://new.example.com",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      const content = readFileSync(h.sshdConfig, "utf8");
      const matches = content.match(/^SetEnv STAMP_PUBLIC_URL=/gm);
      assert.equal(matches?.length, 1, "should be exactly one SetEnv STAMP_PUBLIC_URL line");
      assert.match(content, /^SetEnv STAMP_PUBLIC_URL=https:\/\/new\.example\.com$/m);
      assert.doesNotMatch(content, /old\.example\.com/);
    } finally {
      h.cleanup();
    }
  });

  it("case 3: var unset — exit 0, no SetEnv line written", () => {
    const h = setupHarness("# placeholder\n");
    try {
      const r = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        // STAMP_PUBLIC_URL deliberately absent
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.doesNotMatch(content, /SetEnv STAMP_PUBLIC_URL/);
    } finally {
      h.cleanup();
    }
  });

  it("case 4: illegal charset — exit 1, clear error, file unchanged", () => {
    const initial = "# hardening\n";
    const h = setupHarness(initial);
    try {
      const r = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "https://stamp.example.com\nPermitRootLogin yes",
      });
      assert.equal(r.status, 1, `expected exit 1, got ${r.status}`);
      assert.match(r.stderr, /illegal characters/);
      assert.match(r.stderr, /STAMP_PUBLIC_URL/);
      // File must be unchanged — no injection occurred.
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.doesNotMatch(content, /SetEnv/);
      assert.doesNotMatch(content, /PermitRootLogin/);
    } finally {
      h.cleanup();
    }
  });

  it("case 5: STAMP_PUBLIC_URL without http(s):// prefix — exit 1, semantic error", () => {
    const h = setupHarness();
    try {
      const r = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "ftp://stamp.example.com",
      });
      assert.equal(r.status, 1, `expected exit 1, got ${r.status}`);
      assert.match(r.stderr, /must start with http/);
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.doesNotMatch(content, /SetEnv STAMP_PUBLIC_URL/);
    } finally {
      h.cleanup();
    }
  });

  it("case 6: custom var injected without URL prefix check", () => {
    const h = setupHarness("# hardening\n");
    try {
      const r = runInject(h.sshdConfig, "MY_CUSTOM_TOKEN", {
        MY_CUSTOM_TOKEN: "tok-abc123",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.match(content, /^SetEnv MY_CUSTOM_TOKEN=tok-abc123$/m);
    } finally {
      h.cleanup();
    }
  });

  it("case 7: multiple vars injected in sequence (simulating the entrypoint loop)", () => {
    const h = setupHarness("# hardening\n");
    try {
      const r1 = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "https://stamp.example.com",
      });
      const r2 = runInject(h.sshdConfig, "MY_EXTRA_VAR", {
        MY_EXTRA_VAR: "some-value",
      });
      assert.equal(r1.status, 0, `r1 stderr=${r1.stderr}`);
      assert.equal(r2.status, 0, `r2 stderr=${r2.stderr}`);
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.match(content, /^SetEnv STAMP_PUBLIC_URL=https:\/\/stamp\.example\.com$/m);
      assert.match(content, /^SetEnv MY_EXTRA_VAR=some-value$/m);
    } finally {
      h.cleanup();
    }
  });

  it("case 8a: rejects an invalid env var name (defensive guard against shell metachars)", () => {
    // Names with shell metacharacters or non-conforming shapes must be
    // rejected before any value lookup — closes a latent attack surface
    // even though printenv (not eval) does the actual value read.
    const h = setupHarness();
    try {
      for (const badName of ["bad name", "bad;name", "1abc", "bad$name", ""]) {
        const r = runInject(h.sshdConfig, badName, {});
        assert.equal(r.status, 1, `expected exit 1 for name="${badName}", got ${r.status}`);
        assert.match(r.stderr, /invalid env var name/);
      }
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.doesNotMatch(content, /SetEnv/);
    } finally {
      h.cleanup();
    }
  });

  it("case 9: existing unrelated sshd_config lines are preserved", () => {
    const hardening =
      "PasswordAuthentication no\nPermitRootLogin no\nAllowUsers git\n";
    const h = setupHarness(hardening);
    try {
      const r = runInject(h.sshdConfig, "STAMP_PUBLIC_URL", {
        STAMP_PUBLIC_URL: "https://stamp.example.com",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      const content = readFileSync(h.sshdConfig, "utf8");
      assert.match(content, /PasswordAuthentication no/);
      assert.match(content, /PermitRootLogin no/);
      assert.match(content, /AllowUsers git/);
      assert.match(content, /SetEnv STAMP_PUBLIC_URL=/);
    } finally {
      h.cleanup();
    }
  });
});
