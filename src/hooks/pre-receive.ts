/**
 * stamp-verify pre-receive hook.
 *
 * Install as `hooks/pre-receive` (executable) in a bare git repo. For each
 * ref being pushed, the hook reads the target branch's current config +
 * trusted keys (from the pre-push tree, i.e. `old_sha:.stamp/...`), then
 * verifies every new commit introduced by the push.
 *
 * Rules:
 *   - Non-protected refs (no matching rule in .stamp/config.yml) pass through.
 *   - Creation of protected refs (old_sha=0000...) is rejected — operator
 *     must seed directly, see DESIGN.md "Bootstrap".
 *   - Force-pushes (new_sha not a descendant of old_sha) are rejected.
 *   - Every new commit on a protected branch must be a merge commit with
 *     valid Stamp-Payload + Stamp-Verified trailers, signed by a trusted
 *     key, with SHAs matching the commit's parents, and approvals meeting
 *     the branch's required list.
 *
 * Exits 0 on success, 1 on rejection. Rejection reasons go to stderr —
 * git forwards these to the pushing client.
 */

import { execFileSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import {
  MIN_ACCEPTED_PAYLOAD_VERSION,
  parseCommitAttestation,
  type AttestationPayload,
} from "../lib/attestation.js";
import { fingerprintFromPem } from "../lib/keys.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
  readReviewersFromYaml,
} from "../lib/reviewerHash.js";
import { verifyBytes } from "../lib/signing.js";

const ZERO_SHA = "0000000000000000000000000000000000000000";

interface CheckDef {
  name: string;
  run: string;
}

interface BranchRule {
  required: string[];
  required_checks?: CheckDef[];
}

interface StampConfigAtRef {
  branches: Record<string, BranchRule>;
}

function main(): void {
  const stdin = readAllStdin();
  const lines = stdin.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) process.exit(0);

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const [oldSha, newSha, refname] = parts as [string, string, string];
    verifyRef(oldSha, newSha, refname);
  }
}

function verifyRef(oldSha: string, newSha: string, refname: string): void {
  // Deletion: allow (branch protection at the git/forge level handles this
  // if the operator wants to prevent ref deletion).
  if (newSha === ZERO_SHA) return;

  // Only enforce on refs/heads/*.
  if (!refname.startsWith("refs/heads/")) return;
  const branch = refname.slice("refs/heads/".length);

  // For ref creation (old_sha is zeros), we need SOMETHING to read config
  // from. The "create" case is the bootstrap, and DESIGN.md is explicit:
  // operator seeds directly on the server, not via push. Reject.
  if (oldSha === ZERO_SHA) {
    reject(
      refname,
      `branch creation via push is not allowed. The operator must seed the repo directly on the server (see DESIGN.md "Bootstrap").`,
    );
  }

  // Load config + trusted keys from the pre-push state of this branch.
  const config = readConfigAt(oldSha);
  if (!config) {
    reject(
      refname,
      `no readable .stamp/config.yml at ${oldSha.slice(0, 8)}. Repo is not bootstrapped.`,
    );
  }

  const rule = config.branches[branch];
  if (!rule) {
    // Not a protected branch — pass.
    return;
  }

  // Force-push check: new_sha must be a descendant of old_sha.
  if (!isAncestor(oldSha, newSha)) {
    reject(
      refname,
      `push is not fast-forward (old ${oldSha.slice(0, 8)} is not an ancestor of new ${newSha.slice(0, 8)}). Force-push to a protected branch is not allowed.`,
    );
  }

  const trustedKeys = readTrustedKeysAt(oldSha);

  // Verify every new commit introduced by this push.
  const newCommits = listNewCommits(oldSha, newSha);
  for (const sha of newCommits) {
    verifyCommit(sha, branch, rule, trustedKeys, refname);
  }
}

function verifyCommit(
  sha: string,
  branch: string,
  rule: BranchRule,
  trustedKeys: Map<string, string>,
  refname: string,
): void {
  const commitMessage = run(["cat-file", "-p", sha]).split(/\n\n/s).slice(1).join("\n\n");
  // ^ commit message body is everything after the first blank-line separator
  //   in `git cat-file -p <commit>` output (headers then blank line then body)

  const parsed = parseCommitAttestation(commitMessage);
  if (!parsed) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)} has no Stamp-Payload / Stamp-Verified trailers. Every commit to '${branch}' must be a stamped merge.`,
    );
  }

  const { payload, payloadBytes, signatureBase64 } = parsed;

  // Fetch parents to cross-check SHAs.
  const parents = run(["rev-list", "--parents", "-n", "1", sha])
    .trim()
    .split(/\s+/)
    .slice(1);
  if (parents.length !== 2) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)} is not a merge commit (has ${parents.length} parent(s)). Every commit to '${branch}' must be a --no-ff merge.`,
    );
  }
  const [parent0, parent1] = parents as [string, string];

  if (parent1 !== payload.head_sha) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: second parent (${parent1.slice(0, 8)}) != payload.head_sha (${payload.head_sha.slice(0, 8)})`,
    );
  }

  const mergeBase = run(["merge-base", parent0, parent1]).trim();
  if (mergeBase !== payload.base_sha) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: merge-base(${parent0.slice(0, 8)}, ${parent1.slice(0, 8)}) = ${mergeBase.slice(0, 8)} != payload.base_sha (${payload.base_sha.slice(0, 8)})`,
    );
  }

  if (payload.target_branch !== branch) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: payload.target_branch ("${payload.target_branch}") does not match the branch being pushed ("${branch}")`,
    );
  }

  const trustedPem = trustedKeys.get(payload.signer_key_id);
  if (!trustedPem) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: signer key ${payload.signer_key_id} is not in .stamp/trusted-keys/`,
    );
  }

  let sigValid = false;
  try {
    sigValid = verifyBytes(trustedPem, payloadBytes, signatureBase64);
  } catch (err) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: signature verification threw — ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!sigValid) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: Ed25519 signature does not verify against the signer's trusted key`,
    );
  }

  const approvedReviewers = new Set(
    payload.approvals
      .filter((a) => a.verdict === "approved")
      .map((a) => a.reviewer),
  );
  const missing = rule.required.filter((r) => !approvedReviewers.has(r));
  if (missing.length > 0) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: missing required approvals — ${missing.join(", ")}`,
    );
  }

  // Verify attested checks cover every required_check in the committed
  // config, and that each recorded an exit code of 0.
  const requiredChecks = rule.required_checks ?? [];
  const attestedByName = new Map(
    ((payload as { checks?: { name: string; exit_code: number }[] }).checks ?? [])
      .map((c) => [c.name, c]),
  );
  const missingChecks: string[] = [];
  const failingChecks: string[] = [];
  for (const req of requiredChecks) {
    const attested = attestedByName.get(req.name);
    if (!attested) {
      missingChecks.push(req.name);
      continue;
    }
    if (attested.exit_code !== 0) {
      failingChecks.push(`${req.name} (exit ${attested.exit_code})`);
    }
  }
  if (missingChecks.length > 0) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: attestation is missing required check(s) — ${missingChecks.join(", ")}`,
    );
  }
  if (failingChecks.length > 0) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: attestation records failing check(s) — ${failingChecks.join(", ")}`,
    );
  }

  // v3+: verify per-reviewer prompt/tools/mcp hashes against the
  // merge-base tree (the common ancestor of the two parents). Reading from
  // the commit's own tree (v2) was broken — a feature branch could modify
  // a reviewer prompt and the resulting attestation would self-verify.
  // v3 sources hashes from the version of the reviewer that existed at
  // merge-base, which is invariant under the diff.
  //
  // v2 and below are rejected outright. They're cryptographically valid
  // but bound to the wrong tree (the post-merge tree, which the diff
  // could have modified). No upgrade path other than re-merging with a
  // current stamp-cli build that produces v3.
  const version = payload.schema_version ?? 1;
  if (version < MIN_ACCEPTED_PAYLOAD_VERSION) {
    reject(
      refname,
      `commit ${sha.slice(0, 8)}: attestation schema_version ${version} is no longer accepted ` +
        `(minimum supported is ${MIN_ACCEPTED_PAYLOAD_VERSION} — earlier versions are known-broken under ` +
        `the feature-branch self-review attack). Re-create the merge with a current stamp-cli build ` +
        `which produces v${MIN_ACCEPTED_PAYLOAD_VERSION} attestations bound to the merge-base tree.`,
    );
  }
  // The merge-base check earlier in verifyCommit already cross-checked
  // payload.base_sha against the actual merge-base of the two parents and
  // rejected on mismatch. So we can pass payload.base_sha directly here
  // instead of recomputing the merge-base; it's provably the same value.
  verifyReviewerHashesAtMergeBase(sha, payload.base_sha, payload, refname);
}

function verifyReviewerHashesAtMergeBase(
  sha: string,
  baseSha: string,
  payload: AttestationPayload,
  refname: string,
): void {
  const prefix = `commit ${sha.slice(0, 8)}: v3 attestation:`;

  // baseSha is the merge-base, already cross-checked against payload.base_sha
  // by the caller (verifyRef). The reviewer config + prompts at this tree
  // are the version that existed BEFORE the diff — invariant under
  // whatever the feature branch added — so a feature branch can't modify
  // a reviewer prompt and have the modified version verify here.

  let configYaml: string;
  try {
    configYaml = run(["show", `${baseSha}:.stamp/config.yml`]);
  } catch {
    reject(
      refname,
      `${prefix} .stamp/config.yml unreadable at merge-base ${baseSha.slice(0, 8)}`,
    );
  }
  const reviewers = readReviewersFromYaml(configYaml);

  for (const approval of payload.approvals) {
    const missing: string[] = [];
    if (!approval.prompt_sha256) missing.push("prompt_sha256");
    if (!approval.tools_sha256) missing.push("tools_sha256");
    if (!approval.mcp_sha256) missing.push("mcp_sha256");
    if (missing.length > 0) {
      reject(
        refname,
        `${prefix} approval for "${approval.reviewer}" is missing ${missing.join(", ")}`,
      );
    }
    const def = reviewers[approval.reviewer];
    if (!def) {
      reject(
        refname,
        `${prefix} reviewer "${approval.reviewer}" not defined in .stamp/config.yml at merge-base`,
      );
    }
    let promptBytes: string;
    try {
      promptBytes = run(["show", `${baseSha}:${def.prompt}`]);
    } catch {
      reject(
        refname,
        `${prefix} reviewer "${approval.reviewer}" prompt "${def.prompt}" unreadable at merge-base`,
      );
    }
    checkHashOrReject(prefix, refname, approval.reviewer, "prompt", hashPromptBytes(Buffer.from(promptBytes, "utf8")), approval.prompt_sha256!);
    checkHashOrReject(prefix, refname, approval.reviewer, "tools", hashTools(def.tools), approval.tools_sha256!);
    checkHashOrReject(prefix, refname, approval.reviewer, "mcp_servers", hashMcpServers(def.mcp_servers), approval.mcp_sha256!);
  }
}

function checkHashOrReject(
  prefix: string,
  refname: string,
  reviewer: string,
  field: string,
  computed: string,
  expected: string,
): void {
  if (computed === expected) return;
  reject(
    refname,
    `${prefix} reviewer "${reviewer}" ${field} hash mismatch ` +
      `(expected ${expected.slice(0, 16)}..., committed tree has ${computed.slice(0, 16)}...). ` +
      `The committed config differs from what the attestation claims; re-run stamp merge or revert the change.`,
  );
}

// ---------- git wrappers (hook runs in the bare repo's cwd) ----------

function run(args: string[]): string {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    throw new Error(
      `git ${args.join(" ")} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function readConfigAt(sha: string): StampConfigAtRef | null {
  try {
    const raw = run(["show", `${sha}:.stamp/config.yml`]);
    const parsed = parseYaml(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as Record<string, unknown>;
    const branches: Record<string, BranchRule> = {};
    if (obj.branches && typeof obj.branches === "object") {
      for (const [name, rule] of Object.entries(obj.branches)) {
        if (!rule || typeof rule !== "object") continue;
        const r = rule as Record<string, unknown>;
        if (!Array.isArray(r.required)) continue;

        const required_checks: CheckDef[] = [];
        if (Array.isArray(r.required_checks)) {
          for (const c of r.required_checks) {
            if (c && typeof c === "object") {
              const cc = c as Record<string, unknown>;
              if (typeof cc.name === "string" && typeof cc.run === "string") {
                required_checks.push({ name: cc.name, run: cc.run });
              }
            }
          }
        }

        branches[name] = {
          required: r.required.map(String),
          ...(required_checks.length > 0 ? { required_checks } : {}),
        };
      }
    }
    return { branches };
  } catch {
    return null;
  }
}

function readTrustedKeysAt(sha: string): Map<string, string> {
  // Returns a map of fingerprint → PEM for every .pub file under
  // .stamp/trusted-keys/ at the given ref.
  const map = new Map<string, string>();
  let lsOut: string;
  try {
    lsOut = run(["ls-tree", "-r", "--name-only", sha, ".stamp/trusted-keys/"]);
  } catch {
    return map;
  }
  const files = lsOut.split("\n").filter((f) => f.endsWith(".pub"));
  for (const path of files) {
    try {
      const pem = run(["show", `${sha}:${path}`]);
      const fp = fingerprintFromPem(pem);
      map.set(fp, pem);
    } catch {
      // skip unreadable/invalid
    }
  }
  return map;
}

function isAncestor(ancestor: string, descendant: string): boolean {
  try {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", ancestor, descendant],
      { stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}

function listNewCommits(oldSha: string, newSha: string): string[] {
  // --first-parent follows only the target branch's linear history, so we
  // check the stamped merge commits directly added to main — not every
  // commit they brought in from feature branches.
  const out = run([
    "rev-list",
    "--first-parent",
    `${oldSha}..${newSha}`,
  ]).trim();
  if (!out) return [];
  return out.split("\n");
}

function readAllStdin(): string {
  const chunks: Buffer[] = [];
  const fd = 0;
  const { readFileSync } = require("node:fs") as typeof import("node:fs");
  try {
    chunks.push(readFileSync(fd));
  } catch {
    // empty
  }
  return Buffer.concat(chunks).toString("utf8");
}

// ---------- error output ----------

function reject(refname: string, reason: string): never {
  process.stderr.write(`stamp-verify: rejecting ${refname}\n`);
  process.stderr.write(`  ${reason}\n`);
  process.exit(1);
}

try {
  main();
  process.exit(0);
} catch (err) {
  process.stderr.write(
    `stamp-verify: internal error — ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
}
