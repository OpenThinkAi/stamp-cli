import { Box, render, Text, useApp, useInput } from "ink";
import { useState } from "react";
import {
  parseCommitAttestation,
  type AttestationPayload,
  type ParsedAttestation,
} from "../lib/attestation.js";
import {
  commitMessage,
  currentBranch,
  firstParentCommits,
} from "../lib/git.js";
import { findTrustedKey } from "../lib/keys.js";
import { findRepoRoot } from "../lib/paths.js";
import { verifyBytes } from "../lib/signing.js";

/**
 * Phase 2.B/TUI step 3 — commit list + detail view.
 *
 * List: first-parent commits with a one-line attestation summary.
 *   ↑/↓ or j/k — navigate
 *   enter      — open detail view for the selected commit
 *   q/esc      — quit (Ctrl-C via ink default)
 *
 * Detail: full attestation inspection for one commit.
 *   target, base→head, signer, signature validity, approvals, checks.
 *   esc        — back to list
 *   q          — quit
 *
 * Exit codes: 0 on clean quit, 1 if no TTY is available.
 *
 * Next step wires `r` in the detail view to a review-prose viewer.
 */

const COMMITS_LIMIT = 30;

interface Row {
  sha: string;
  title: string;
  attestation: AttestationPayload | null;
}

function loadRows(repoRoot: string, branch: string, limit: number): Row[] {
  const commits = firstParentCommits(branch, limit, repoRoot);
  return commits.map((c) => ({
    sha: c.sha,
    title: c.title,
    attestation: parseCommitAttestation(c.body)?.payload ?? null,
  }));
}

function renderAttestationSummary(p: AttestationPayload): string {
  const approvals = p.approvals
    .map((a) => (a.verdict === "approved" ? "✓" : "✗") + a.reviewer)
    .join(" ");
  const checks = (p.checks ?? [])
    .map((c) => (c.exit_code === 0 ? "✓" : "✗") + c.name)
    .join(" ");
  const checksPart = checks ? `  ${checks}` : "";
  return `${approvals}${checksPart}`;
}

function CommitRow({ row, selected }: { row: Row; selected: boolean }) {
  const marker = selected ? "▶" : " ";
  const sha = row.sha.slice(0, 10);
  const body = row.attestation
    ? renderAttestationSummary(row.attestation)
    : "unstamped";
  const bodyColor = row.attestation ? undefined : "red";

  return (
    <Box>
      <Text color={selected ? "yellow" : undefined} bold={selected}>
        {marker} {sha}
      </Text>
      <Box marginRight={2}>
        <Text color={bodyColor} dimColor={!selected && !!row.attestation}>
          {body}
        </Text>
      </Box>
      <Text dimColor={!selected}>{row.title}</Text>
    </Box>
  );
}

// ---------- detail view ----------

interface DetailData {
  sha: string;
  title: string;
  /** null if the commit has no attestation trailer */
  parsed: ParsedAttestation | null;
  /** null if no trailer, "valid", "invalid", or "untrusted" (no matching key). */
  sigStatus: "valid" | "invalid" | "untrusted" | null;
}

function loadDetail(repoRoot: string, sha: string): DetailData {
  const msg = commitMessage(sha, repoRoot);
  const title = (msg.split("\n")[0] ?? "").trim();
  const parsed = parseCommitAttestation(msg);
  if (!parsed) {
    return { sha, title, parsed: null, sigStatus: null };
  }
  const trustedPem = findTrustedKey(repoRoot, parsed.payload.signer_key_id);
  if (!trustedPem) {
    return { sha, title, parsed, sigStatus: "untrusted" };
  }
  let ok = false;
  try {
    ok = verifyBytes(trustedPem, parsed.payloadBytes, parsed.signatureBase64);
  } catch {
    ok = false;
  }
  return { sha, title, parsed, sigStatus: ok ? "valid" : "invalid" };
}

function Detail({ data }: { data: DetailData }) {
  const { sha, title, parsed, sigStatus } = data;

  return (
    <Box flexDirection="column" padding={1}>
      <Box marginBottom={1}>
        <Text color="yellow" bold>
          detail — {sha.slice(0, 12)}
        </Text>
      </Box>
      <Text>{title}</Text>

      {!parsed ? (
        <Box marginTop={1}>
          <Text color="red">no Stamp-Payload trailer — commit is unstamped</Text>
        </Box>
      ) : (
        <>
          <Box marginTop={1} flexDirection="column">
            <Text>
              <Text dimColor>target:     </Text>
              {parsed.payload.target_branch}
            </Text>
            <Text>
              <Text dimColor>base→head:  </Text>
              {parsed.payload.base_sha.slice(0, 10)} →{" "}
              {parsed.payload.head_sha.slice(0, 10)}
            </Text>
            <Text>
              <Text dimColor>signer:     </Text>
              {parsed.payload.signer_key_id}
            </Text>
            <Text>
              <Text dimColor>signature:  </Text>
              <SigBadge status={sigStatus} />
            </Text>
          </Box>

          <Box marginTop={1} flexDirection="column">
            <Text bold>approvals:</Text>
            {parsed.payload.approvals.map((a) => (
              <Text key={a.reviewer}>
                {"  "}
                <Text color={a.verdict === "approved" ? "green" : "red"}>
                  {a.verdict === "approved" ? "✓" : "✗"}
                </Text>{" "}
                {a.reviewer.padEnd(12)} {a.verdict}
              </Text>
            ))}
          </Box>

          {parsed.payload.checks && parsed.payload.checks.length > 0 && (
            <Box marginTop={1} flexDirection="column">
              <Text bold>checks:</Text>
              {parsed.payload.checks.map((c) => (
                <Text key={c.name}>
                  {"  "}
                  <Text color={c.exit_code === 0 ? "green" : "red"}>
                    {c.exit_code === 0 ? "✓" : "✗"}
                  </Text>{" "}
                  {c.name.padEnd(12)} exit {c.exit_code}
                </Text>
              ))}
            </Box>
          )}
        </>
      )}

      <Box marginTop={2}>
        <Text dimColor>esc back   q quit   (r: reviews — next phase)</Text>
      </Box>
    </Box>
  );
}

function SigBadge({ status }: { status: DetailData["sigStatus"] }) {
  if (status === null) return <Text color="red">n/a</Text>;
  if (status === "valid") return <Text color="green">✓ valid</Text>;
  if (status === "invalid") return <Text color="red">✗ INVALID</Text>;
  return <Text color="red">✗ untrusted key (not in .stamp/trusted-keys/)</Text>;
}

// ---------- app ----------

function App({
  repoRoot,
  branch,
  rows,
}: {
  repoRoot: string;
  branch: string;
  rows: Row[];
}) {
  const { exit } = useApp();
  const [selected, setSelected] = useState(0);
  const [detailSha, setDetailSha] = useState<string | null>(null);

  useInput((input, key) => {
    if (input === "q") {
      exit();
      return;
    }
    if (detailSha !== null) {
      if (key.escape) {
        setDetailSha(null);
        return;
      }
      return;
    }
    // list mode
    if (key.escape) {
      exit();
      return;
    }
    if (key.upArrow || input === "k") {
      setSelected((i) => Math.max(0, i - 1));
      return;
    }
    if (key.downArrow || input === "j") {
      setSelected((i) => Math.min(rows.length - 1, i + 1));
      return;
    }
    if (key.return && rows[selected]) {
      setDetailSha(rows[selected]!.sha);
      return;
    }
  });

  if (detailSha !== null) {
    const data = loadDetail(repoRoot, detailSha);
    return <Detail data={data} />;
  }

  if (rows.length === 0) {
    return (
      <Box padding={1} flexDirection="column">
        <Text color="yellow" bold>
          stamp ui — {branch}
        </Text>
        <Box marginTop={1}>
          <Text>No commits on this branch.</Text>
        </Box>
        <Box marginTop={2}>
          <Text dimColor>q to quit</Text>
        </Box>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" padding={1}>
      <Box marginBottom={1}>
        <Text color="yellow" bold>
          stamp ui — {branch}
        </Text>
        <Text dimColor>
          ({rows.length} commit{rows.length === 1 ? "" : "s"}, first-parent)
        </Text>
      </Box>
      {rows.map((row, i) => (
        <CommitRow key={row.sha} row={row} selected={i === selected} />
      ))}
      <Box marginTop={1}>
        <Text dimColor>
          ↑↓ / jk navigate   ⏎ detail   q quit
        </Text>
      </Box>
    </Box>
  );
}

export function runUi(): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error(
      "error: `stamp ui` requires an interactive terminal (TTY). " +
        "Run it directly, not under a pipe/redirect or non-interactive shell.",
    );
    process.exit(1);
  }

  const repoRoot = findRepoRoot();
  const branch = currentBranch(repoRoot);
  const rows = loadRows(repoRoot, branch, COMMITS_LIMIT);
  render(<App repoRoot={repoRoot} branch={branch} rows={rows} />);
}
