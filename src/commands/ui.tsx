import { Box, render, Text, useApp, useInput } from "ink";
import { useState } from "react";
import {
  parseCommitAttestation,
  type AttestationPayload,
} from "../lib/attestation.js";
import {
  currentBranch,
  firstParentCommits,
} from "../lib/git.js";
import { findRepoRoot } from "../lib/paths.js";

/**
 * Phase 2.B/TUI step 2 — commit list view.
 *
 * Renders first-parent merges on the current branch with a one-line
 * attestation summary (signer short, reviewer ✓/✗, check ✓/✗).
 * Navigate with ↑/↓ or j/k; q/esc to quit. Ctrl-C via ink's default.
 *
 * Exit codes: 0 on clean quit, 1 if no TTY is available.
 *
 * Subsequent steps wire the enter key to a commit-detail view and then
 * a review-prose viewer.
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

function App({
  branch,
  rows,
}: {
  branch: string;
  rows: Row[];
}) {
  const { exit } = useApp();
  const [selected, setSelected] = useState(0);

  useInput((input, key) => {
    if (input === "q" || key.escape) {
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
  });

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
          ↑↓ / jk navigate   q quit   (enter: detail view — next phase)
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
  render(<App branch={branch} rows={rows} />);
}
