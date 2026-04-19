import { Box, render, Text, useApp, useInput, useStdout } from "ink";
import { existsSync } from "node:fs";
import { useMemo, useState } from "react";
import {
  parseCommitAttestation,
  type AttestationPayload,
  type ParsedAttestation,
} from "../lib/attestation.js";
import { latestReviews, openDb, type LatestReview } from "../lib/db.js";
import {
  commitMessage,
  currentBranch,
  firstParentCommits,
} from "../lib/git.js";
import { findTrustedKey } from "../lib/keys.js";
import { findRepoRoot, stampStateDbPath } from "../lib/paths.js";
import { verifyBytes } from "../lib/signing.js";

/**
 * Phase 2.B/TUI step 4 — list + detail + review prose viewer.
 *
 * List:
 *   ↑/↓ or j/k   navigate
 *   ⏎            open detail for selected commit
 *   q/esc        quit
 *
 * Detail:
 *   r            open review prose viewer (if any reviews in local DB)
 *   esc          back to list
 *   q            quit
 *
 * Reviews:
 *   n            next reviewer (cycles)
 *   p            previous reviewer
 *   ↑/↓ or j/k   scroll prose
 *   esc          back to detail
 *   q            quit
 *
 * Ctrl-C via ink's default in all modes.
 *
 * Exit codes: 0 on clean quit, 1 if no TTY is available.
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

// ---------- detail ----------

interface DetailData {
  sha: string;
  title: string;
  parsed: ParsedAttestation | null;
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

function SigBadge({ status }: { status: DetailData["sigStatus"] }) {
  if (status === null) return <Text color="red">n/a</Text>;
  if (status === "valid") return <Text color="green">✓ valid</Text>;
  if (status === "invalid") return <Text color="red">✗ INVALID</Text>;
  return <Text color="red">✗ untrusted key (not in .stamp/trusted-keys/)</Text>;
}

function Detail({
  data,
  hasReviewProse,
}: {
  data: DetailData;
  hasReviewProse: boolean;
}) {
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
        <Text dimColor>
          esc back   q quit
          {hasReviewProse ? "   r reviews" : "   (no review prose in local DB)"}
        </Text>
      </Box>
    </Box>
  );
}

// ---------- review prose viewer ----------

function loadReviewProse(
  repoRoot: string,
  payload: AttestationPayload,
): LatestReview[] {
  const dbPath = stampStateDbPath(repoRoot);
  if (!existsSync(dbPath)) return [];
  const db = openDb(dbPath);
  try {
    const rows = latestReviews(db, payload.base_sha, payload.head_sha);
    // Preserve attestation's reviewer order for consistent n/p cycling.
    const byName = new Map(rows.map((r) => [r.reviewer, r]));
    const ordered: LatestReview[] = [];
    for (const a of payload.approvals) {
      const row = byName.get(a.reviewer);
      if (row) ordered.push(row);
    }
    return ordered;
  } finally {
    db.close();
  }
}

function ReviewProse({
  sha,
  reviews,
  index,
  scrollOffset,
  viewportHeight,
}: {
  sha: string;
  reviews: LatestReview[];
  index: number;
  scrollOffset: number;
  viewportHeight: number;
}) {
  const current = reviews[index]!;
  const hasProse = (current.issues ?? "").trim().length > 0;
  const lines = useMemo(() => (current.issues ?? "").split("\n"), [current]);
  const visible = lines.slice(scrollOffset, scrollOffset + viewportHeight);
  const hasMoreBelow = scrollOffset + viewportHeight < lines.length;
  const hasMoreAbove = scrollOffset > 0;

  return (
    <Box flexDirection="column" padding={1}>
      <Box marginBottom={1}>
        <Text color="yellow" bold>
          review: {current.reviewer}
        </Text>
        <Text dimColor> — commit {sha.slice(0, 10)}</Text>
      </Box>
      <Text>
        <Text color={current.verdict === "approved" ? "green" : "red"}>
          verdict:
        </Text>{" "}
        {current.verdict}
      </Text>

      <Box marginTop={1} height={1}>
        {hasMoreAbove ? <Text dimColor>↑ more above</Text> : null}
      </Box>

      <Box flexDirection="column">
        {!hasProse ? (
          <Text dimColor>(no prose recorded)</Text>
        ) : (
          visible.map((line, i) => (
            <Text key={`${scrollOffset}-${i}`}>{line || " "}</Text>
          ))
        )}
      </Box>

      <Box marginTop={1} height={1}>
        {hasMoreBelow ? <Text dimColor>↓ more below</Text> : null}
      </Box>

      <Box marginTop={1}>
        <Text dimColor>
          ({index + 1}/{reviews.length}) n next   p prev   ↑↓/jk scroll   esc back   q quit
        </Text>
      </Box>
    </Box>
  );
}

// ---------- app ----------

type Mode =
  | { kind: "list" }
  | { kind: "detail"; sha: string }
  | {
      kind: "reviews";
      sha: string;
      reviews: LatestReview[];
      index: number;
      scroll: number;
    };

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
  const { stdout } = useStdout();
  const [selected, setSelected] = useState(0);
  const [mode, setMode] = useState<Mode>({ kind: "list" });

  // Leave room for the header/footer chrome — ~12 rows of non-prose per screen
  // (title, verdict line, scroll indicators above & below, key-hint line,
  // padding).
  const proseViewportHeight = Math.max(5, (stdout?.rows ?? 30) - 12);

  // Detail data + the matching review-prose rows are both keyed on the
  // commit SHA. Memoize them together so SQLite is opened once per commit
  // (re-runs only when the user opens detail for a different commit).
  const contextSha =
    mode.kind === "detail" || mode.kind === "reviews" ? mode.sha : null;
  const commitContext = useMemo(() => {
    if (contextSha === null) return null;
    const data = loadDetail(repoRoot, contextSha);
    const reviews = data.parsed
      ? loadReviewProse(repoRoot, data.parsed.payload)
      : [];
    return { data, reviews };
  }, [contextSha, repoRoot]);

  useInput((input, key) => {
    if (input === "q") {
      exit();
      return;
    }

    if (mode.kind === "reviews") {
      if (key.escape) {
        setMode({ kind: "detail", sha: mode.sha });
        return;
      }
      if (input === "n") {
        setMode({
          ...mode,
          index: (mode.index + 1) % mode.reviews.length,
          scroll: 0,
        });
        return;
      }
      if (input === "p") {
        setMode({
          ...mode,
          index: (mode.index - 1 + mode.reviews.length) % mode.reviews.length,
          scroll: 0,
        });
        return;
      }
      if (key.downArrow || input === "j") {
        const current = mode.reviews[mode.index]!;
        const lineCount = (current.issues ?? "").split("\n").length;
        const maxScroll = Math.max(0, lineCount - proseViewportHeight);
        setMode({ ...mode, scroll: Math.min(maxScroll, mode.scroll + 1) });
        return;
      }
      if (key.upArrow || input === "k") {
        setMode({ ...mode, scroll: Math.max(0, mode.scroll - 1) });
        return;
      }
      return;
    }

    if (mode.kind === "detail") {
      if (key.escape) {
        setMode({ kind: "list" });
        return;
      }
      if (input === "r" && commitContext && commitContext.reviews.length > 0) {
        setMode({
          kind: "reviews",
          sha: mode.sha,
          reviews: commitContext.reviews,
          index: 0,
          scroll: 0,
        });
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
      setMode({ kind: "detail", sha: rows[selected]!.sha });
      return;
    }
  });

  if (mode.kind === "reviews") {
    return (
      <ReviewProse
        sha={mode.sha}
        reviews={mode.reviews}
        index={mode.index}
        scrollOffset={mode.scroll}
        viewportHeight={proseViewportHeight}
      />
    );
  }

  if (mode.kind === "detail" && commitContext) {
    return (
      <Detail
        data={commitContext.data}
        hasReviewProse={commitContext.reviews.length > 0}
      />
    );
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
