import { Box, render, Text, useApp, useInput } from "ink";
import { findRepoRoot } from "../lib/paths.js";

/**
 * Phase 2.B/TUI step 1 — skeleton.
 *
 * Placeholder app. Exits on `q` or `esc`; Ctrl-C goes through ink's
 * default `exitOnCtrlC` handler. Prints the repo root so the user
 * can confirm the app found the right place.
 *
 * Exit codes: 0 on clean quit, 1 if no TTY is available.
 *
 * Subsequent steps replace the body with a commit-list view, then
 * detail view, then review-prose viewer.
 */

function App({ repoRoot }: { repoRoot: string }) {
  const { exit } = useApp();

  useInput((input, key) => {
    if (input === "q" || key.escape) {
      exit();
    }
  });

  return (
    <Box flexDirection="column" padding={1}>
      <Box marginBottom={1}>
        <Text color="yellow" bold>
          stamp ui
        </Text>
      </Box>
      <Text dimColor>repo: {repoRoot}</Text>
      <Box marginTop={1}>
        <Text>
          placeholder — subsequent phases add the commit list, drill-down,
          and review prose viewer.
        </Text>
      </Box>
      <Box marginTop={2}>
        <Text dimColor>press q or esc to quit</Text>
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
  render(<App repoRoot={repoRoot} />);
}
