/**
 * Rich STATIC rendering primitives for stamp's CI-facing check output
 * (`stamp verify-pr`, consumed by stamp/verify-attestation@v1's step log).
 *
 * Deliberately NOT a TUI: no alt-screen, no input loop, no cursor
 * control — just a badge banner + box-drawing tables printed once.
 * GitHub Actions step logs render ANSI colors and box-drawing (but not
 * markdown), so the same output reads well on a TTY and in CI. Markdown
 * for the run's Summary tab is a separate surface — see the
 * GITHUB_STEP_SUMMARY writers in `verifyPr.ts`.
 *
 * Dependency-free: hand-rolled ANSI + box-drawing, gated behind
 * `colorEnabled()`. Honors the NO_COLOR standard (https://no-color.org).
 */

// --- ANSI -------------------------------------------------------------------

const ESC = "\x1b[";
type Code = string;
export const A = {
  reset: "0",
  bold: "1",
  dim: "2",
  black: "30",
  red: "31",
  green: "32",
  yellow: "33",
  cyan: "36",
  gray: "90",
  bgRed: "41",
  bgGreen: "42",
  bgYellow: "43",
} as const;

/**
 * Decide whether to emit ANSI color. NO_COLOR (any value, even empty)
 * disables; otherwise color is on for a TTY *or* inside GitHub Actions
 * (GITHUB_ACTIONS=true), whose log viewer renders ANSI even though the
 * step's stdout is a pipe.
 */
export function colorEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.NO_COLOR !== undefined) return false;
  return Boolean(process.stdout.isTTY) || env.GITHUB_ACTIONS === "true";
}

/** A tiny styler closed over the color flag. `paint(false)` is the identity. */
export function paint(color: boolean) {
  return (text: string, ...codes: Code[]): string => {
    if (!color || codes.length === 0) return text;
    return `${ESC}${codes.join(";")}m${text}${ESC}${A.reset}m`;
  };
}

/** Visible length: strip ANSI SGR sequences, then count code points. */
function vlen(s: string): number {
  return [...s.replace(/\x1b\[[0-9;]*m/g, "")].length;
}

// --- Text helpers -----------------------------------------------------------

/** Word-wrap plain text to `width`; hard-breaks words longer than the column. */
export function wrap(text: string, width: number): string[] {
  if (width < 1) width = 1;
  const out: string[] = [];
  for (const para of text.split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/).filter(Boolean)) {
      let w = word;
      while (w.length > width) {
        if (line) {
          out.push(line);
          line = "";
        }
        out.push(w.slice(0, width));
        w = w.slice(width);
      }
      if (!line) line = w;
      else if (line.length + 1 + w.length <= width) line += " " + w;
      else {
        out.push(line);
        line = w;
      }
    }
    out.push(line);
  }
  return out.length ? out : [""];
}

// --- Box-drawing table engine -----------------------------------------------

type Align = "left" | "right";
export interface Column {
  header: string;
  /** the flex column wraps to fit the width budget; others size to content. */
  flex?: boolean;
  align?: Align;
}

const BOX = {
  tl: "┌", tr: "┐", bl: "└", br: "┘",
  h: "─", v: "│",
  tj: "┬", bj: "┴", lj: "├", rj: "┤", x: "┼",
} as const;

function pad(cell: string, width: number, align: Align): string {
  const gap = width - vlen(cell);
  if (gap <= 0) return cell;
  return align === "right" ? " ".repeat(gap) + cell : cell + " ".repeat(gap);
}

/**
 * Render a bordered table. `rows` cells may carry ANSI (width is measured
 * ignoring escapes). The flex column wraps to fit `maxWidth`; everything
 * else sizes to its content.
 */
export function table(
  cols: Column[],
  rows: string[][],
  opts: { color: boolean; maxWidth: number; indent?: string },
): string {
  const p = paint(opts.color);
  const indent = opts.indent ?? "";
  const n = cols.length;

  // Natural width per column = widest of header / cells.
  const widths = cols.map((col, i) =>
    Math.max(vlen(col.header), ...rows.map((r) => vlen(r[i] ?? ""))),
  );

  // Shrink the flex column if the table overflows the width budget.
  // Frame overhead: each column adds 2 padding spaces + a vertical bar,
  // plus a trailing bar and the indent.
  const frame = n * 3 + 1 + indent.length;
  const flexIdx = cols.findIndex((col) => col.flex);
  if (flexIdx >= 0) {
    const others = widths.reduce((s, w, i) => (i === flexIdx ? s : s + w), 0);
    const budget = opts.maxWidth - frame - others;
    widths[flexIdx] = Math.max(20, Math.min(widths[flexIdx]!, budget));
  }

  const line = (l: string, mid: string, r: string) =>
    indent +
    p(l + cols.map((_, i) => BOX.h.repeat(widths[i]! + 2)).join(mid) + r, A.gray);

  const rowLine = (cells: string[]) => {
    // Wrap each flex cell to its column width → a grid of physical lines.
    const wrapped = cells.map((cell, i) =>
      cols[i]!.flex ? wrap(cell.replace(/\x1b\[[0-9;]*m/g, ""), widths[i]!) : [cell],
    );
    const height = Math.max(...wrapped.map((w) => w.length));
    const lines: string[] = [];
    for (let row = 0; row < height; row++) {
      const parts = cols.map((col, i) => {
        const text = wrapped[i]![row] ?? "";
        return " " + pad(text, widths[i]!, col.align ?? "left") + " ";
      });
      lines.push(
        indent + p(BOX.v, A.gray) + parts.join(p(BOX.v, A.gray)) + p(BOX.v, A.gray),
      );
    }
    return lines.join("\n");
  };

  const out: string[] = [];
  out.push(line(BOX.tl, BOX.tj, BOX.tr));
  out.push(rowLine(cols.map((col) => p(col.header, A.bold))));
  out.push(line(BOX.lj, BOX.x, BOX.rj));
  for (const r of rows) out.push(rowLine(r));
  out.push(line(BOX.bl, BOX.bj, BOX.br));
  return out.join("\n");
}

// --- Markdown helpers (GITHUB_STEP_SUMMARY surface) ---------------------------

/** Escape a value for a GitHub-markdown table cell (pipes + newlines). */
export function mdCell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}
