/**
 * Control-character handling for text that crosses a trust boundary on its
 * way to a terminal or a log line (AGT-2270).
 *
 *   - `stripTerminalControls` — for text printed to an operator's terminal
 *     that another party controls (server responses, peer PR titles, LLM
 *     output). Removes ESC/CSI/OSC sequences and every other C0/C1 control
 *     except newline and tab, so a hostile string cannot move the cursor,
 *     rewrite earlier lines, set the window title or emit hyperlinks.
 *   - `escapeLogControls` — for untrusted values interpolated into a
 *     one-line log entry. Renders CR, LF and other controls as visible
 *     escapes (`\n`, `\x1b`, ...) so a value cannot start a forged log line,
 *     while keeping the evidence readable.
 */

// eslint-disable-next-line no-control-regex
const ANSI_SEQUENCE_RE = /\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\)?|[@-Z\\-_])/g;
// C0 minus \t (0x09) and \n (0x0a), DEL, and the C1 range.
// eslint-disable-next-line no-control-regex
const TERMINAL_CONTROL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

export function stripTerminalControls(text: string): string {
  return text.replace(ANSI_SEQUENCE_RE, "").replace(TERMINAL_CONTROL_RE, "");
}

// Every C0 control, DEL, C1, and the Unicode line/paragraph separators.
// eslint-disable-next-line no-control-regex
const LOG_CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

export function escapeLogControls(text: string): string {
  return text.replace(LOG_CONTROL_RE, (c) => {
    if (c === "\n") return "\\n";
    if (c === "\r") return "\\r";
    if (c === "\t") return "\\t";
    const code = c.charCodeAt(0);
    return code > 0xff
      ? `\\u${code.toString(16).padStart(4, "0")}`
      : `\\x${code.toString(16).padStart(2, "0")}`;
  });
}
