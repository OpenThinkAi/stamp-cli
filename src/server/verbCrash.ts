/**
 * Client-facing crash line for the Node SSH verbs (AGT-2270).
 *
 * An SSH verb's stderr goes straight to the client. A stack trace there
 * shows server filesystem paths (the bundle location, the prompts cache)
 * and internal call structure to any enrolled member, so an unexpected
 * error prints its class and message only — never `err.stack`. Errors that
 * carry server-side detail keep it out of `message` (see
 * `PromptFetchFailedError.detail`).
 */
export function verbCrashLine(verb: string, err: unknown): string {
  if (err instanceof Error) {
    const firstLine = (err.message.split("\n")[0] ?? "").trim();
    const name = err.name && err.name !== "Error" ? `${err.name}: ` : "";
    return `error: ${verb} failed: ${name}${firstLine || "unexpected error"}\n`;
  }
  return `error: ${verb} failed: unexpected error\n`;
}
