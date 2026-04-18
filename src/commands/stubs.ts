/**
 * Stubs for commands that haven't landed yet:
 *   - log, reviewers   → Phase 1.F
 */

function notImplemented(name: string, phase: string): never {
  console.error(`${name} is not yet implemented (lands in Phase ${phase}).`);
  process.exit(2);
}

export const runLog = () => notImplemented("stamp log", "1.F");
export const runReviewers = (_sub: string) =>
  notImplemented("stamp reviewers", "1.F");
