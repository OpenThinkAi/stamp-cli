/**
 * Stubs for Phase 1.A. Real implementations land in later phases:
 *   - review, status           → Phase 1.B / 1.C
 *   - merge, verify, keys      → Phase 1.D
 *   - push                     → Phase 1.E
 *   - log, reviewers           → Phase 1.F
 */

function notImplemented(name: string, phase: string): never {
  console.error(`${name} is not yet implemented (lands in Phase ${phase}).`);
  process.exit(2);
}

export const runReview = () => notImplemented("stamp review", "1.B");
export const runStatus = () => notImplemented("stamp status", "1.C");
export const runMerge = () => notImplemented("stamp merge", "1.D");
export const runVerify = () => notImplemented("stamp verify", "1.D");
export const runPush = () => notImplemented("stamp push", "1.E");
export const runLog = () => notImplemented("stamp log", "1.F");
export const runKeys = (_sub: string) => notImplemented("stamp keys", "1.D");
export const runReviewers = (_sub: string) =>
  notImplemented("stamp reviewers", "1.F");
