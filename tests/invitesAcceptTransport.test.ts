/**
 * AGT-416 — `stamp invites accept` transport selection.
 *
 * The security property: transport (HTTPS vs plaintext HTTP) is decided
 * client-side, NOT from the share URL, and plaintext HTTP requires two
 * explicit flags — `--insecure-http-for-dev` AND `--accept-insecure` —
 * neither of which is `--yes`. So an agent passing `--yes` can never
 * silently downgrade the token + SSH pubkey to plaintext.
 *
 * `resolveAcceptTransport` is pure (modulo the UsageError throw), so the
 * whole contract is testable without standing up a server.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { resolveAcceptTransport } from "../src/commands/invites.ts";
import { UsageError } from "../src/commands/serverRepo.ts";

describe("resolveAcceptTransport (AGT-416)", () => {
  it("defaults to HTTPS when no flags are passed", () => {
    assert.deepEqual(resolveAcceptTransport({}), { useHttp: false });
  });

  it("uses HTTPS when only --accept-insecure is passed (consent without selection)", () => {
    assert.deepEqual(
      resolveAcceptTransport({ acceptInsecure: true }),
      { useHttp: false },
    );
  });

  it("refuses --insecure-http-for-dev WITHOUT --accept-insecure", () => {
    assert.throws(
      () => resolveAcceptTransport({ insecureHttpForDev: true }),
      (e: Error) =>
        e instanceof UsageError && /--accept-insecure/.test(e.message),
    );
  });

  it("the refusal explicitly states --yes does not enable HTTP", () => {
    let err: Error | null = null;
    try {
      resolveAcceptTransport({ insecureHttpForDev: true });
    } catch (e) {
      err = e as Error;
    }
    assert.ok(err);
    assert.match(err!.message, /--yes does NOT enable HTTP/);
  });

  it("uses HTTP only when BOTH flags are passed", () => {
    assert.deepEqual(
      resolveAcceptTransport({
        insecureHttpForDev: true,
        acceptInsecure: true,
      }),
      { useHttp: true },
    );
  });

  it("has no `yes` lever — the signature cannot express a --yes HTTP downgrade", () => {
    // Compile-time + runtime proof that `yes` is not a transport input:
    // passing it through an unknown-shaped object never flips useHttp.
    const sneaky = { yes: true } as Parameters<typeof resolveAcceptTransport>[0];
    assert.deepEqual(resolveAcceptTransport(sneaky), { useHttp: false });
  });
});
