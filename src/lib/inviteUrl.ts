/**
 * Parser for the share-URL format that `stamp invites mint` emits and
 * `stamp invites accept` consumes:
 *
 *   stamp+invite://<host>[:<port>]/<token>
 *
 * Lives in lib/ rather than commands/ so unit tests can import it
 * without dragging the rest of the accept-invite TUI surface.
 *
 * SECURITY (AGT-416): the URL carries NO transport marker. Transport
 * (HTTPS vs plaintext HTTP) is decided entirely client-side by the
 * invitee at accept time, defaulting to HTTPS — see `resolveAcceptTransport`
 * in commands/invites.ts. Earlier versions baked `?insecure=1` into the
 * URL to flip the accept POST to HTTP; that let a network/MITM attacker
 * (or a phisher) append `?insecure=1` to a legitimate HTTPS invite and
 * downgrade the single-use token + SSH pubkey to sniffable plaintext. A
 * transport decision must not cross the trust boundary inside an
 * attacker-tamperable URL. For back-compat any trailing `?...` query on a
 * legacy URL is stripped and IGNORED — it can no longer influence
 * transport.
 */

export interface ParsedShareTarget {
  /** `host[:port]` from the URL (no scheme, no path). */
  host: string;
  /** 32-byte base64url token. */
  token: string;
}

/** Matches the 32-byte base64url shape mint-invite emits (43 chars, no padding). */
const TOKEN_RE = /^[A-Za-z0-9_-]{20,128}$/;

export class ShareUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShareUrlError";
  }
}

/**
 * Parse a stamp+invite:// URL or a bare token. A bare token requires
 * `serverFlag` to be supplied so we know where to POST.
 */
export function parseShareUrl(
  input: string,
  serverFlag?: string,
): ParsedShareTarget {
  const trimmed = input.trim();
  if (trimmed.startsWith("stamp+invite://")) {
    const remainder = trimmed.slice("stamp+invite://".length);
    const firstSlash = remainder.indexOf("/");
    if (firstSlash < 0) {
      throw new ShareUrlError(`share URL has no token: ${JSON.stringify(input)}`);
    }
    const host = remainder.slice(0, firstSlash);
    let tokenPart = remainder.slice(firstSlash + 1);
    // Strip and IGNORE any trailing query string. Legacy URLs may carry
    // `?insecure=1`; it no longer affects transport (see docblock /
    // AGT-416) but must still parse so an in-flight legacy invite isn't
    // hard-rejected.
    const queryIdx = tokenPart.indexOf("?");
    if (queryIdx >= 0) {
      tokenPart = tokenPart.slice(0, queryIdx);
    }
    if (!TOKEN_RE.test(tokenPart)) {
      throw new ShareUrlError(
        `share URL has a malformed token: ${JSON.stringify(tokenPart)}`,
      );
    }
    if (host.length === 0) {
      throw new ShareUrlError(`share URL has no host: ${JSON.stringify(input)}`);
    }
    return { host, token: tokenPart };
  }

  // Bare token; needs --server.
  if (!TOKEN_RE.test(trimmed)) {
    throw new ShareUrlError(
      `expected a stamp+invite:// URL or a bare token (got ${JSON.stringify(input)})`,
    );
  }
  if (!serverFlag) {
    throw new ShareUrlError(
      "bare token requires --server <host>:<port> so we know where to POST",
    );
  }
  return { host: serverFlag, token: trimmed };
}
