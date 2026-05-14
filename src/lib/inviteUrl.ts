/**
 * Parser for the share-URL format that `stamp invites mint` emits and
 * `stamp invites accept` consumes:
 *
 *   stamp+invite://<host>[:<port>]/<token>[?insecure=1]
 *
 * Lives in lib/ rather than commands/ so unit tests can import it
 * without dragging the rest of the accept-invite TUI surface.
 *
 * The `?insecure=1` query param flips HTTPS → HTTP for the accept POST.
 * Emitted by mint-invite only when STAMP_PUBLIC_URL is plain http://
 * (dev / self-hosted-on-LAN). Operators running TLS at the platform
 * edge (Railway) never see it.
 */

export interface ParsedShareTarget {
  /** `host[:port]` from the URL (no scheme, no path). */
  host: string;
  /** 32-byte base64url token. */
  token: string;
  /** When true, accept POST goes over plain HTTP instead of HTTPS. */
  insecure: boolean;
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
    let insecure = false;
    const queryIdx = tokenPart.indexOf("?");
    if (queryIdx >= 0) {
      // Only one supported query param: insecure=1
      const query = tokenPart.slice(queryIdx + 1);
      tokenPart = tokenPart.slice(0, queryIdx);
      if (query === "insecure=1") insecure = true;
    }
    if (!TOKEN_RE.test(tokenPart)) {
      throw new ShareUrlError(
        `share URL has a malformed token: ${JSON.stringify(tokenPart)}`,
      );
    }
    if (host.length === 0) {
      throw new ShareUrlError(`share URL has no host: ${JSON.stringify(input)}`);
    }
    return { host, token: tokenPart, insecure };
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
  return { host: serverFlag, token: trimmed, insecure: false };
}
