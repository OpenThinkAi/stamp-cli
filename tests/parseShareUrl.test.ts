/**
 * `stamp accept-invite` URL parser tests. The share URL format is the
 * wire surface between mint and accept; a parser regression here would
 * make every invite invitee mint silently unreachable, with no fix
 * short of server-side rewrites. Pin the accepted shapes here.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { parseShareUrl } from "../src/lib/inviteUrl.ts";

const VALID_TOKEN = "abc123_def456-ghiJKLmnopqrstuvwxyz0123456789AB";

describe("parseShareUrl", () => {
  it("parses host:port + token from a stamp+invite:// URL", () => {
    const r = parseShareUrl(`stamp+invite://stamp.example.com:8443/${VALID_TOKEN}`);
    assert.equal(r.host, "stamp.example.com:8443");
    assert.equal(r.token, VALID_TOKEN);
    assert.equal(r.insecure, false);
  });

  it("parses a URL with implicit port (just hostname)", () => {
    const r = parseShareUrl(`stamp+invite://stamp.example.com/${VALID_TOKEN}`);
    assert.equal(r.host, "stamp.example.com");
    assert.equal(r.token, VALID_TOKEN);
    assert.equal(r.insecure, false);
  });

  it("flips insecure on ?insecure=1", () => {
    const r = parseShareUrl(`stamp+invite://localhost:8080/${VALID_TOKEN}?insecure=1`);
    assert.equal(r.host, "localhost:8080");
    assert.equal(r.token, VALID_TOKEN);
    assert.equal(r.insecure, true);
  });

  it("accepts a bare token when --server is supplied", () => {
    const r = parseShareUrl(VALID_TOKEN, "stamp.example.com:443");
    assert.equal(r.host, "stamp.example.com:443");
    assert.equal(r.token, VALID_TOKEN);
    assert.equal(r.insecure, false);
  });

  it("rejects a bare token without --server", () => {
    assert.throws(
      () => parseShareUrl(VALID_TOKEN),
      /requires --server/,
    );
  });

  it("rejects a stamp+invite:// URL with no token path", () => {
    assert.throws(
      () => parseShareUrl("stamp+invite://host.example.com"),
      /no token/,
    );
  });

  it("rejects a stamp+invite:// URL with no host", () => {
    assert.throws(
      () => parseShareUrl(`stamp+invite:///${VALID_TOKEN}`),
      /no host/,
    );
  });

  it("rejects a malformed token in a URL (wrong charset / too short)", () => {
    assert.throws(
      () => parseShareUrl("stamp+invite://host.example.com/short!"),
      /malformed token/,
    );
  });

  it("rejects bare input that is neither a URL nor a valid token", () => {
    assert.throws(
      () => parseShareUrl("not-a-url-or-token!"),
      /URL or a bare token/,
    );
  });

  it("trims surrounding whitespace before parsing", () => {
    const r = parseShareUrl(`  stamp+invite://host.example.com/${VALID_TOKEN}\n`);
    assert.equal(r.host, "host.example.com");
    assert.equal(r.token, VALID_TOKEN);
  });
});
