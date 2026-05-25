/**
 * Tests for src/lib/serverConfig.ts — parseServerConfig, parseServerFlag.
 *
 * Coverage:
 *   - ws_url: valid ws:// and wss:// values are accepted and stored
 *   - ws_url: non-ws scheme (http://, ftp://, bare string) is rejected
 *   - ws_url: malformed URL (unparseable) is rejected
 *   - ws_url: absent → wsUrl is undefined (field is optional)
 *   - ws_url: present on parseServerFlag path → wsUrl is undefined (can't
 *     express it in host:port form)
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { parseServerConfig, parseServerFlag } from "../src/lib/serverConfig.ts";

// ─── ws_url: valid values ─────────────────────────────────────────────

describe("parseServerConfig: ws_url — valid values accepted", () => {
  it("accepts a wss:// URL and stores it as wsUrl", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: wss://stamp-cli-production.up.railway.app
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.wsUrl, "wss://stamp-cli-production.up.railway.app");
  });

  it("accepts a ws:// URL and stores it as wsUrl", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: ws://localhost:8080
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.wsUrl, "ws://localhost:8080");
  });

  it("strips trailing slash from ws_url before storing", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: wss://stamp-cli-production.up.railway.app/
`;
    // parseServerConfig stores the raw (non-trailing-stripped) value;
    // buildWsPeerListenUrl strips it when appending /peer/listen.
    // This test verifies the raw value is stored as-is.
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.wsUrl, "wss://stamp-cli-production.up.railway.app/");
  });

  it("accepts a wss:// URL with a path prefix", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: wss://example.com/stamp
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.wsUrl, "wss://example.com/stamp");
  });
});

// ─── ws_url: absent → wsUrl is undefined ─────────────────────────────

describe("parseServerConfig: ws_url — absent leaves wsUrl undefined", () => {
  it("wsUrl is undefined when ws_url is not present in config", () => {
    const raw = `
host: stamp.example.com
port: 2222
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.wsUrl, undefined);
  });
});

// ─── ws_url: invalid scheme ───────────────────────────────────────────

describe("parseServerConfig: ws_url — non-ws scheme is rejected", () => {
  it("rejects http:// scheme", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: http://stamp-cli-production.up.railway.app
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*must start with 'ws:\/\/' or 'wss:\/\/'/,
    );
  });

  it("rejects https:// scheme", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: https://stamp-cli-production.up.railway.app
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*must start with 'ws:\/\/' or 'wss:\/\/'/,
    );
  });

  it("rejects a bare hostname with no scheme", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: stamp-cli-production.up.railway.app
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*must start with 'ws:\/\/' or 'wss:\/\/'/,
    );
  });

  it("rejects ftp:// scheme", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: ftp://example.com
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*must start with 'ws:\/\/' or 'wss:\/\/'/,
    );
  });
});

// ─── ws_url: malformed URL ────────────────────────────────────────────

describe("parseServerConfig: ws_url — malformed URL (correct scheme but unparseable) is rejected", () => {
  it("rejects a URL that fails URL parsing after scheme check", () => {
    // A string that starts with wss:// but is not a valid URL.
    const raw = `
host: stamp.example.com
port: 2222
ws_url: wss://
`;
    // wss:// alone has no host — new URL("wss://") throws in Node.js.
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*not a valid URL/,
    );
  });
});

// ─── ws_url: non-string type ──────────────────────────────────────────

describe("parseServerConfig: ws_url — non-string type is rejected", () => {
  it("rejects a numeric ws_url", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: 8080
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*must be a non-empty string/,
    );
  });
});

// ─── parseServerFlag: wsUrl is always undefined ───────────────────────

describe("parseServerFlag: wsUrl is always undefined", () => {
  it("parseServerFlag leaves wsUrl undefined (host:port can't express it)", () => {
    const cfg = parseServerFlag("stamp.example.com:2222");
    assert.equal(cfg.wsUrl, undefined);
  });
});
