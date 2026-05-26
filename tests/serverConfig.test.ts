/**
 * Tests for src/lib/serverConfig.ts — parseServerConfig, parseServerFlag.
 *
 * Coverage (AGT-454, SSE transport):
 *   - http_url: valid http:// and https:// values accepted and stored as httpUrl
 *   - http_url: non-http scheme (ws://, ftp://, bare string) is rejected
 *   - http_url: malformed URL (unparseable) is rejected
 *   - http_url: non-string type is rejected
 *   - http_url: absent → httpUrl is undefined (field is optional)
 *   - ws_url (back-compat): ws://|wss:// rewritten to http://|https://
 *   - http_url wins when both keys are present
 *   - parseServerFlag: httpUrl is always undefined (host:port can't express it)
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { parseServerConfig, parseServerFlag } from "../src/lib/serverConfig.ts";

// ─── http_url: valid values ───────────────────────────────────────────

describe("parseServerConfig: http_url — valid values accepted", () => {
  it("accepts an https:// URL and stores it as httpUrl", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: https://stamp-cli-production.up.railway.app
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "https://stamp-cli-production.up.railway.app");
  });

  it("accepts an http:// URL and stores it as httpUrl", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: http://localhost:8080
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "http://localhost:8080");
  });

  it("stores httpUrl as-is including trailing slash (stripping happens at URL-build time)", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: https://stamp-cli-production.up.railway.app/
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "https://stamp-cli-production.up.railway.app/");
  });

  it("accepts an https:// URL with a path prefix", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: https://example.com/stamp
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "https://example.com/stamp");
  });
});

// ─── http_url: absent → httpUrl is undefined ──────────────────────────

describe("parseServerConfig: http_url — absent leaves httpUrl undefined", () => {
  it("httpUrl is undefined when neither http_url nor ws_url is present", () => {
    const raw = `
host: stamp.example.com
port: 2222
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, undefined);
  });
});

// ─── http_url: invalid scheme ─────────────────────────────────────────

describe("parseServerConfig: http_url — non-http scheme is rejected", () => {
  it("rejects ws:// scheme on http_url", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: ws://stamp-cli-production.up.railway.app
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /http_url.*must start with 'http:\/\/' or 'https:\/\/'/,
    );
  });

  it("rejects a bare hostname with no scheme", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: stamp-cli-production.up.railway.app
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /http_url.*must start with 'http:\/\/' or 'https:\/\/'/,
    );
  });

  it("rejects ftp:// scheme", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: ftp://example.com
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /http_url.*must start with 'http:\/\/' or 'https:\/\/'/,
    );
  });
});

// ─── http_url: malformed URL ──────────────────────────────────────────

describe("parseServerConfig: http_url — malformed URL is rejected", () => {
  it("rejects a URL that fails URL parsing after scheme check", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: https://
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /http_url.*not a valid URL/,
    );
  });
});

// ─── http_url: non-string type ────────────────────────────────────────

describe("parseServerConfig: http_url — non-string type is rejected", () => {
  it("rejects a numeric http_url", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: 8080
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /http_url.*must be a non-empty string/,
    );
  });
});

// ─── ws_url: back-compat (rewritten to http(s)) ───────────────────────

describe("parseServerConfig: ws_url — back-compat scheme rewrite", () => {
  it("rewrites wss:// to https:// and stores as httpUrl", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: wss://stamp-cli-production.up.railway.app
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "https://stamp-cli-production.up.railway.app");
  });

  it("rewrites ws:// to http:// and stores as httpUrl", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: ws://localhost:8080
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "http://localhost:8080");
  });

  it("rejects a non-ws scheme on the legacy ws_url key", () => {
    const raw = `
host: stamp.example.com
port: 2222
ws_url: https://example.com
`;
    assert.throws(
      () => parseServerConfig(raw, "<test>"),
      /ws_url.*must start with 'ws:\/\/' or 'wss:\/\/'/,
    );
  });

  it("http_url wins when both http_url and ws_url are present", () => {
    const raw = `
host: stamp.example.com
port: 2222
http_url: https://canonical.example.com
ws_url: wss://legacy.example.com
`;
    const cfg = parseServerConfig(raw, "<test>");
    assert.equal(cfg.httpUrl, "https://canonical.example.com");
  });
});

// ─── parseServerFlag: httpUrl is always undefined ─────────────────────

describe("parseServerFlag: httpUrl is always undefined", () => {
  it("parseServerFlag leaves httpUrl undefined (host:port can't express it)", () => {
    const cfg = parseServerFlag("stamp.example.com:2222");
    assert.equal(cfg.httpUrl, undefined);
  });
});
