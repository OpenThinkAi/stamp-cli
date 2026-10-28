/**
 * AGT-2240 — unit tests for the pr_url ↔ repo binding check shared by the
 * stamp-pr-opened broker and the `stamp pr listen` listener.
 */
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { checkPrUrlBinding, parseGithubPrUrl } from "../src/lib/prUrlBinding.ts";

describe("parseGithubPrUrl", () => {
  it("parses a canonical github.com PR URL", () => {
    assert.deepEqual(parseGithubPrUrl("https://github.com/acme/widget/pull/42"), {
      owner: "acme",
      repo: "widget",
      number: 42,
    });
  });

  it("accepts a mixed-case host", () => {
    assert.ok(parseGithubPrUrl("https://GitHub.com/acme/widget/pull/1"));
  });

  for (const bad of [
    "",
    "-H",
    "--hostname=evil",
    "http://github.com/acme/widget/pull/1",
    "https://evil.example/acme/widget/pull/1",
    "https://github.com.evil.example/acme/widget/pull/1",
    "https://user@github.com/acme/widget/pull/1",
    "https://github.com:443/acme/widget/pull/1",
    "https://github.com/acme/widget/pull/1?x=1",
    "https://github.com/acme/widget/pull/1#frag",
    "https://github.com/acme/widget/pull/1/files",
    "https://github.com/acme/widget/pull/0",
    "https://github.com/acme/widget/issues/1",
    "https://github.com/../widget/pull/1",
    "https://github.com/acme/../pull/1",
    "https://github.com/acme/widget/pull/1\n",
  ]) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      assert.equal(parseGithubPrUrl(bad), null);
    });
  }
});

describe("checkPrUrlBinding", () => {
  it("ok when owner/repo match exactly", () => {
    const r = checkPrUrlBinding("https://github.com/acme/widget/pull/42", "acme/widget");
    assert.equal(r.ok, true);
  });

  it("ok when owner/repo match case-insensitively (GitHub names are case-insensitive)", () => {
    const r = checkPrUrlBinding("https://github.com/Acme/Widget/pull/42", "acme/widget");
    assert.equal(r.ok, true);
  });

  it("rejects a PR in a different repo of the same owner", () => {
    const r = checkPrUrlBinding("https://github.com/acme/other/pull/42", "acme/widget");
    assert.equal(r.ok, false);
  });

  it("rejects a PR in a different owner", () => {
    const r = checkPrUrlBinding("https://github.com/victim/widget/pull/42", "acme/widget");
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /not the authorized repo/);
  });

  it("rejects a non-github.com host even when the path matches", () => {
    const r = checkPrUrlBinding("https://ghe.example/acme/widget/pull/42", "acme/widget");
    assert.equal(r.ok, false);
  });
});
