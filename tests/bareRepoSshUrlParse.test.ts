/**
 * Tests for parseBareRepoSshUrl — the inverse of bareRepoSshUrl, used by
 * `stamp push --resync-mirror` to derive the server connection + repo
 * name from the repo's own origin remote.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  bareRepoSshUrl,
  parseBareRepoSshUrl,
} from "../src/lib/serverConfig.ts";

describe("parseBareRepoSshUrl", () => {
  it("round-trips what bareRepoSshUrl emits", () => {
    const cfg = {
      user: "git",
      host: "roundhouse.proxy.rlwy.net",
      port: 45830,
      repoRootPrefix: "/srv/git",
    };
    const url = bareRepoSshUrl(cfg, "site-template");
    const parsed = parseBareRepoSshUrl(url);
    assert.deepEqual(parsed, {
      user: "git",
      host: "roundhouse.proxy.rlwy.net",
      port: 45830,
      repoName: "site-template",
    });
  });

  it("takes the repo name from the LAST path segment", () => {
    const parsed = parseBareRepoSshUrl(
      "ssh://git@stamp.example.com:2222/data/repos/nested/think-cli.git",
    );
    assert.equal(parsed?.repoName, "think-cli");
  });

  it("tolerates surrounding whitespace and a trailing slash", () => {
    const parsed = parseBareRepoSshUrl(
      "  ssh://git@host1:22/srv/git/x.git/\n",
    );
    assert.equal(parsed?.repoName, "x");
    assert.equal(parsed?.port, 22);
  });

  it("rejects everything that is not a stamp-server-shaped ssh URL", () => {
    for (const url of [
      "git@github.com:MicroMediaSites/site-template.git", // scp-style forge URL
      "https://github.com/MicroMediaSites/site-template.git",
      "ssh://git@host/srv/git/x.git", // no explicit port
      "ssh://git@host:0/srv/git/x.git", // port out of range
      "ssh://git@host:70000/srv/git/x.git",
      "ssh://git@host:22/srv/git/x", // no .git suffix
      "ssh://git@host:22/x.git; rm -rf /", // junk after suffix
      "ssh://-flag@host:22/srv/git/x.git", // flag-shaped user
      "",
    ]) {
      assert.equal(parseBareRepoSshUrl(url), null, `should reject: ${url}`);
    }
  });
});
