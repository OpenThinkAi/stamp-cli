import { defineConfig } from "tsup";

// Two builds:
//  - CLI: ESM, matches "type": "module" in package.json
//  - Hook: CJS, because the installed hook lives in bare repos that have
//    no package.json nearby; Node would otherwise treat .js files there as
//    CommonJS and reject the ESM `import` syntax.
export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: ["esm"],
    target: "node22",
    clean: true,
    sourcemap: true,
    shims: false,
    // Splitting ON so dynamic imports (e.g. the `stamp ui` command's lazy
    // import of ink/react via await import()) produce separate chunks. Keeps
    // the hot-path bundle small for non-ui commands.
    splitting: true,
    banner: { js: "#!/usr/bin/env node" },
    // CLI keeps yaml/commander as runtime deps (npm install provides them).
    // Bundling yaml here triggers tsup's "Dynamic require of 'process' is not
    // supported" error in ESM mode.
  },
  {
    entry: {
      "hooks/pre-receive": "src/hooks/pre-receive.ts",
      "hooks/post-receive": "src/hooks/post-receive.ts",
      // Server-side standalone scripts. Same CJS shape as the hooks for
      // the same reason: they run in /usr/local/{bin,sbin} on the server
      // image with no package.json nearby, so Node would otherwise treat
      // .js files there as CommonJS and reject ESM import syntax.
      "server/authorized-keys": "src/server/authorized-keys.ts",
      "server/seed-users": "src/server/seed-users.ts",
      "server/mint-invite": "src/server/mint-invite.ts",
      "server/start-http-server": "src/server/start-http-server.ts",
      "server/users-cli": "src/server/users-cli.ts",
      "server/bootstrap-review-key": "src/server/bootstrap-review-key.ts",
      "server/stamp-review": "src/server/stamp-review.ts",
    },
    format: ["cjs"],
    target: "node22",
    clean: false, // don't wipe the ESM build
    sourcemap: true,
    shims: false,
    splitting: false,
    banner: { js: "#!/usr/bin/env node" },
    // Bundle runtime deps the server-image .cjs scripts need at execution
    // time. The Docker runtime stage copies just the built .cjs files to
    // /usr/local/{bin,sbin}/ — no package.json or node_modules sit next to
    // them, so any require() that resolves to a node_modules package fails
    // with "Cannot find module 'X'". `noExternal` instructs tsup to inline
    // the listed packages (plus their transitive deps) into the bundle so
    // the .cjs is fully self-contained.
    //
    //   - yaml: parsed in hooks (pre-receive reads .stamp/config.yml)
    //     and several server scripts.
    //   - @anthropic-ai/sdk: invoked by stamp-review for server-attested
    //     verdicts (AGT-330). Discovered missing during the HiveDB Shape 2
    //     smoke test — `Cannot find module '@anthropic-ai/sdk'` from
    //     /usr/local/bin/stamp-review on the deployed Railway image.
    //
    // CLI (ESM) build above intentionally leaves these external — the CLI
    // ships via npm install so node_modules is present alongside dist/.
    noExternal: ["yaml", "@anthropic-ai/sdk"],
    outExtension: () => ({ js: ".cjs" }),
  },
]);
