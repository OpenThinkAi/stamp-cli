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
    },
    format: ["cjs"],
    target: "node22",
    clean: false, // don't wipe the ESM build
    sourcemap: true,
    shims: false,
    splitting: false,
    banner: { js: "#!/usr/bin/env node" },
    noExternal: ["yaml"],
    outExtension: () => ({ js: ".cjs" }),
  },
]);
