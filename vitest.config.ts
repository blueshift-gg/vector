import { defineConfig } from "vitest/config";

export default defineConfig({
  // @solana/web3.js@3.0.0-rc.0's bundled lib references a `__VERSION__`
  // global that the package expects its consumers' bundlers to inline.
  // Vitest's esbuild step doesn't perform that substitution by default,
  // so we provide it here. Stringified so it lands as a literal.
  define: {
    __VERSION__: JSON.stringify("3.0.0-rc.0"),
  },
  test: {
    testTimeout: 30_000,
    hookTimeout: 60_000,
    // Per-scheme test files (ed25519/eip191/secp256k1/falcon512/hawk512) are
    // independent — each owns its own PDA — so they run concurrently against
    // the single shared validator.
  },
});
