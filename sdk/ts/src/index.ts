/**
 * Vector SDK — core (scheme-agnostic) entrypoint.
 *
 * The default import is light: it pulls no per-scheme crypto. Construct a
 * `Vector` from its scheme's subpath so you only install/bundle the crypto you
 * use, e.g. `import { vectorEd25519 } from "vector-sdk/ed25519"`. Importing a
 * scheme subpath also registers its offline verifier with {@link verifyArtifact}.
 *
 * Per-scheme subpaths — each exports its `Scheme` const, identity/init/sign
 * builders, a `vector<Scheme>(...)` constructor, and a `<scheme>ChainSigner`:
 *
 * - `vector-sdk/ed25519`
 * - `vector-sdk/secp256k1`
 * - `vector-sdk/eip191`
 * - `vector-sdk/falcon512`
 * - `vector-sdk/hawk512`
 *
 * The low-level chain engine is at `vector-sdk/branching`.
 */
export * from "./scheme.js";
export * from "./instructions.js";
export * from "./digest.js";
export * from "./vector.js";
export * from "./inspect.js";
export * from "./wallet.js";
export * from "./migrate.js";
export * from "./scan.js";
