/**
 * Off-chain helpers for constructing Vector program instructions and
 * computing the digests the on-chain programs verify.
 *
 * Each signing scheme is its own on-chain program with its own program ID.
 * There is no on-chain scheme discriminator: the program ID identifies the
 * scheme, the account header is `nonce[32] || bump[1]` (33 bytes), and PDA
 * seeds are `["vector", identity_seed]`. A {@link Scheme} bundles what a
 * client needs to talk to a given program: its program ID, wire signature
 * length, and identity/stored-identity lengths.
 *
 * # Layout
 *
 * - `./scheme.js` — the {@link Scheme} descriptor, {@link VectorAccount}
 *   header mirror, canonical PDA derivation, and shared byte helpers.
 * - `./instructions.js` — generic builders (initialize/advance/close/
 *   withdraw, instructions-sysvar serialization).
 * - `./digest.js` — {@link advanceVectorDigest}, the value clients sign.
 * - `./schemes/*.js` — one module per program (`ed25519`, `eip191`,
 *   `falcon512`, `hawk512`, `secp256k1`): its `Scheme`/program-ID const,
 *   identity derivation, an `initialize` builder, and a signer where one
 *   exists.
 *
 * Everything is re-exported flat here, so either style works:
 *
 * ```ts
 * import { ED25519, signAdvanceInstruction } from "vector-sdk";          // flat
 * import { ED25519, signAdvanceInstruction } from "vector-sdk/ed25519";  // per-scheme
 * ```
 *
 * The Falcon/Hawk wire-size constants are owned by `./scheme.js` and
 * re-exported flat from there. `./schemes/falcon512.js` and
 * `./schemes/hawk512.js` also re-export them for their standalone subpath
 * entrypoints; to keep the flat API unambiguous they are NOT glob-exported
 * here from those modules (only the symbols unique to each scheme module
 * are).
 */

export * from "./scheme.js";
export * from "./instructions.js";
export * from "./digest.js";

export * from "./schemes/ed25519.js";
export * from "./schemes/eip191.js";
export * from "./schemes/secp256k1.js";

// Falcon/Hawk: re-export only the scheme-unique symbols. The wire-size
// constants come from `./scheme.js` above (re-exporting them again via
// these modules would make them ambiguous and silently drop them from the
// flat barrel).
export {
  FALCON512,
  FALCON_SECRET_KEY_LEN,
  falcon512Identity,
  falcon512Keygen,
  falcon512PublicKey,
  createInitializeFalcon512,
  signAdvanceInstructionFalcon512,
} from "./schemes/falcon512.js";
export {
  HAWK512,
  hawk512Identity,
  createInitializeHawk512,
} from "./schemes/hawk512.js";
