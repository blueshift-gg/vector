/**
 * Client helpers for the Vector program: build its instructions and compute
 * the digests it verifies.
 *
 * One program serves every signing scheme. An account is named by its scheme
 * and its identity, the key it was created with: the PDA seeds are
 * `["vector", [scheme], sha256(identity)]`.
 *
 * Everything is exported here. Each scheme can also be imported on its own,
 * which pulls in only that scheme's crypto:
 *
 * ```ts
 * import { ED25519, signAdvanceInstructionEd25519 } from "vector-sdk";
 * import { ED25519, signAdvanceInstructionEd25519 } from "vector-sdk/ed25519";
 * ```
 */

export * from "./scheme.js";
export * from "./instructions.js";
export * from "./digest.js";
export * from "./verify.js";

export * from "./schemes/ed25519.js";
export * from "./schemes/eip191.js";
export * from "./schemes/secp256k1.js";
export * from "./schemes/winternitz.js";
export * from "./schemes/xmss.js";

// Falcon: re-export only the scheme-unique symbols. The wire-size
// constants come from `./scheme.js` above (re-exporting them again via
// this module would make them ambiguous and silently drop them from the
// flat barrel).
export {
  FALCON512,
  FALCON_SECRET_KEY_LEN,
  falcon512Keygen,
  falcon512PublicKey,
  createInitializeFalcon512,
  signAdvanceInstructionFalcon512,
} from "./schemes/falcon512.js";
export type { Falcon512Keypair } from "./schemes/falcon512.js";

// ML-DSA-44: as for Falcon, the size constants come from `./scheme.js`.
export {
  MLDSA44,
  MLDSA44_SECRET_KEY_LEN,
  MLDSA44_EXPAND_STEPS,
  MLDSA44_EXPAND_DISCRIMINATOR,
  MLDSA44_STORED_IDENTITY_LEN,
  mldsa44Identity,
  mldsa44Keygen,
  mldsa44PublicKey,
  createInitializeMlDsa44,
  createExpandMlDsa44,
  createRegisterMlDsa44Instructions,
  signAdvanceInstructionMlDsa44,
} from "./schemes/mldsa44.js";
export type { MlDsa44Keypair } from "./schemes/mldsa44.js";
