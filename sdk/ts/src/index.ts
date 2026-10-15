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

export * from "./schemes/falcon512.js";
export * from "./schemes/mldsa44.js";
