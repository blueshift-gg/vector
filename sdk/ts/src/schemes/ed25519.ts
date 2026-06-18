/**
 * Ed25519 program: identity is the 32-byte public key, verified directly
 * over the advance digest.
 *
 * Mirrors `crates/core/src/schemes/ed25519.rs`. Pulls in only
 * `@noble/curves/ed25519`.
 */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";

import { Scheme, findVectorPda } from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";
import { Vector, Artifact } from "../vector.js";
import { ChainSigner, deriveLaneSeed } from "../branching.js";
import { registerArtifactVerifier, artifactParts } from "../inspect.js";

/** Ed25519 — identity is the 32-byte public key. */
export const ED25519: Scheme = {
  programId: new Address("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV"),
  signatureLen: 64,
  identityLen: 32,
  storedIdentityLen: 32,
};

/** Ed25519 identity (32-byte public key) for a private key seed. */
export function ed25519Identity(signingKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(signingKey);
}

/** Initialize an Ed25519 vector account. `pubkey` is the 32-byte public key. */
export function createInitializeEd25519(
  payer: Address,
  pubkey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, ED25519, pubkey, pubkey);
}

/**
 * Sign the advance digest with an Ed25519 key and return a ready-to-submit
 * advance instruction.
 * @param signingKey 32-byte Ed25519 private key seed
 */
export function signAdvanceInstructionEd25519(
  signingKey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = ed25519Identity(signingKey);
  const digest = advanceVectorDigest(
    ED25519,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );
  const signature = ed25519.sign(digest, signingKey);
  return createAdvanceInstruction(ED25519, identity, signature);
}

/** Ed25519 chain signer bound to a 32-byte private-key seed. */
export function ed25519ChainSigner(signingKey: Uint8Array): ChainSigner {
  return {
    scheme: ED25519,
    identity: ed25519Identity(signingKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionEd25519(signingKey, nonce, pre, post, feePayer),
  };
}

/** Construct an Ed25519 {@link Vector} from a 32-byte private-key seed. */
export function vectorEd25519(
  signingKey: Uint8Array,
  opts?: { feePayer?: Address }
): Vector {
  const signer = ed25519ChainSigner(signingKey);
  const [pda] = findVectorPda(ED25519, signer.identity);
  return Vector.fromParts({
    scheme: ED25519,
    signer,
    pda,
    initIx: (payer) => createInitializeEd25519(payer, signer.identity),
    feePayer: opts?.feePayer,
    deriveChild: (i) =>
      vectorEd25519(deriveLaneSeed(signingKey, "ed25519", i), opts),
  });
}

registerArtifactVerifier(ED25519.programId, (a: Artifact) => {
  const parts = artifactParts(a, ED25519);
  if (!parts) return false;
  try {
    return ed25519.verify(parts.signature, parts.digest, a.identity);
  } catch {
    return false;
  }
});
