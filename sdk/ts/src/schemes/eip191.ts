/**
 * secp256k1 + EIP-191 program: identity is the 20-byte Ethereum address;
 * the digest is wrapped in the EIP-191 personal-sign envelope before
 * signing/recovery.
 *
 * Mirrors `crates/core/src/schemes/eip191.rs`. Pulls in only
 * `@noble/curves/secp256k1` + `@noble/hashes/sha3` (keccak).
 */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

import { Scheme, findVectorPda } from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";
import { Vector, Artifact } from "../vector.js";
import { ChainSigner, deriveLaneSeed } from "../branching.js";
import { registerArtifactVerifier, artifactParts } from "../inspect.js";

/** secp256k1 ECDSA + EIP-191 envelope — identity is the 20-byte ETH address. */
export const EIP191: Scheme = {
  programId: new Address("G6okL1MvXx7k5eytY7wRXNupXyYG1QVZW37ygAjMiTTu"),
  signatureLen: 65,
  identityLen: 20,
  storedIdentityLen: 20,
};

/** Derive the 20-byte Ethereum address from a 32-byte secp256k1 private key. */
export function ethAddressFromPrivateKey(privateKey: Uint8Array): Uint8Array {
  const pubkey = secp256k1.getPublicKey(privateKey, false); // uncompressed, 65 bytes
  const hash = keccak_256(pubkey.slice(1)); // remove 0x04 prefix
  return hash.slice(12, 32); // last 20 bytes
}

/** EIP-191 identity: the raw 20-byte ETH address. */
export function eip191Identity(privateKey: Uint8Array): Uint8Array {
  return ethAddressFromPrivateKey(privateKey);
}

/** Initialize an EIP-191 vector account. `ethAddress` is the 20-byte address. */
export function createInitializeEip191(
  payer: Address,
  ethAddress: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, EIP191, ethAddress, ethAddress);
}

/** EIP-191 personal-sign: `keccak256("\x19Ethereum Signed Message:\n32" || digest)` */
const EIP191_PREFIX = new TextEncoder().encode(
  "\x19Ethereum Signed Message:\n32"
);

function eip191Hash(digest: Uint8Array): Uint8Array {
  const buf = new Uint8Array(EIP191_PREFIX.length + digest.length);
  buf.set(EIP191_PREFIX);
  buf.set(digest, EIP191_PREFIX.length);
  return keccak_256(buf);
}

/**
 * Sign the advance digest with an EIP-191 (Ethereum-style) secp256k1 key and
 * return a ready-to-submit advance instruction.
 * @param privateKey 32-byte secp256k1 private key
 */
export function signAdvanceInstructionEip191(
  privateKey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = eip191Identity(privateKey);
  const digest = advanceVectorDigest(
    EIP191,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );

  const ethDigest = eip191Hash(digest);
  const sig = secp256k1.sign(ethDigest, privateKey);
  const sigBytes = new Uint8Array(65);
  sigBytes.set(sig.toCompactRawBytes(), 0); // r || s (64 bytes)
  sigBytes[64] = sig.recovery; // v (1 byte)

  return createAdvanceInstruction(EIP191, identity, sigBytes);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** EIP-191 (Ethereum) chain signer (32-byte secp256k1 private key). */
export function eip191ChainSigner(privateKey: Uint8Array): ChainSigner {
  return {
    scheme: EIP191,
    identity: eip191Identity(privateKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionEip191(privateKey, nonce, pre, post, feePayer),
  };
}

/** Construct an EIP-191 {@link Vector} from a 32-byte secp256k1 private key. */
export function vectorEip191(
  privateKey: Uint8Array,
  opts?: { feePayer?: Address }
): Vector {
  const signer = eip191ChainSigner(privateKey);
  const [pda] = findVectorPda(EIP191, signer.identity);
  return Vector.fromParts({
    scheme: EIP191,
    signer,
    pda,
    initIx: (payer) => createInitializeEip191(payer, signer.identity),
    feePayer: opts?.feePayer,
    deriveChild: (i) =>
      vectorEip191(deriveLaneSeed(privateKey, "eip191", i), opts),
  });
}

registerArtifactVerifier(EIP191.programId, (a: Artifact) => {
  const parts = artifactParts(a, EIP191);
  if (!parts) return false;
  try {
    const recovered = secp256k1.Signature.fromCompact(parts.signature.slice(0, 64))
      .addRecoveryBit(parts.signature[64])
      .recoverPublicKey(eip191Hash(parts.digest))
      .toRawBytes(false); // 65-byte uncompressed: 0x04 || x || y
    return bytesEqual(keccak_256(recovered.slice(1)).slice(12, 32), a.identity);
  } catch {
    return false;
  }
});
