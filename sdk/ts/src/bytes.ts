/** Byte helpers shared by the SDK. Internal: not exported from the package. */
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";

export { concatBytes };

export function sha256(...parts: Uint8Array[]): Uint8Array {
  return nobleSha256(parts.length === 1 ? parts[0] : concatBytes(...parts));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function writeU16LE(buf: Uint8Array, value: number, offset: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

export function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

export function writeU64LE(buf: Uint8Array, value: bigint, offset: number): void {
  for (let i = 0; i < 8; i++) {
    buf[offset + i] = Number((value >> BigInt(8 * i)) & 0xffn);
  }
}

export function readU64LE(buf: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buf[offset + i]);
  return value;
}

export const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** Length of the `validUntil` that starts `advance` data: a slot (u64 LE). */
export const VALID_UNTIL_LEN = 8;

/** A `validUntil` that never expires: `u64::MAX`. */
export const NEVER_EXPIRES = 0xffff_ffff_ffff_ffffn;

/** `validUntil` as the 8 bytes the digest and the instruction data carry. */
export function validUntilBytes(validUntil: bigint | number = NEVER_EXPIRES): Uint8Array {
  const value = BigInt(validUntil);
  if (value < 0n || value > NEVER_EXPIRES) throw new Error("validUntil must fit a u64");
  const bytes = new Uint8Array(VALID_UNTIL_LEN);
  writeU64LE(bytes, value, 0);
  return bytes;
}
