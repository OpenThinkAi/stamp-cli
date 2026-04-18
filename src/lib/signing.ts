import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

/**
 * Ed25519 signing. Per RFC 8032, Ed25519 signatures commit to the message
 * directly — no pre-hashing, no padding. Node's crypto.sign/verify accept
 * `null` as the algorithm to get this mode.
 */

export function signBytes(privateKeyPem: string, data: Buffer): string {
  const key = createPrivateKey(privateKeyPem);
  const sig = sign(null, data, key);
  return sig.toString("base64");
}

export function verifyBytes(
  publicKeyPem: string,
  data: Buffer,
  signatureBase64: string,
): boolean {
  const key = createPublicKey(publicKeyPem);
  const sig = Buffer.from(signatureBase64, "base64");
  return verify(null, data, key, sig);
}
