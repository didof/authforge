import { ConfigurationError } from "./errors.js";

const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
const base32UpperAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function randomBytes(size: number): Uint8Array {
  if (size < 1) {
    throw new ConfigurationError("Random byte size must be greater than zero.");
  }
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function encodeHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function encodeBase32LowerNoPadding(bytes: Uint8Array): string {
  return encodeBase32(bytes, base32Alphabet);
}

export function encodeBase32UpperNoPadding(bytes: Uint8Array): string {
  return encodeBase32(bytes, base32UpperAlphabet);
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function decodeBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

export async function sha256Hex(value: string | Uint8Array): Promise<string> {
  return encodeHex(await digest("SHA-256", value));
}

export async function sha1Hex(value: string | Uint8Array): Promise<string> {
  return encodeHex(await digest("SHA-1", value));
}

async function digest(
  algorithm: AlgorithmIdentifier,
  value: string | Uint8Array,
): Promise<Uint8Array> {
  const data =
    typeof value === "string" ? new TextEncoder().encode(value) : value;
  const buffer = data.buffer.slice(
    data.byteOffset,
    data.byteOffset + data.byteLength,
  ) as ArrayBuffer;
  const digestBuffer = await crypto.subtle.digest(algorithm, buffer);
  return new Uint8Array(digestBuffer);
}

function encodeBase32(bytes: Uint8Array, alphabet: string): string {
  let output = "";
  let bits = 0;
  let value = 0;

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}
