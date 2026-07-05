import { encodeBase32UpperNoPadding, randomBytes } from "./crypto.js";

export interface OtpOptions {
  bytes?: number;
}

export function generateOtp(options: OtpOptions = {}): string {
  return encodeBase32UpperNoPadding(randomBytes(options.bytes ?? 5));
}

export function generateRecoveryCode(options: OtpOptions = {}): string {
  return encodeBase32UpperNoPadding(randomBytes(options.bytes ?? 10));
}

export function constantTimeStringEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;

  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }

  return diff === 0;
}
