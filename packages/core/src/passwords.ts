import { sha1Hex } from "./crypto.js";
import { type AuthResult, err, ok } from "./types.js";

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}

export interface PasswordPolicy {
  minLength?: number;
  maxLength?: number;
  rejectPwnedPasswords?: boolean;
}

export interface PasswordStrengthOptions {
  policy?: PasswordPolicy;
  fetcher?: typeof fetch;
}

export type PasswordStrengthError = "too_short" | "too_long" | "pwned";

export async function checkPasswordStrength(
  password: string,
  options: PasswordStrengthOptions = {},
): Promise<AuthResult<true, PasswordStrengthError>> {
  const policy = options.policy ?? {};
  const minLength = policy.minLength ?? 8;
  const maxLength = policy.maxLength ?? 255;

  if (password.length < minLength) {
    return err("too_short");
  }
  if (password.length > maxLength) {
    return err("too_long");
  }
  if (
    policy.rejectPwnedPasswords &&
    (await isPwnedPassword(password, options.fetcher))
  ) {
    return err("pwned");
  }
  return ok(true);
}

export async function isPwnedPassword(
  password: string,
  fetcher: typeof fetch = fetch,
): Promise<boolean> {
  const hash = (await sha1Hex(password)).toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const response = await fetcher(
    `https://api.pwnedpasswords.com/range/${prefix}`,
  );

  if (!response.ok) {
    throw new Error(
      `Have I Been Pwned request failed with status ${response.status}.`,
    );
  }

  const body = await response.text();
  return body
    .split("\n")
    .some((line) => line.trim().toUpperCase().startsWith(suffix));
}
