import { encodeBase32UpperNoPadding, randomBytes } from "./crypto.js";
import { constantTimeStringEqual } from "./otp.js";
import type { StoredTotpCredential, TotpCredentialStore } from "./stores.js";
import {
  type AuthResult,
  type Clock,
  err,
  ok,
  systemClock,
  type UserId,
} from "./types.js";

export interface TotpServiceOptions {
  store: TotpCredentialStore;
  issuer: string;
  clock?: Clock;
  digits?: number;
  periodSeconds?: number;
  window?: number;
  secretBytes?: number;
}

export interface CreateTotpCredentialInput {
  userId: UserId;
  accountName: string;
  key?: Uint8Array;
}

export interface CreatedTotpCredential {
  credential: StoredTotpCredential;
  secret: string;
  otpauthUrl: string;
}

export type TotpVerificationError = "not_found" | "invalid_code";

export class TotpService {
  private readonly store: TotpCredentialStore;
  private readonly clock: Clock;
  private readonly issuer: string;
  private readonly digits: number;
  private readonly periodSeconds: number;
  private readonly window: number;
  private readonly secretBytes: number;

  constructor(options: TotpServiceOptions) {
    this.store = options.store;
    this.clock = options.clock ?? systemClock;
    this.issuer = options.issuer;
    this.digits = options.digits ?? 6;
    this.periodSeconds = options.periodSeconds ?? 30;
    this.window = options.window ?? 1;
    this.secretBytes = options.secretBytes ?? 20;
  }

  public async createCredential(
    input: CreateTotpCredentialInput,
  ): Promise<CreatedTotpCredential> {
    const key = input.key ?? randomBytes(this.secretBytes);
    const credential: StoredTotpCredential = {
      userId: input.userId,
      key,
      createdAt: this.clock.now(),
    };
    await this.store.setTotpCredential(credential);
    const secret = encodeBase32UpperNoPadding(key);
    return {
      credential,
      secret,
      otpauthUrl: createTotpUri({
        issuer: this.issuer,
        accountName: input.accountName,
        secret,
        digits: this.digits,
        periodSeconds: this.periodSeconds,
      }),
    };
  }

  public async verifyCode(
    userId: UserId,
    code: string,
  ): Promise<AuthResult<StoredTotpCredential, TotpVerificationError>> {
    const credential = await this.store.getTotpCredential(userId);
    if (credential === null) {
      return err("not_found");
    }

    const now = this.clock.now();
    for (let offset = -this.window; offset <= this.window; offset += 1) {
      const expected = await generateTotpCode(credential.key, {
        at: new Date(now.getTime() + offset * this.periodSeconds * 1000),
        digits: this.digits,
        periodSeconds: this.periodSeconds,
      });
      if (constantTimeStringEqual(expected, code)) {
        return ok(credential);
      }
    }

    return err("invalid_code");
  }

  public async deleteCredential(userId: UserId): Promise<void> {
    await this.store.deleteTotpCredential(userId);
  }
}

export interface GenerateTotpCodeOptions {
  at?: Date;
  digits?: number;
  periodSeconds?: number;
}

export async function generateTotpCode(
  key: Uint8Array,
  options: GenerateTotpCodeOptions = {},
): Promise<string> {
  const at = options.at ?? new Date();
  const digits = options.digits ?? 6;
  const periodSeconds = options.periodSeconds ?? 30;
  const counter = Math.floor(at.getTime() / 1000 / periodSeconds);
  const counterBytes = new ArrayBuffer(8);
  new DataView(counterBytes).setBigUint64(0, BigInt(counter));

  const keyBuffer = key.buffer.slice(
    key.byteOffset,
    key.byteOffset + key.byteLength,
  ) as ArrayBuffer;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const hmac = new Uint8Array(
    await crypto.subtle.sign("HMAC", cryptoKey, counterBytes),
  );
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export interface CreateTotpUriInput {
  issuer: string;
  accountName: string;
  secret: string;
  digits?: number;
  periodSeconds?: number;
}

export function createTotpUri(input: CreateTotpUriInput): string {
  const label = `${input.issuer}:${input.accountName}`;
  const params = new URLSearchParams({
    secret: input.secret,
    issuer: input.issuer,
    algorithm: "SHA1",
    digits: String(input.digits ?? 6),
    period: String(input.periodSeconds ?? 30),
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}
