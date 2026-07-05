import { encodeBase32LowerNoPadding, randomBytes } from "./crypto.js";
import { constantTimeStringEqual, generateOtp } from "./otp.js";
import type {
  EmailVerificationStore,
  StoredEmailVerificationRequest,
} from "./stores.js";
import {
  type AuthResult,
  err,
  ok,
  type Clock,
  type UserId,
  systemClock,
} from "./types.js";

export interface EmailVerificationServiceOptions {
  store: EmailVerificationStore;
  clock?: Clock;
  expiresInSeconds?: number;
  idBytes?: number;
}

export interface CreateEmailVerificationInput {
  userId: UserId;
  email: string;
}

export type EmailVerificationError = "expired" | "invalid_code" | "not_found";

export class EmailVerificationService {
  private readonly store: EmailVerificationStore;
  private readonly clock: Clock;
  private readonly expiresInSeconds: number;
  private readonly idBytes: number;

  constructor(options: EmailVerificationServiceOptions) {
    this.store = options.store;
    this.clock = options.clock ?? systemClock;
    this.expiresInSeconds = options.expiresInSeconds ?? 60 * 10;
    this.idBytes = options.idBytes ?? 20;
  }

  public async createRequest(
    input: CreateEmailVerificationInput,
  ): Promise<StoredEmailVerificationRequest> {
    await this.store.deleteUserEmailVerificationRequests(input.userId);
    const request: StoredEmailVerificationRequest = {
      id: encodeBase32LowerNoPadding(randomBytes(this.idBytes)),
      userId: input.userId,
      email: input.email,
      code: generateOtp(),
      expiresAt: new Date(
        this.clock.now().getTime() + this.expiresInSeconds * 1000,
      ),
    };
    await this.store.createEmailVerificationRequest(request);
    return request;
  }

  public async verifyCode(
    userId: UserId,
    requestId: string,
    code: string,
  ): Promise<
    AuthResult<StoredEmailVerificationRequest, EmailVerificationError>
  > {
    const request = await this.store.getEmailVerificationRequest(
      userId,
      requestId,
    );
    if (request === null) {
      return err("not_found");
    }
    if (this.clock.now().getTime() >= request.expiresAt.getTime()) {
      await this.store.deleteEmailVerificationRequest(userId, requestId);
      return err("expired");
    }
    if (!constantTimeStringEqual(request.code, code)) {
      return err("invalid_code");
    }
    await this.store.deleteEmailVerificationRequest(userId, requestId);
    return ok(request);
  }
}
