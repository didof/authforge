import {
  encodeBase32LowerNoPadding,
  randomBytes,
  sha256Hex,
} from "./crypto.js";
import { constantTimeStringEqual, generateOtp } from "./otp.js";
import type {
  PasswordResetStore,
  StoredPasswordResetSession,
} from "./stores.js";
import {
  type AuthResult,
  err,
  ok,
  type Clock,
  type UserId,
  systemClock,
} from "./types.js";

export interface PasswordResetServiceOptions {
  store: PasswordResetStore;
  clock?: Clock;
  tokenBytes?: number;
  expiresInSeconds?: number;
}

export interface CreatePasswordResetInput {
  userId: UserId;
  email: string;
}

export interface CreatedPasswordResetSession {
  token: string;
  session: StoredPasswordResetSession;
}

export type PasswordResetValidationError = "expired" | "not_found";
export type PasswordResetCodeError =
  PasswordResetValidationError | "invalid_code";

export class PasswordResetService {
  private readonly store: PasswordResetStore;
  private readonly clock: Clock;
  private readonly tokenBytes: number;
  private readonly expiresInSeconds: number;

  constructor(options: PasswordResetServiceOptions) {
    this.store = options.store;
    this.clock = options.clock ?? systemClock;
    this.tokenBytes = options.tokenBytes ?? 20;
    this.expiresInSeconds = options.expiresInSeconds ?? 60 * 10;
  }

  public async createSession(
    input: CreatePasswordResetInput,
  ): Promise<CreatedPasswordResetSession> {
    const token = encodeBase32LowerNoPadding(randomBytes(this.tokenBytes));
    const session: StoredPasswordResetSession = {
      id: await sha256Hex(token),
      userId: input.userId,
      email: input.email,
      code: generateOtp(),
      expiresAt: new Date(
        this.clock.now().getTime() + this.expiresInSeconds * 1000,
      ),
      emailVerified: false,
      twoFactorVerified: false,
    };
    await this.store.createPasswordResetSession(session);
    return { token, session };
  }

  public async validateToken(
    token: string,
  ): Promise<
    AuthResult<StoredPasswordResetSession, PasswordResetValidationError>
  > {
    const session = await this.store.getPasswordResetSession(
      await sha256Hex(token),
    );
    if (session === null) {
      return err("not_found");
    }
    if (this.clock.now().getTime() >= session.expiresAt.getTime()) {
      await this.store.deletePasswordResetSession(session.id);
      return err("expired");
    }
    return ok(session);
  }

  public async verifyEmailCode(
    sessionId: string,
    code: string,
  ): Promise<AuthResult<StoredPasswordResetSession, PasswordResetCodeError>> {
    const session = await this.store.getPasswordResetSession(sessionId);
    if (session === null) {
      return err("not_found");
    }
    if (this.clock.now().getTime() >= session.expiresAt.getTime()) {
      await this.store.deletePasswordResetSession(session.id);
      return err("expired");
    }
    if (!constantTimeStringEqual(session.code, code)) {
      return err("invalid_code");
    }
    const verified = { ...session, emailVerified: true };
    await this.store.updatePasswordResetSession(verified);
    return ok(verified);
  }

  public async setTwoFactorVerified(sessionId: string): Promise<void> {
    const session = await this.store.getPasswordResetSession(sessionId);
    if (session === null) {
      return;
    }
    await this.store.updatePasswordResetSession({
      ...session,
      twoFactorVerified: true,
    });
  }

  public async invalidateUserSessions(userId: UserId): Promise<void> {
    await this.store.deleteUserPasswordResetSessions(userId);
  }
}
