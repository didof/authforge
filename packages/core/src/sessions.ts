import {
  encodeBase32LowerNoPadding,
  randomBytes,
  sha256Hex,
} from "./crypto.js";
import type { SessionStore, StoredSession } from "./stores.js";
import {
  type AuthResult,
  err,
  ok,
  type Clock,
  type UserId,
  systemClock,
} from "./types.js";

export interface SessionServiceOptions {
  store: SessionStore;
  clock?: Clock;
  tokenBytes?: number;
  expiresInSeconds?: number;
  refreshWindowSeconds?: number;
}

export interface CreateSessionInput {
  userId: UserId;
  twoFactorVerified?: boolean;
}

export interface CreatedSession {
  token: string;
  session: StoredSession;
}

export type SessionValidationError = "expired" | "not_found";

export class SessionService {
  private readonly store: SessionStore;
  private readonly clock: Clock;
  private readonly tokenBytes: number;
  private readonly expiresInSeconds: number;
  private readonly refreshWindowSeconds: number;

  constructor(options: SessionServiceOptions) {
    this.store = options.store;
    this.clock = options.clock ?? systemClock;
    this.tokenBytes = options.tokenBytes ?? 20;
    this.expiresInSeconds = options.expiresInSeconds ?? 60 * 60 * 24 * 30;
    this.refreshWindowSeconds =
      options.refreshWindowSeconds ?? 60 * 60 * 24 * 15;
  }

  public generateToken(): string {
    return encodeBase32LowerNoPadding(randomBytes(this.tokenBytes));
  }

  public async createSession(
    input: CreateSessionInput,
  ): Promise<CreatedSession> {
    const token = this.generateToken();
    const session: StoredSession = {
      id: await this.hashToken(token),
      userId: input.userId,
      expiresAt: this.expiresAt(this.expiresInSeconds),
      twoFactorVerified: input.twoFactorVerified ?? false,
    };
    await this.store.createSession(session);
    return { token, session };
  }

  public async validateToken(
    token: string,
  ): Promise<AuthResult<StoredSession, SessionValidationError>> {
    const sessionId = await this.hashToken(token);
    const session = await this.store.getSession(sessionId);
    if (session === null) {
      return err("not_found");
    }

    if (this.clock.now().getTime() >= session.expiresAt.getTime()) {
      await this.store.deleteSession(session.id);
      return err("expired");
    }

    if (this.shouldRefresh(session)) {
      const refreshed = {
        ...session,
        expiresAt: this.expiresAt(this.expiresInSeconds),
      };
      await this.store.updateSession(refreshed);
      return ok(refreshed);
    }

    return ok(session);
  }

  public async setTwoFactorVerified(sessionId: string): Promise<void> {
    const session = await this.store.getSession(sessionId);
    if (session === null) {
      return;
    }
    await this.store.updateSession({ ...session, twoFactorVerified: true });
  }

  public async invalidateSession(sessionId: string): Promise<void> {
    await this.store.deleteSession(sessionId);
  }

  public async invalidateUserSessions(userId: UserId): Promise<void> {
    await this.store.deleteUserSessions(userId);
  }

  public async hashToken(token: string): Promise<string> {
    return sha256Hex(token);
  }

  private shouldRefresh(session: StoredSession): boolean {
    const refreshAt =
      session.expiresAt.getTime() - this.refreshWindowSeconds * 1000;
    return this.clock.now().getTime() >= refreshAt;
  }

  private expiresAt(seconds: number): Date {
    return new Date(this.clock.now().getTime() + seconds * 1000);
  }
}
