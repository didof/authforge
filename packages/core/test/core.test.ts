import { describe, expect, it } from "vitest";
import {
  AuthForgeService,
  EmailVerificationService,
  EncryptedTotpCredentialStore,
  ExpiringTokenBucket,
  MemoryRateLimitStore,
  MemoryEmailVerificationStore,
  MemoryPasswordResetStore,
  MemorySessionStore,
  MemoryWebAuthnChallengeStore,
  PasswordResetService,
  PersistentRefillingTokenBucket,
  RecoveryCodeService,
  RefillingTokenBucket,
  SessionService,
  Throttler,
  TotpService,
  createMemoryAuthStores,
  WebAuthnChallengeService,
  generateTotpCode,
  getSecondFactorState,
  type AuthUser,
  type Clock,
} from "../src/index.js";
import type { PasswordHasher } from "../src/index.js";

class MutableClock implements Clock {
  public current: Date;

  constructor(date: Date) {
    this.current = date;
  }

  public now(): Date {
    return new Date(this.current);
  }

  public advance(seconds: number): void {
    this.current = new Date(this.current.getTime() + seconds * 1000);
  }
}

class TestPasswordHasher implements PasswordHasher {
  public async hash(password: string): Promise<string> {
    return `hash:${password}`;
  }

  public async verify(hash: string, password: string): Promise<boolean> {
    return hash === `hash:${password}`;
  }
}

function createTestAuthForge(clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"))) {
  const stores = createMemoryAuthStores();
  const sessions = new SessionService({ store: stores.sessions, clock });
  const emailVerification = new EmailVerificationService({
    store: stores.emailVerifications,
    clock,
  });
  const passwordReset = new PasswordResetService({
    store: stores.passwordResets,
    clock,
  });
  const totp = new TotpService({
    store: stores.totpCredentials,
    issuer: "AuthForge",
    clock,
    window: 0,
  });
  const recoveryCodes = new RecoveryCodeService({
    store: stores.recoveryCodes,
    hasher: new TestPasswordHasher(),
  });
  const auth = new AuthForgeService({
    accounts: stores.accounts,
    sessions,
    passwordHasher: new TestPasswordHasher(),
    emailVerification,
    passwordReset,
    totp,
    recoveryCodes,
    clock,
    accountIdGenerator: () => "user-1",
  });
  return { auth, clock, emailVerification, passwordReset, sessions, stores, totp };
}

describe("AuthForgeService", () => {
  it("signs up password accounts and rejects duplicate email addresses", async () => {
    const { auth, stores } = createTestAuthForge();

    const signup = await auth.signupWithPassword({
      email: "USER@example.com",
      password: "correct horse battery staple",
      username: "user",
      profile: { name: "Example User" },
      createSession: false,
    });

    expect(signup.ok).toBe(true);
    expect(signup.ok ? signup.value.user.email : null).toBe(
      "user@example.com",
    );
    expect(await stores.accounts.getAccountByEmail("user@example.com"))
      .toMatchObject({
        username: "user",
        emailVerified: false,
      });

    const duplicate = await auth.signupWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
    });
    expect(duplicate).toEqual({ ok: false, error: "duplicate_email" });
  });

  it("logs in with password and marks sessions as requiring 2FA when factors exist", async () => {
    const { auth, clock } = createTestAuthForge();
    const signup = await auth.signupWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
      createSession: false,
    });
    expect(signup.ok).toBe(true);

    const noFactorLogin = await auth.loginWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
    });
    expect(noFactorLogin.ok).toBe(true);
    expect(
      noFactorLogin.ok
        ? noFactorLogin.value.session.session.twoFactorVerified
        : false,
    ).toBe(true);

    const setup = await auth.setupTotp({
      userId: "user-1",
      accountName: "user@example.com",
    });
    expect(setup.ok).toBe(true);

    const factorLogin = await auth.loginWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
    });
    expect(factorLogin.ok).toBe(true);
    expect(
      factorLogin.ok ? factorLogin.value.user.factors.totp : false,
    ).toBe(true);
    expect(
      factorLogin.ok ? factorLogin.value.session.session.twoFactorVerified : true,
    ).toBe(false);

    const code = await generateTotpCode(
      setup.ok ? setup.value.credential.key : new Uint8Array(),
      { at: clock.now() },
    );
    const verified = await auth.verifyTotp({
      userId: "user-1",
      code,
      sessionId: factorLogin.ok ? factorLogin.value.session.session.id : "",
    });
    expect(verified.ok).toBe(true);
  });

  it("starts and completes email verification", async () => {
    const { auth, stores } = createTestAuthForge();
    await auth.signupWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
      createSession: false,
    });

    const started = await auth.startEmailVerification("user-1");
    expect(started.ok).toBe(true);

    const completed = await auth.completeEmailVerification({
      userId: "user-1",
      requestId: started.ok ? started.value.request.id : "",
      code: started.ok ? started.value.request.code : "",
    });
    expect(completed.ok).toBe(true);
    expect(await stores.accounts.getAccountById("user-1")).toMatchObject({
      emailVerified: true,
    });
  });

  it("completes password reset and invalidates old sessions", async () => {
    const { auth, stores } = createTestAuthForge();
    const signup = await auth.signupWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
    });
    expect(signup.ok).toBe(true);

    const oldSessionId = signup.ok
      ? signup.value.session?.session.id
      : undefined;
    const reset = await auth.startPasswordReset("user@example.com");
    expect(reset.ok).toBe(true);
    expect(reset.ok ? reset.value.accountFound : false).toBe(true);

    const completed = await auth.completePasswordReset({
      token: reset.ok && reset.value.reset !== null ? reset.value.reset.token : "",
      emailCode:
        reset.ok && reset.value.reset !== null
          ? reset.value.reset.session.code
          : "",
      newPassword: "new correct horse battery staple",
    });
    expect(completed.ok).toBe(true);
    if (oldSessionId !== undefined) {
      expect(await stores.sessions.getSession(oldSessionId)).toBeNull();
    }

    const oldPassword = await auth.loginWithPassword({
      email: "user@example.com",
      password: "correct horse battery staple",
    });
    expect(oldPassword).toEqual({ ok: false, error: "invalid_credentials" });

    const newPassword = await auth.loginWithPassword({
      email: "user@example.com",
      password: "new correct horse battery staple",
    });
    expect(newPassword.ok).toBe(true);
  });
});

describe("SessionService", () => {
  it("creates hashed sessions and validates the original token", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const store = new MemorySessionStore();
    const service = new SessionService({
      store,
      clock,
      expiresInSeconds: 60,
      refreshWindowSeconds: 30,
    });

    const created = await service.createSession({ userId: "user-1" });
    expect(created.session.id).not.toBe(created.token);

    const result = await service.validateToken(created.token);
    expect(result.ok).toBe(true);
    expect(result.ok ? result.value.userId : null).toBe("user-1");
  });

  it("deletes expired sessions", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const store = new MemorySessionStore();
    const service = new SessionService({
      store,
      clock,
      expiresInSeconds: 10,
    });

    const created = await service.createSession({ userId: "user-1" });
    clock.advance(11);

    const result = await service.validateToken(created.token);
    expect(result).toEqual({ ok: false, error: "expired" });
    expect(await store.getSession(created.session.id)).toBeNull();
  });
});

describe("EmailVerificationService", () => {
  it("accepts a valid code only once", async () => {
    const store = new MemoryEmailVerificationStore();
    const service = new EmailVerificationService({ store });
    const request = await service.createRequest({
      userId: "user-1",
      email: "user@example.com",
    });

    const first = await service.verifyCode("user-1", request.id, request.code);
    expect(first.ok).toBe(true);

    const second = await service.verifyCode("user-1", request.id, request.code);
    expect(second).toEqual({ ok: false, error: "not_found" });
  });
});

describe("PasswordResetService", () => {
  it("marks the reset email as verified after the correct code", async () => {
    const store = new MemoryPasswordResetStore();
    const service = new PasswordResetService({ store });
    const created = await service.createSession({
      userId: "user-1",
      email: "user@example.com",
    });

    const verified = await service.verifyEmailCode(
      created.session.id,
      created.session.code,
    );
    expect(verified.ok).toBe(true);
    expect(verified.ok ? verified.value.emailVerified : false).toBe(true);
  });
});

describe("RecoveryCodeService", () => {
  it("rotates the recovery code after a successful reset", async () => {
    const stores = await import("../src/index.js").then((module) =>
      module.createMemoryAuthStores(),
    );
    const service = new RecoveryCodeService({
      store: stores.recoveryCodes,
      hasher: new TestPasswordHasher(),
      codeBytes: 5,
    });

    const created = await service.createRecoveryCode("user-1");
    const reset = await service.resetSecondFactors("user-1", created.code);
    expect(reset.ok).toBe(true);

    const replay = await service.resetSecondFactors("user-1", created.code);
    expect(replay).toEqual({ ok: false, error: "invalid_code" });
  });
});

describe("TotpService", () => {
  it("creates and verifies TOTP credentials", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const stores = await import("../src/index.js").then((module) =>
      module.createMemoryAuthStores(),
    );
    const service = new TotpService({
      store: stores.totpCredentials,
      issuer: "AuthForge",
      clock,
      window: 0,
    });
    const created = await service.createCredential({
      userId: "user-1",
      accountName: "user@example.com",
    });
    const code = await generateTotpCode(created.credential.key, {
      at: clock.now(),
    });

    expect(created.otpauthUrl.startsWith("otpauth://totp/")).toBe(true);
    expect(await service.verifyCode("user-1", code)).toMatchObject({
      ok: true,
    });
    expect(await service.verifyCode("user-1", "000000")).toEqual({
      ok: false,
      error: "invalid_code",
    });
  });

  it("supports encrypted TOTP storage wrappers", async () => {
    const stores = await import("../src/index.js").then((module) =>
      module.createMemoryAuthStores(),
    );
    const encryptedStore = new EncryptedTotpCredentialStore({
      store: stores.totpCredentials,
      key: new Uint8Array(32).fill(7),
    });
    const service = new TotpService({
      store: encryptedStore,
      issuer: "AuthForge",
      window: 0,
    });
    const created = await service.createCredential({
      userId: "user-1",
      accountName: "user@example.com",
    });
    const rawStored = await stores.totpCredentials.getTotpCredential("user-1");
    expect(rawStored?.key).not.toEqual(created.credential.key);

    const code = await generateTotpCode(created.credential.key);
    expect(await service.verifyCode("user-1", code)).toMatchObject({
      ok: true,
    });
  });
});

describe("rate limiters", () => {
  it("persists refilling token buckets through the store interface", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const store = new MemoryRateLimitStore();
    const bucket = new PersistentRefillingTokenBucket({
      store,
      name: "login",
      max: 2,
      refillIntervalSeconds: 10,
      clock,
    });

    expect(await bucket.consume("ip", 1)).toBe(true);
    expect(await bucket.consume("ip", 1)).toBe(true);
    expect(await bucket.consume("ip", 1)).toBe(false);

    clock.advance(10);
    expect(await bucket.consume("ip", 1)).toBe(true);
  });

  it("refills token buckets over time", () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const bucket = new RefillingTokenBucket<string>(2, 10, { clock });

    expect(bucket.consume("ip", 1)).toBe(true);
    expect(bucket.consume("ip", 1)).toBe(true);
    expect(bucket.consume("ip", 1)).toBe(false);

    clock.advance(10);
    expect(bucket.consume("ip", 1)).toBe(true);
  });

  it("resets expiring buckets after the window", () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const bucket = new ExpiringTokenBucket<string>(1, 10, { clock });

    expect(bucket.consume("user", 1)).toBe(true);
    expect(bucket.consume("user", 1)).toBe(false);

    clock.advance(10);
    expect(bucket.consume("user", 1)).toBe(true);
  });

  it("allows the first throttled attempt before applying backoff", () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));
    const throttler = new Throttler<string>([10], { clock });

    expect(throttler.consume("user")).toBe(true);
    expect(throttler.consume("user")).toBe(false);

    clock.advance(10);
    expect(throttler.consume("user")).toBe(true);
  });
});

describe("second factor policy", () => {
  it("prefers passkeys, then security keys, then TOTP", () => {
    const user: AuthUser = {
      id: "user-1",
      email: "user@example.com",
      emailVerified: true,
      factors: {
        passkey: true,
        securityKey: true,
        totp: true,
      },
    };

    const state = getSecondFactorState(user, { twoFactorVerified: false });
    expect(state.method).toBe("passkey");
    expect(state.nextPath).toBe("/2fa/passkey");
  });
});

describe("WebAuthnChallengeService", () => {
  it("creates single-use challenges", async () => {
    const store = new MemoryWebAuthnChallengeStore();
    const service = new WebAuthnChallengeService({ store });
    const challenge = await service.createChallenge();

    expect((await service.consumeChallenge(challenge.challenge)).ok).toBe(true);
    expect(await service.consumeChallenge(challenge.challenge)).toEqual({
      ok: false,
      error: "expired_or_not_found",
    });
  });
});
