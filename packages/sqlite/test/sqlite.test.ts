import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  EmailVerificationService,
  PasswordResetService,
  PersistentRefillingTokenBucket,
  SessionService,
  type StoredAccount,
  TotpService,
  WebAuthnChallengeService,
  generateTotpCode,
} from "@aeonkey/core";
import { SqliteAuthStore, createSqliteAuthSchema } from "../src/index.js";

describe("SqliteAuthStore", () => {
  it("stores accounts and handles duplicate email addresses", async () => {
    const store = createStore();
    const account = createAccount();

    const created = await store.createAccount(account);
    expect(created.ok).toBe(true);
    expect(await store.getAccountById("user-1")).toMatchObject({
      email: "user@example.com",
      username: "user",
      emailVerified: false,
    });
    expect(await store.getAccountByEmail("user@example.com")).toMatchObject({
      id: "user-1",
    });

    const duplicate = await store.createAccount({
      ...createAccount("user-2"),
      email: "user@example.com",
    });
    expect(duplicate).toEqual({ ok: false, error: "duplicate_email" });

    await store.updateAccountPassword(
      "user-1",
      "new-hash",
      new Date("2026-01-02T00:00:00.000Z"),
    );
    await store.setAccountEmailVerified(
      "user-1",
      true,
      new Date("2026-01-02T00:00:00.000Z"),
    );
    expect(await store.getAccountById("user-1")).toMatchObject({
      passwordHash: "new-hash",
      emailVerified: true,
    });
  });

  it("stores sessions durably", async () => {
    const store = createStore();
    const sessions = new SessionService({ store });

    const created = await sessions.createSession({
      userId: 123,
      twoFactorVerified: true,
    });
    const result = await sessions.validateToken(created.token);

    expect(result.ok).toBe(true);
    expect(result.ok ? result.value.userId : null).toBe(123);
    expect(result.ok ? result.value.twoFactorVerified : false).toBe(true);
  });

  it("stores email verification and password reset sessions", async () => {
    const store = createStore();
    const emailVerification = new EmailVerificationService({ store });
    const passwordReset = new PasswordResetService({ store });

    const emailRequest = await emailVerification.createRequest({
      userId: "user-1",
      email: "user@example.com",
    });
    expect(
      await emailVerification.verifyCode(
        "user-1",
        emailRequest.id,
        emailRequest.code,
      ),
    ).toMatchObject({ ok: true });

    const reset = await passwordReset.createSession({
      userId: "user-1",
      email: "user@example.com",
    });
    expect(
      await passwordReset.verifyEmailCode(reset.session.id, reset.session.code),
    ).toMatchObject({ ok: true });
  });

  it("stores TOTP credentials and WebAuthn challenges", async () => {
    const store = createStore();
    const totp = new TotpService({
      store,
      issuer: "AeonKey",
      window: 0,
    });
    const credential = await totp.createCredential({
      userId: "user-1",
      accountName: "user@example.com",
    });
    const code = await generateTotpCode(credential.credential.key);
    expect(await totp.verifyCode("user-1", code)).toMatchObject({ ok: true });

    const challenges = new WebAuthnChallengeService({ store });
    const challenge = await challenges.createChallenge();
    expect(
      await challenges.consumeChallenge(challenge.challenge),
    ).toMatchObject({ ok: true });
    expect(await challenges.consumeChallenge(challenge.challenge)).toEqual({
      ok: false,
      error: "expired_or_not_found",
    });
  });

  it("reports registered factor state from durable factor tables", async () => {
    const store = createStore();
    await store.createAccount(createAccount());

    expect(await store.getAccountFactors("user-1")).toEqual({
      totp: false,
      passkey: false,
      securityKey: false,
    });

    await store.setTotpCredential({
      userId: "user-1",
      key: new Uint8Array([1, 2, 3]),
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    await store.createCredential({
      id: new Uint8Array([4, 5, 6]),
      userId: "user-1",
      name: "Laptop",
      algorithmId: -7,
      publicKey: new Uint8Array([7, 8, 9]),
      kind: "passkey",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });

    expect(await store.getAccountFactors("user-1")).toEqual({
      totp: true,
      passkey: true,
      securityKey: false,
    });
  });

  it("persists rate-limit buckets", async () => {
    const store = createStore();
    const bucket = new PersistentRefillingTokenBucket({
      store,
      name: "login",
      max: 1,
      refillIntervalSeconds: 60,
    });

    expect(await bucket.consume("ip:127.0.0.1", 1)).toBe(true);
    expect(await bucket.consume("ip:127.0.0.1", 1)).toBe(false);
    expect(await store.getRateLimitBucket("login", "ip:127.0.0.1"))
      .toMatchObject({
        count: 0,
      });
  });
});

function createStore(): SqliteAuthStore {
  const db = new Database(":memory:");
  createSqliteAuthSchema(db);
  return new SqliteAuthStore(db);
}

function createAccount(id = "user-1"): StoredAccount {
  const now = new Date("2026-01-01T00:00:00.000Z");
  return {
    id,
    email: `${id === "user-1" ? "user" : id}@example.com`,
    username: id === "user-1" ? "user" : id,
    passwordHash: "hash",
    emailVerified: false,
    profile: { name: "Example User" },
    createdAt: now,
    updatedAt: now,
  };
}
