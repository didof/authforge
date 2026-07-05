import type { AuthResult, RegisteredFactors, UserId } from "./types.js";

export interface StoredAccount {
  id: UserId;
  email: string;
  username: string | null;
  passwordHash: string;
  emailVerified: boolean;
  profile: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export type CreateAccountError = "duplicate_email" | "duplicate_id";

export interface AccountStore {
  createAccount(
    account: StoredAccount,
  ): Promise<AuthResult<StoredAccount, CreateAccountError>>;
  getAccountById(userId: UserId): Promise<StoredAccount | null>;
  getAccountByEmail(email: string): Promise<StoredAccount | null>;
  updateAccount(account: StoredAccount): Promise<void>;
  updateAccountPassword(
    userId: UserId,
    passwordHash: string,
    updatedAt: Date,
  ): Promise<void>;
  setAccountEmailVerified(
    userId: UserId,
    emailVerified: boolean,
    updatedAt: Date,
  ): Promise<void>;
  getAccountFactors(userId: UserId): Promise<RegisteredFactors>;
}

export interface StoredSession {
  id: string;
  userId: UserId;
  expiresAt: Date;
  twoFactorVerified: boolean;
}

export interface SessionStore {
  createSession(session: StoredSession): Promise<void>;
  getSession(sessionId: string): Promise<StoredSession | null>;
  updateSession(session: StoredSession): Promise<void>;
  deleteSession(sessionId: string): Promise<void>;
  deleteUserSessions(userId: UserId): Promise<void>;
}

export interface StoredEmailVerificationRequest {
  id: string;
  userId: UserId;
  email: string;
  code: string;
  expiresAt: Date;
}

export interface EmailVerificationStore {
  createEmailVerificationRequest(
    request: StoredEmailVerificationRequest,
  ): Promise<void>;
  getEmailVerificationRequest(
    userId: UserId,
    id: string,
  ): Promise<StoredEmailVerificationRequest | null>;
  deleteEmailVerificationRequest(userId: UserId, id: string): Promise<void>;
  deleteUserEmailVerificationRequests(userId: UserId): Promise<void>;
}

export interface StoredPasswordResetSession {
  id: string;
  userId: UserId;
  email: string;
  code: string;
  expiresAt: Date;
  emailVerified: boolean;
  twoFactorVerified: boolean;
}

export interface PasswordResetStore {
  createPasswordResetSession(
    session: StoredPasswordResetSession,
  ): Promise<void>;
  getPasswordResetSession(
    sessionId: string,
  ): Promise<StoredPasswordResetSession | null>;
  updatePasswordResetSession(
    session: StoredPasswordResetSession,
  ): Promise<void>;
  deletePasswordResetSession(sessionId: string): Promise<void>;
  deleteUserPasswordResetSessions(userId: UserId): Promise<void>;
}

export interface ReplaceRecoveryCodeInput {
  userId: UserId;
  currentHash: string;
  nextHash: string;
}

export interface RecoveryCodeStore {
  setRecoveryCodeHash(userId: UserId, hash: string): Promise<void>;
  getRecoveryCodeHash(userId: UserId): Promise<string | null>;
  replaceRecoveryCodeHashAndClearFactors(
    input: ReplaceRecoveryCodeInput,
  ): Promise<boolean>;
}

export interface StoredTotpCredential {
  userId: UserId;
  key: Uint8Array;
  createdAt: Date;
}

export interface TotpCredentialStore {
  setTotpCredential(credential: StoredTotpCredential): Promise<void>;
  getTotpCredential(userId: UserId): Promise<StoredTotpCredential | null>;
  deleteTotpCredential(userId: UserId): Promise<void>;
}

export interface StoredWebAuthnChallenge {
  challengeHash: string;
  expiresAt: Date;
}

export interface WebAuthnChallengeStore {
  createChallenge(challenge: StoredWebAuthnChallenge): Promise<void>;
  consumeChallenge(challengeHash: string, now: Date): Promise<boolean>;
  deleteExpiredChallenges(now: Date): Promise<void>;
}

export interface StoredWebAuthnCredential {
  id: Uint8Array;
  userId: UserId;
  name: string;
  algorithmId: number;
  publicKey: Uint8Array;
  kind: "passkey" | "security-key";
  createdAt: Date;
}

export interface WebAuthnCredentialStore {
  createCredential(credential: StoredWebAuthnCredential): Promise<void>;
  getCredential(id: Uint8Array): Promise<StoredWebAuthnCredential | null>;
  getUserCredential(
    userId: UserId,
    id: Uint8Array,
  ): Promise<StoredWebAuthnCredential | null>;
  listUserCredentials(
    userId: UserId,
    kind?: StoredWebAuthnCredential["kind"],
  ): Promise<StoredWebAuthnCredential[]>;
  deleteUserCredential(userId: UserId, id: Uint8Array): Promise<boolean>;
}

export interface StoredRateLimitBucket {
  name: string;
  key: string;
  count: number;
  updatedAt: Date;
  expiresAt: Date;
}

export interface RateLimitStore {
  getRateLimitBucket(
    name: string,
    key: string,
  ): Promise<StoredRateLimitBucket | null>;
  setRateLimitBucket(bucket: StoredRateLimitBucket): Promise<void>;
  deleteRateLimitBucket(name: string, key: string): Promise<void>;
  deleteExpiredRateLimitBuckets(now: Date): Promise<void>;
}
