import { encodeHex } from "./crypto.js";
import type {
  AccountStore,
  CreateAccountError,
  EmailVerificationStore,
  PasswordResetStore,
  RateLimitStore,
  RecoveryCodeStore,
  ReplaceRecoveryCodeInput,
  SessionStore,
  StoredAccount,
  StoredEmailVerificationRequest,
  StoredPasswordResetSession,
  StoredRateLimitBucket,
  StoredSession,
  StoredTotpCredential,
  StoredWebAuthnChallenge,
  StoredWebAuthnCredential,
  TotpCredentialStore,
  WebAuthnChallengeStore,
  WebAuthnCredentialStore,
} from "./stores.js";
import { type AuthResult, err, ok, type RegisteredFactors } from "./types.js";
import type { UserId } from "./types.js";

export interface MemoryAccountStoreOptions {
  totpCredentials?: TotpCredentialStore;
  webAuthnCredentials?: WebAuthnCredentialStore;
}

export class MemoryAccountStore implements AccountStore {
  private readonly accountsById = new Map<UserId, StoredAccount>();
  private readonly idsByEmail = new Map<string, UserId>();
  private readonly totpCredentials: TotpCredentialStore | undefined;
  private readonly webAuthnCredentials: WebAuthnCredentialStore | undefined;

  constructor(options: MemoryAccountStoreOptions = {}) {
    this.totpCredentials = options.totpCredentials;
    this.webAuthnCredentials = options.webAuthnCredentials;
  }

  public async createAccount(
    account: StoredAccount,
  ): Promise<AuthResult<StoredAccount, CreateAccountError>> {
    if (this.idsByEmail.has(account.email)) {
      return err("duplicate_email");
    }
    if (this.accountsById.has(account.id)) {
      return err("duplicate_id");
    }

    this.accountsById.set(account.id, cloneAccount(account));
    this.idsByEmail.set(account.email, account.id);
    return ok(cloneAccount(account));
  }

  public async getAccountById(userId: UserId): Promise<StoredAccount | null> {
    const account = this.accountsById.get(userId);
    return account === undefined ? null : cloneAccount(account);
  }

  public async getAccountByEmail(
    email: string,
  ): Promise<StoredAccount | null> {
    const userId = this.idsByEmail.get(email);
    if (userId === undefined) {
      return null;
    }
    return this.getAccountById(userId);
  }

  public async updateAccount(account: StoredAccount): Promise<void> {
    const current = this.accountsById.get(account.id);
    if (current !== undefined && current.email !== account.email) {
      this.idsByEmail.delete(current.email);
    }
    this.accountsById.set(account.id, cloneAccount(account));
    this.idsByEmail.set(account.email, account.id);
  }

  public async updateAccountPassword(
    userId: UserId,
    passwordHash: string,
    updatedAt: Date,
  ): Promise<void> {
    const account = this.accountsById.get(userId);
    if (account === undefined) {
      return;
    }
    this.accountsById.set(userId, {
      ...account,
      passwordHash,
      updatedAt: new Date(updatedAt),
    });
  }

  public async setAccountEmailVerified(
    userId: UserId,
    emailVerified: boolean,
    updatedAt: Date,
  ): Promise<void> {
    const account = this.accountsById.get(userId);
    if (account === undefined) {
      return;
    }
    this.accountsById.set(userId, {
      ...account,
      emailVerified,
      updatedAt: new Date(updatedAt),
    });
  }

  public async getAccountFactors(userId: UserId): Promise<RegisteredFactors> {
    const totp =
      this.totpCredentials === undefined
        ? false
        : (await this.totpCredentials.getTotpCredential(userId)) !== null;
    const passkeys =
      this.webAuthnCredentials === undefined
        ? []
        : await this.webAuthnCredentials.listUserCredentials(userId, "passkey");
    const securityKeys =
      this.webAuthnCredentials === undefined
        ? []
        : await this.webAuthnCredentials.listUserCredentials(
            userId,
            "security-key",
          );

    return {
      totp,
      passkey: passkeys.length > 0,
      securityKey: securityKeys.length > 0,
    };
  }
}

export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, StoredSession>();

  public async createSession(session: StoredSession): Promise<void> {
    this.sessions.set(session.id, cloneSession(session));
  }

  public async getSession(sessionId: string): Promise<StoredSession | null> {
    const session = this.sessions.get(sessionId);
    return session === undefined ? null : cloneSession(session);
  }

  public async updateSession(session: StoredSession): Promise<void> {
    this.sessions.set(session.id, cloneSession(session));
  }

  public async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  public async deleteUserSessions(userId: UserId): Promise<void> {
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.delete(sessionId);
      }
    }
  }
}

export class MemoryEmailVerificationStore implements EmailVerificationStore {
  private readonly requests = new Map<string, StoredEmailVerificationRequest>();

  public async createEmailVerificationRequest(
    request: StoredEmailVerificationRequest,
  ): Promise<void> {
    this.requests.set(
      emailVerificationKey(request.userId, request.id),
      cloneEmailVerificationRequest(request),
    );
  }

  public async getEmailVerificationRequest(
    userId: UserId,
    id: string,
  ): Promise<StoredEmailVerificationRequest | null> {
    const request = this.requests.get(emailVerificationKey(userId, id));
    return request === undefined
      ? null
      : cloneEmailVerificationRequest(request);
  }

  public async deleteEmailVerificationRequest(
    userId: UserId,
    id: string,
  ): Promise<void> {
    this.requests.delete(emailVerificationKey(userId, id));
  }

  public async deleteUserEmailVerificationRequests(
    userId: UserId,
  ): Promise<void> {
    const prefix = `${String(userId)}:`;
    for (const key of this.requests.keys()) {
      if (key.startsWith(prefix)) {
        this.requests.delete(key);
      }
    }
  }
}

export class MemoryPasswordResetStore implements PasswordResetStore {
  private readonly sessions = new Map<string, StoredPasswordResetSession>();

  public async createPasswordResetSession(
    session: StoredPasswordResetSession,
  ): Promise<void> {
    this.sessions.set(session.id, clonePasswordResetSession(session));
  }

  public async getPasswordResetSession(
    sessionId: string,
  ): Promise<StoredPasswordResetSession | null> {
    const session = this.sessions.get(sessionId);
    return session === undefined ? null : clonePasswordResetSession(session);
  }

  public async updatePasswordResetSession(
    session: StoredPasswordResetSession,
  ): Promise<void> {
    this.sessions.set(session.id, clonePasswordResetSession(session));
  }

  public async deletePasswordResetSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  public async deleteUserPasswordResetSessions(userId: UserId): Promise<void> {
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.delete(sessionId);
      }
    }
  }
}

export class MemoryWebAuthnChallengeStore implements WebAuthnChallengeStore {
  private readonly challenges = new Map<string, StoredWebAuthnChallenge>();

  public async createChallenge(
    challenge: StoredWebAuthnChallenge,
  ): Promise<void> {
    this.challenges.set(challenge.challengeHash, {
      ...challenge,
      expiresAt: new Date(challenge.expiresAt),
    });
  }

  public async consumeChallenge(
    challengeHash: string,
    now: Date,
  ): Promise<boolean> {
    const challenge = this.challenges.get(challengeHash);
    if (
      challenge === undefined ||
      now.getTime() >= challenge.expiresAt.getTime()
    ) {
      this.challenges.delete(challengeHash);
      return false;
    }
    this.challenges.delete(challengeHash);
    return true;
  }

  public async deleteExpiredChallenges(now: Date): Promise<void> {
    for (const [hash, challenge] of this.challenges.entries()) {
      if (now.getTime() >= challenge.expiresAt.getTime()) {
        this.challenges.delete(hash);
      }
    }
  }
}

export class MemoryRecoveryCodeStore implements RecoveryCodeStore {
  private readonly hashes = new Map<UserId, string>();

  public async setRecoveryCodeHash(
    userId: UserId,
    hash: string,
  ): Promise<void> {
    this.hashes.set(userId, hash);
  }

  public async getRecoveryCodeHash(userId: UserId): Promise<string | null> {
    return this.hashes.get(userId) ?? null;
  }

  public async replaceRecoveryCodeHashAndClearFactors(
    input: ReplaceRecoveryCodeInput,
  ): Promise<boolean> {
    const currentHash = this.hashes.get(input.userId);
    if (currentHash !== input.currentHash) {
      return false;
    }
    this.hashes.set(input.userId, input.nextHash);
    return true;
  }
}

export class MemoryTotpCredentialStore implements TotpCredentialStore {
  private readonly credentials = new Map<UserId, StoredTotpCredential>();

  public async setTotpCredential(
    credential: StoredTotpCredential,
  ): Promise<void> {
    this.credentials.set(credential.userId, cloneTotpCredential(credential));
  }

  public async getTotpCredential(
    userId: UserId,
  ): Promise<StoredTotpCredential | null> {
    const credential = this.credentials.get(userId);
    return credential === undefined ? null : cloneTotpCredential(credential);
  }

  public async deleteTotpCredential(userId: UserId): Promise<void> {
    this.credentials.delete(userId);
  }
}

export class MemoryWebAuthnCredentialStore implements WebAuthnCredentialStore {
  private readonly credentials = new Map<string, StoredWebAuthnCredential>();

  public async createCredential(
    credential: StoredWebAuthnCredential,
  ): Promise<void> {
    this.credentials.set(
      credentialKey(credential.id),
      cloneCredential(credential),
    );
  }

  public async getCredential(
    id: Uint8Array,
  ): Promise<StoredWebAuthnCredential | null> {
    const credential = this.credentials.get(credentialKey(id));
    return credential === undefined ? null : cloneCredential(credential);
  }

  public async getUserCredential(
    userId: UserId,
    id: Uint8Array,
  ): Promise<StoredWebAuthnCredential | null> {
    const credential = this.credentials.get(credentialKey(id));
    if (credential === undefined || credential.userId !== userId) {
      return null;
    }
    return cloneCredential(credential);
  }

  public async listUserCredentials(
    userId: UserId,
    kind?: StoredWebAuthnCredential["kind"],
  ): Promise<StoredWebAuthnCredential[]> {
    return Array.from(this.credentials.values())
      .filter(
        (credential) =>
          credential.userId === userId &&
          (kind === undefined || credential.kind === kind),
      )
      .map(cloneCredential);
  }

  public async deleteUserCredential(
    userId: UserId,
    id: Uint8Array,
  ): Promise<boolean> {
    const key = credentialKey(id);
    const credential = this.credentials.get(key);
    if (credential === undefined || credential.userId !== userId) {
      return false;
    }
    this.credentials.delete(key);
    return true;
  }
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly buckets = new Map<string, StoredRateLimitBucket>();

  public async getRateLimitBucket(
    name: string,
    key: string,
  ): Promise<StoredRateLimitBucket | null> {
    const bucket = this.buckets.get(rateLimitBucketKey(name, key));
    return bucket === undefined ? null : cloneRateLimitBucket(bucket);
  }

  public async setRateLimitBucket(
    bucket: StoredRateLimitBucket,
  ): Promise<void> {
    this.buckets.set(rateLimitBucketKey(bucket.name, bucket.key), {
      ...bucket,
      updatedAt: new Date(bucket.updatedAt),
      expiresAt: new Date(bucket.expiresAt),
    });
  }

  public async deleteRateLimitBucket(name: string, key: string): Promise<void> {
    this.buckets.delete(rateLimitBucketKey(name, key));
  }

  public async deleteExpiredRateLimitBuckets(now: Date): Promise<void> {
    for (const [key, bucket] of this.buckets.entries()) {
      if (now.getTime() >= bucket.expiresAt.getTime()) {
        this.buckets.delete(key);
      }
    }
  }
}

export interface MemoryAuthStores {
  accounts: MemoryAccountStore;
  sessions: MemorySessionStore;
  emailVerifications: MemoryEmailVerificationStore;
  passwordResets: MemoryPasswordResetStore;
  recoveryCodes: MemoryRecoveryCodeStore;
  totpCredentials: MemoryTotpCredentialStore;
  webAuthnChallenges: MemoryWebAuthnChallengeStore;
  webAuthnCredentials: MemoryWebAuthnCredentialStore;
  rateLimits: MemoryRateLimitStore;
}

export function createMemoryAuthStores(): MemoryAuthStores {
  const totpCredentials = new MemoryTotpCredentialStore();
  const webAuthnCredentials = new MemoryWebAuthnCredentialStore();
  return {
    accounts: new MemoryAccountStore({
      totpCredentials,
      webAuthnCredentials,
    }),
    sessions: new MemorySessionStore(),
    emailVerifications: new MemoryEmailVerificationStore(),
    passwordResets: new MemoryPasswordResetStore(),
    recoveryCodes: new MemoryRecoveryCodeStore(),
    totpCredentials,
    webAuthnChallenges: new MemoryWebAuthnChallengeStore(),
    webAuthnCredentials,
    rateLimits: new MemoryRateLimitStore(),
  };
}

function emailVerificationKey(userId: UserId, id: string): string {
  return `${String(userId)}:${id}`;
}

function credentialKey(id: Uint8Array): string {
  return encodeHex(id);
}

function rateLimitBucketKey(name: string, key: string): string {
  return `${name}:${key}`;
}

function cloneAccount(account: StoredAccount): StoredAccount {
  return {
    ...account,
    profile: cloneProfile(account.profile),
    createdAt: new Date(account.createdAt),
    updatedAt: new Date(account.updatedAt),
  };
}

function cloneSession(session: StoredSession): StoredSession {
  return {
    ...session,
    expiresAt: new Date(session.expiresAt),
  };
}

function cloneEmailVerificationRequest(
  request: StoredEmailVerificationRequest,
): StoredEmailVerificationRequest {
  return {
    ...request,
    expiresAt: new Date(request.expiresAt),
  };
}

function clonePasswordResetSession(
  session: StoredPasswordResetSession,
): StoredPasswordResetSession {
  return {
    ...session,
    expiresAt: new Date(session.expiresAt),
  };
}

function cloneCredential(
  credential: StoredWebAuthnCredential,
): StoredWebAuthnCredential {
  return {
    ...credential,
    id: new Uint8Array(credential.id),
    publicKey: new Uint8Array(credential.publicKey),
    createdAt: new Date(credential.createdAt),
  };
}

function cloneTotpCredential(
  credential: StoredTotpCredential,
): StoredTotpCredential {
  return {
    ...credential,
    key: new Uint8Array(credential.key),
    createdAt: new Date(credential.createdAt),
  };
}

function cloneRateLimitBucket(
  bucket: StoredRateLimitBucket,
): StoredRateLimitBucket {
  return {
    ...bucket,
    updatedAt: new Date(bucket.updatedAt),
    expiresAt: new Date(bucket.expiresAt),
  };
}

function cloneProfile(
  profile: Record<string, unknown>,
): Record<string, unknown> {
  return JSON.parse(JSON.stringify(profile)) as Record<string, unknown>;
}
