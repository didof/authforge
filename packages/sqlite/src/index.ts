import type Database from "better-sqlite3";
import {
  err,
  ok,
  type AccountStore,
  type AuthResult,
  type CreateAccountError,
  EmailVerificationStore,
  PasswordResetStore,
  RateLimitStore,
  type RegisteredFactors,
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
  UserId,
} from "@aeonkey/core";

export function createSqliteAuthSchema(db: Database.Database): void {
  db.exec(`
CREATE TABLE IF NOT EXISTS aeonkey_account (
  id TEXT NOT NULL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  username TEXT,
  password_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL,
  profile TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS aeonkey_account_email_idx ON aeonkey_account(email);

CREATE TABLE IF NOT EXISTS aeonkey_session (
  id TEXT NOT NULL PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  two_factor_verified INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS aeonkey_session_user_id_idx ON aeonkey_session(user_id);

CREATE TABLE IF NOT EXISTS aeonkey_email_verification_request (
  id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (id, user_id)
);

CREATE INDEX IF NOT EXISTS aeonkey_email_verification_user_id_idx
ON aeonkey_email_verification_request(user_id);

CREATE TABLE IF NOT EXISTS aeonkey_password_reset_session (
  id TEXT NOT NULL PRIMARY KEY,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  email_verified INTEGER NOT NULL,
  two_factor_verified INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS aeonkey_password_reset_user_id_idx
ON aeonkey_password_reset_session(user_id);

CREATE TABLE IF NOT EXISTS aeonkey_recovery_code (
  user_id TEXT NOT NULL PRIMARY KEY,
  hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS aeonkey_totp_credential (
  user_id TEXT NOT NULL PRIMARY KEY,
  key BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS aeonkey_webauthn_challenge (
  challenge_hash TEXT NOT NULL PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS aeonkey_webauthn_credential (
  id BLOB NOT NULL PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  algorithm_id INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  kind TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS aeonkey_webauthn_credential_user_id_idx
ON aeonkey_webauthn_credential(user_id);

CREATE TABLE IF NOT EXISTS aeonkey_rate_limit_bucket (
  name TEXT NOT NULL,
  key TEXT NOT NULL,
  count INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (name, key)
);

CREATE INDEX IF NOT EXISTS aeonkey_rate_limit_expires_at_idx
ON aeonkey_rate_limit_bucket(expires_at);
`);
}

export class SqliteAuthStore
  implements
    AccountStore,
    SessionStore,
    EmailVerificationStore,
    PasswordResetStore,
    RecoveryCodeStore,
    TotpCredentialStore,
    WebAuthnChallengeStore,
    WebAuthnCredentialStore,
    RateLimitStore
{
  constructor(private readonly db: Database.Database) {}

  public async createAccount(
    account: StoredAccount,
  ): Promise<AuthResult<StoredAccount, CreateAccountError>> {
    if ((await this.getAccountByEmail(account.email)) !== null) {
      return err("duplicate_email");
    }
    if ((await this.getAccountById(account.id)) !== null) {
      return err("duplicate_id");
    }

    try {
      this.db
        .prepare(
          "INSERT INTO aeonkey_account (id, email, username, password_hash, email_verified, profile, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          encodeUserId(account.id),
          account.email,
          account.username,
          account.passwordHash,
          boolToInt(account.emailVerified),
          JSON.stringify(account.profile),
          toUnix(account.createdAt),
          toUnix(account.updatedAt),
        );
    } catch (error) {
      if (!isSqliteConstraintError(error)) {
        throw error;
      }
      if ((await this.getAccountByEmail(account.email)) !== null) {
        return err("duplicate_email");
      }
      return err("duplicate_id");
    }

    return ok(accountFromRow(await this.getRequiredAccountRow(account.id)));
  }

  public async getAccountById(userId: UserId): Promise<StoredAccount | null> {
    const row = this.db
      .prepare(
        "SELECT id, email, username, password_hash, email_verified, profile, created_at, updated_at FROM aeonkey_account WHERE id = ?",
      )
      .get(encodeUserId(userId)) as AccountRow | undefined;
    return row === undefined ? null : accountFromRow(row);
  }

  public async getAccountByEmail(
    email: string,
  ): Promise<StoredAccount | null> {
    const row = this.db
      .prepare(
        "SELECT id, email, username, password_hash, email_verified, profile, created_at, updated_at FROM aeonkey_account WHERE email = ?",
      )
      .get(email) as AccountRow | undefined;
    return row === undefined ? null : accountFromRow(row);
  }

  public async updateAccount(account: StoredAccount): Promise<void> {
    this.db
      .prepare(
        "UPDATE aeonkey_account SET email = ?, username = ?, password_hash = ?, email_verified = ?, profile = ?, created_at = ?, updated_at = ? WHERE id = ?",
      )
      .run(
        account.email,
        account.username,
        account.passwordHash,
        boolToInt(account.emailVerified),
        JSON.stringify(account.profile),
        toUnix(account.createdAt),
        toUnix(account.updatedAt),
        encodeUserId(account.id),
      );
  }

  public async updateAccountPassword(
    userId: UserId,
    passwordHash: string,
    updatedAt: Date,
  ): Promise<void> {
    this.db
      .prepare(
        "UPDATE aeonkey_account SET password_hash = ?, updated_at = ? WHERE id = ?",
      )
      .run(passwordHash, toUnix(updatedAt), encodeUserId(userId));
  }

  public async setAccountEmailVerified(
    userId: UserId,
    emailVerified: boolean,
    updatedAt: Date,
  ): Promise<void> {
    this.db
      .prepare(
        "UPDATE aeonkey_account SET email_verified = ?, updated_at = ? WHERE id = ?",
      )
      .run(boolToInt(emailVerified), toUnix(updatedAt), encodeUserId(userId));
  }

  public async getAccountFactors(userId: UserId): Promise<RegisteredFactors> {
    const encodedUserId = encodeUserId(userId);
    const totp = this.db
      .prepare("SELECT 1 FROM aeonkey_totp_credential WHERE user_id = ?")
      .get(encodedUserId);
    const passkey = this.db
      .prepare(
        "SELECT 1 FROM aeonkey_webauthn_credential WHERE user_id = ? AND kind = 'passkey'",
      )
      .get(encodedUserId);
    const securityKey = this.db
      .prepare(
        "SELECT 1 FROM aeonkey_webauthn_credential WHERE user_id = ? AND kind = 'security-key'",
      )
      .get(encodedUserId);

    return {
      totp: totp !== undefined,
      passkey: passkey !== undefined,
      securityKey: securityKey !== undefined,
    };
  }

  public async createSession(session: StoredSession): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_session (id, user_id, expires_at, two_factor_verified) VALUES (?, ?, ?, ?)",
      )
      .run(
        session.id,
        encodeUserId(session.userId),
        toUnix(session.expiresAt),
        boolToInt(session.twoFactorVerified),
      );
  }

  public async getSession(sessionId: string): Promise<StoredSession | null> {
    const row = this.db
      .prepare(
        "SELECT id, user_id, expires_at, two_factor_verified FROM aeonkey_session WHERE id = ?",
      )
      .get(sessionId) as SessionRow | undefined;
    return row === undefined ? null : sessionFromRow(row);
  }

  public async updateSession(session: StoredSession): Promise<void> {
    this.db
      .prepare(
        "UPDATE aeonkey_session SET user_id = ?, expires_at = ?, two_factor_verified = ? WHERE id = ?",
      )
      .run(
        encodeUserId(session.userId),
        toUnix(session.expiresAt),
        boolToInt(session.twoFactorVerified),
        session.id,
      );
  }

  public async deleteSession(sessionId: string): Promise<void> {
    this.db.prepare("DELETE FROM aeonkey_session WHERE id = ?").run(sessionId);
  }

  public async deleteUserSessions(userId: UserId): Promise<void> {
    this.db
      .prepare("DELETE FROM aeonkey_session WHERE user_id = ?")
      .run(encodeUserId(userId));
  }

  public async createEmailVerificationRequest(
    request: StoredEmailVerificationRequest,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_email_verification_request (id, user_id, email, code, expires_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(
        request.id,
        encodeUserId(request.userId),
        request.email,
        request.code,
        toUnix(request.expiresAt),
      );
  }

  public async getEmailVerificationRequest(
    userId: UserId,
    id: string,
  ): Promise<StoredEmailVerificationRequest | null> {
    const row = this.db
      .prepare(
        "SELECT id, user_id, email, code, expires_at FROM aeonkey_email_verification_request WHERE id = ? AND user_id = ?",
      )
      .get(id, encodeUserId(userId)) as EmailVerificationRow | undefined;
    return row === undefined ? null : emailVerificationFromRow(row);
  }

  public async deleteEmailVerificationRequest(
    userId: UserId,
    id: string,
  ): Promise<void> {
    this.db
      .prepare(
        "DELETE FROM aeonkey_email_verification_request WHERE id = ? AND user_id = ?",
      )
      .run(id, encodeUserId(userId));
  }

  public async deleteUserEmailVerificationRequests(
    userId: UserId,
  ): Promise<void> {
    this.db
      .prepare(
        "DELETE FROM aeonkey_email_verification_request WHERE user_id = ?",
      )
      .run(encodeUserId(userId));
  }

  public async createPasswordResetSession(
    session: StoredPasswordResetSession,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_password_reset_session (id, user_id, email, code, expires_at, email_verified, two_factor_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        session.id,
        encodeUserId(session.userId),
        session.email,
        session.code,
        toUnix(session.expiresAt),
        boolToInt(session.emailVerified),
        boolToInt(session.twoFactorVerified),
      );
  }

  public async getPasswordResetSession(
    sessionId: string,
  ): Promise<StoredPasswordResetSession | null> {
    const row = this.db
      .prepare(
        "SELECT id, user_id, email, code, expires_at, email_verified, two_factor_verified FROM aeonkey_password_reset_session WHERE id = ?",
      )
      .get(sessionId) as PasswordResetRow | undefined;
    return row === undefined ? null : passwordResetFromRow(row);
  }

  public async updatePasswordResetSession(
    session: StoredPasswordResetSession,
  ): Promise<void> {
    this.db
      .prepare(
        "UPDATE aeonkey_password_reset_session SET user_id = ?, email = ?, code = ?, expires_at = ?, email_verified = ?, two_factor_verified = ? WHERE id = ?",
      )
      .run(
        encodeUserId(session.userId),
        session.email,
        session.code,
        toUnix(session.expiresAt),
        boolToInt(session.emailVerified),
        boolToInt(session.twoFactorVerified),
        session.id,
      );
  }

  public async deletePasswordResetSession(sessionId: string): Promise<void> {
    this.db
      .prepare("DELETE FROM aeonkey_password_reset_session WHERE id = ?")
      .run(sessionId);
  }

  public async deleteUserPasswordResetSessions(userId: UserId): Promise<void> {
    this.db
      .prepare("DELETE FROM aeonkey_password_reset_session WHERE user_id = ?")
      .run(encodeUserId(userId));
  }

  public async setRecoveryCodeHash(
    userId: UserId,
    hash: string,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_recovery_code (user_id, hash) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash",
      )
      .run(encodeUserId(userId), hash);
  }

  public async getRecoveryCodeHash(userId: UserId): Promise<string | null> {
    const row = this.db
      .prepare("SELECT hash FROM aeonkey_recovery_code WHERE user_id = ?")
      .get(encodeUserId(userId)) as RecoveryCodeRow | undefined;
    return row?.hash ?? null;
  }

  public async replaceRecoveryCodeHashAndClearFactors(
    input: ReplaceRecoveryCodeInput,
  ): Promise<boolean> {
    const transaction = this.db.transaction(() => {
      const result = this.db
        .prepare(
          "UPDATE aeonkey_recovery_code SET hash = ? WHERE user_id = ? AND hash = ?",
        )
        .run(input.nextHash, encodeUserId(input.userId), input.currentHash);
      if (result.changes < 1) {
        return false;
      }
      const userId = encodeUserId(input.userId);
      this.db
        .prepare(
          "UPDATE aeonkey_session SET two_factor_verified = 0 WHERE user_id = ?",
        )
        .run(userId);
      this.db
        .prepare("DELETE FROM aeonkey_totp_credential WHERE user_id = ?")
        .run(userId);
      this.db
        .prepare("DELETE FROM aeonkey_webauthn_credential WHERE user_id = ?")
        .run(userId);
      return true;
    });
    return transaction();
  }

  public async setTotpCredential(
    credential: StoredTotpCredential,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_totp_credential (user_id, key, created_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET key = excluded.key, created_at = excluded.created_at",
      )
      .run(
        encodeUserId(credential.userId),
        Buffer.from(credential.key),
        toUnix(credential.createdAt),
      );
  }

  public async getTotpCredential(
    userId: UserId,
  ): Promise<StoredTotpCredential | null> {
    const row = this.db
      .prepare(
        "SELECT user_id, key, created_at FROM aeonkey_totp_credential WHERE user_id = ?",
      )
      .get(encodeUserId(userId)) as TotpRow | undefined;
    return row === undefined ? null : totpFromRow(row);
  }

  public async deleteTotpCredential(userId: UserId): Promise<void> {
    this.db
      .prepare("DELETE FROM aeonkey_totp_credential WHERE user_id = ?")
      .run(encodeUserId(userId));
  }

  public async createChallenge(
    challenge: StoredWebAuthnChallenge,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_webauthn_challenge (challenge_hash, expires_at) VALUES (?, ?)",
      )
      .run(challenge.challengeHash, toUnix(challenge.expiresAt));
  }

  public async consumeChallenge(
    challengeHash: string,
    now: Date,
  ): Promise<boolean> {
    const transaction = this.db.transaction(() => {
      const row = this.db
        .prepare(
          "SELECT challenge_hash, expires_at FROM aeonkey_webauthn_challenge WHERE challenge_hash = ?",
        )
        .get(challengeHash) as ChallengeRow | undefined;
      if (
        row === undefined ||
        now.getTime() >= fromUnix(row.expires_at).getTime()
      ) {
        this.db
          .prepare(
            "DELETE FROM aeonkey_webauthn_challenge WHERE challenge_hash = ?",
          )
          .run(challengeHash);
        return false;
      }
      this.db
        .prepare(
          "DELETE FROM aeonkey_webauthn_challenge WHERE challenge_hash = ?",
        )
        .run(challengeHash);
      return true;
    });
    return transaction();
  }

  public async deleteExpiredChallenges(now: Date): Promise<void> {
    this.db
      .prepare("DELETE FROM aeonkey_webauthn_challenge WHERE expires_at <= ?")
      .run(toUnix(now));
  }

  public async createCredential(
    credential: StoredWebAuthnCredential,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_webauthn_credential (id, user_id, name, algorithm_id, public_key, kind, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        Buffer.from(credential.id),
        encodeUserId(credential.userId),
        credential.name,
        credential.algorithmId,
        Buffer.from(credential.publicKey),
        credential.kind,
        toUnix(credential.createdAt),
      );
  }

  public async getCredential(
    id: Uint8Array,
  ): Promise<StoredWebAuthnCredential | null> {
    const row = this.db
      .prepare(
        "SELECT id, user_id, name, algorithm_id, public_key, kind, created_at FROM aeonkey_webauthn_credential WHERE id = ?",
      )
      .get(Buffer.from(id)) as WebAuthnCredentialRow | undefined;
    return row === undefined ? null : webAuthnCredentialFromRow(row);
  }

  public async getUserCredential(
    userId: UserId,
    id: Uint8Array,
  ): Promise<StoredWebAuthnCredential | null> {
    const row = this.db
      .prepare(
        "SELECT id, user_id, name, algorithm_id, public_key, kind, created_at FROM aeonkey_webauthn_credential WHERE id = ? AND user_id = ?",
      )
      .get(Buffer.from(id), encodeUserId(userId)) as
      WebAuthnCredentialRow | undefined;
    return row === undefined ? null : webAuthnCredentialFromRow(row);
  }

  public async listUserCredentials(
    userId: UserId,
    kind?: StoredWebAuthnCredential["kind"],
  ): Promise<StoredWebAuthnCredential[]> {
    const rows =
      kind === undefined
        ? (this.db
            .prepare(
              "SELECT id, user_id, name, algorithm_id, public_key, kind, created_at FROM aeonkey_webauthn_credential WHERE user_id = ?",
            )
            .all(encodeUserId(userId)) as WebAuthnCredentialRow[])
        : (this.db
            .prepare(
              "SELECT id, user_id, name, algorithm_id, public_key, kind, created_at FROM aeonkey_webauthn_credential WHERE user_id = ? AND kind = ?",
            )
            .all(encodeUserId(userId), kind) as WebAuthnCredentialRow[]);
    return rows.map(webAuthnCredentialFromRow);
  }

  public async deleteUserCredential(
    userId: UserId,
    id: Uint8Array,
  ): Promise<boolean> {
    const result = this.db
      .prepare(
        "DELETE FROM aeonkey_webauthn_credential WHERE user_id = ? AND id = ?",
      )
      .run(encodeUserId(userId), Buffer.from(id));
    return result.changes > 0;
  }

  public async getRateLimitBucket(
    name: string,
    key: string,
  ): Promise<StoredRateLimitBucket | null> {
    const row = this.db
      .prepare(
        "SELECT name, key, count, updated_at, expires_at FROM aeonkey_rate_limit_bucket WHERE name = ? AND key = ?",
      )
      .get(name, key) as RateLimitBucketRow | undefined;
    return row === undefined ? null : rateLimitBucketFromRow(row);
  }

  public async setRateLimitBucket(
    bucket: StoredRateLimitBucket,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO aeonkey_rate_limit_bucket (name, key, count, updated_at, expires_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(name, key) DO UPDATE SET count = excluded.count, updated_at = excluded.updated_at, expires_at = excluded.expires_at",
      )
      .run(
        bucket.name,
        bucket.key,
        bucket.count,
        toUnix(bucket.updatedAt),
        toUnix(bucket.expiresAt),
      );
  }

  public async deleteRateLimitBucket(
    name: string,
    key: string,
  ): Promise<void> {
    this.db
      .prepare(
        "DELETE FROM aeonkey_rate_limit_bucket WHERE name = ? AND key = ?",
      )
      .run(name, key);
  }

  public async deleteExpiredRateLimitBuckets(now: Date): Promise<void> {
    this.db
      .prepare("DELETE FROM aeonkey_rate_limit_bucket WHERE expires_at <= ?")
      .run(toUnix(now));
  }

  private async getRequiredAccountRow(userId: UserId): Promise<AccountRow> {
    const row = this.db
      .prepare(
        "SELECT id, email, username, password_hash, email_verified, profile, created_at, updated_at FROM aeonkey_account WHERE id = ?",
      )
      .get(encodeUserId(userId)) as AccountRow | undefined;
    if (row === undefined) {
      throw new Error("Expected account row to exist after insert.");
    }
    return row;
  }
}

function encodeUserId(userId: UserId): string {
  return JSON.stringify({ type: typeof userId, value: userId });
}

function decodeUserId(encoded: string): UserId {
  const parsed = JSON.parse(encoded) as {
    type: "string" | "number";
    value: string | number;
  };
  return parsed.value;
}

function toUnix(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

function fromUnix(value: number): Date {
  return new Date(value * 1000);
}

function boolToInt(value: boolean): number {
  return value ? 1 : 0;
}

function intToBool(value: number): boolean {
  return value === 1;
}

function accountFromRow(row: AccountRow): StoredAccount {
  return {
    id: decodeUserId(row.id),
    email: row.email,
    username: row.username,
    passwordHash: row.password_hash,
    emailVerified: intToBool(row.email_verified),
    profile: parseProfile(row.profile),
    createdAt: fromUnix(row.created_at),
    updatedAt: fromUnix(row.updated_at),
  };
}

function sessionFromRow(row: SessionRow): StoredSession {
  return {
    id: row.id,
    userId: decodeUserId(row.user_id),
    expiresAt: fromUnix(row.expires_at),
    twoFactorVerified: intToBool(row.two_factor_verified),
  };
}

function emailVerificationFromRow(
  row: EmailVerificationRow,
): StoredEmailVerificationRequest {
  return {
    id: row.id,
    userId: decodeUserId(row.user_id),
    email: row.email,
    code: row.code,
    expiresAt: fromUnix(row.expires_at),
  };
}

function passwordResetFromRow(
  row: PasswordResetRow,
): StoredPasswordResetSession {
  return {
    id: row.id,
    userId: decodeUserId(row.user_id),
    email: row.email,
    code: row.code,
    expiresAt: fromUnix(row.expires_at),
    emailVerified: intToBool(row.email_verified),
    twoFactorVerified: intToBool(row.two_factor_verified),
  };
}

function totpFromRow(row: TotpRow): StoredTotpCredential {
  return {
    userId: decodeUserId(row.user_id),
    key: new Uint8Array(row.key),
    createdAt: fromUnix(row.created_at),
  };
}

function webAuthnCredentialFromRow(
  row: WebAuthnCredentialRow,
): StoredWebAuthnCredential {
  return {
    id: new Uint8Array(row.id),
    userId: decodeUserId(row.user_id),
    name: row.name,
    algorithmId: row.algorithm_id,
    publicKey: new Uint8Array(row.public_key),
    kind: row.kind,
    createdAt: fromUnix(row.created_at),
  };
}

function rateLimitBucketFromRow(
  row: RateLimitBucketRow,
): StoredRateLimitBucket {
  return {
    name: row.name,
    key: row.key,
    count: row.count,
    updatedAt: fromUnix(row.updated_at),
    expiresAt: fromUnix(row.expires_at),
  };
}

function parseProfile(profile: string): Record<string, unknown> {
  const parsed = JSON.parse(profile) as unknown;
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    return {};
  }
  return parsed as Record<string, unknown>;
}

function isSqliteConstraintError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === "SQLITE_CONSTRAINT_UNIQUE"
  );
}

interface AccountRow {
  id: string;
  email: string;
  username: string | null;
  password_hash: string;
  email_verified: number;
  profile: string;
  created_at: number;
  updated_at: number;
}

interface SessionRow {
  id: string;
  user_id: string;
  expires_at: number;
  two_factor_verified: number;
}

interface EmailVerificationRow {
  id: string;
  user_id: string;
  email: string;
  code: string;
  expires_at: number;
}

interface PasswordResetRow {
  id: string;
  user_id: string;
  email: string;
  code: string;
  expires_at: number;
  email_verified: number;
  two_factor_verified: number;
}

interface RecoveryCodeRow {
  hash: string;
}

interface TotpRow {
  user_id: string;
  key: Buffer;
  created_at: number;
}

interface ChallengeRow {
  challenge_hash: string;
  expires_at: number;
}

interface WebAuthnCredentialRow {
  id: Buffer;
  user_id: string;
  name: string;
  algorithm_id: number;
  public_key: Buffer;
  kind: "passkey" | "security-key";
  created_at: number;
}

interface RateLimitBucketRow {
  name: string;
  key: string;
  count: number;
  updated_at: number;
  expires_at: number;
}
