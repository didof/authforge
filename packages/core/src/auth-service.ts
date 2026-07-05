import {
  encodeBase32LowerNoPadding,
  randomBytes,
} from "./crypto.js";
import {
  type CreatedWebAuthnChallenge,
  WebAuthnChallengeService,
  type WebAuthnAssertionInput,
  type WebAuthnRegistrationInput,
  WebAuthnService,
  type WebAuthnVerificationError,
} from "./webauthn.js";
import {
  EmailVerificationService,
  type EmailVerificationError,
} from "./email-verification.js";
import {
  PasswordResetService,
  type CreatedPasswordResetSession,
  type PasswordResetCodeError,
  type PasswordResetValidationError,
} from "./password-reset.js";
import {
  checkPasswordStrength,
  type PasswordHasher,
  type PasswordPolicy,
  type PasswordStrengthError,
} from "./passwords.js";
import {
  RecoveryCodeService,
  type CreatedRecoveryCode,
  type RecoveryCodeResetError,
  type RotatedRecoveryCode,
} from "./recovery-codes.js";
import {
  SessionService,
  type CreatedSession,
} from "./sessions.js";
import type {
  AccountStore,
  CreateAccountError,
  StoredAccount,
  StoredEmailVerificationRequest,
  StoredTotpCredential,
  StoredWebAuthnCredential,
} from "./stores.js";
import {
  TotpService,
  type CreatedTotpCredential,
  type TotpVerificationError,
} from "./totp.js";
import {
  type AuthResult,
  type AuthUser,
  type Clock,
  err,
  ok,
  type RegisteredFactors,
  systemClock,
  type UserId,
} from "./types.js";

export interface AeonKeyServiceOptions {
  accounts: AccountStore;
  sessions: SessionService;
  passwordHasher: PasswordHasher;
  emailVerification?: EmailVerificationService;
  passwordReset?: PasswordResetService;
  totp?: TotpService;
  recoveryCodes?: RecoveryCodeService;
  webAuthn?: WebAuthnService;
  webAuthnChallenges?: WebAuthnChallengeService;
  clock?: Clock;
  accountIdGenerator?: () => UserId;
  passwordPolicy?: PasswordPolicy;
}

export interface SignupWithPasswordInput {
  email: string;
  password: string;
  username?: string | null;
  profile?: Record<string, unknown>;
  emailVerified?: boolean;
  createSession?: boolean;
}

export interface SignupWithPasswordResult {
  user: AuthUser;
  session: CreatedSession | null;
}

export type SignupWithPasswordError =
  | CreateAccountError
  | PasswordStrengthError;

export interface LoginWithPasswordInput {
  email: string;
  password: string;
  requireEmailVerified?: boolean;
}

export interface LoginWithPasswordResult {
  user: AuthUser;
  session: CreatedSession;
}

export type LoginWithPasswordError =
  | "invalid_credentials"
  | "email_not_verified";

export interface StartEmailVerificationResult {
  user: AuthUser;
  request: StoredEmailVerificationRequest;
}

export type StartEmailVerificationError =
  | "account_not_found"
  | "service_unavailable";

export interface CompleteEmailVerificationInput {
  userId: UserId;
  requestId: string;
  code: string;
}

export type CompleteEmailVerificationError =
  | EmailVerificationError
  | "account_not_found"
  | "email_changed"
  | "service_unavailable";

export interface StartPasswordResetResult {
  accountFound: boolean;
  reset: CreatedPasswordResetSession | null;
}

export interface CompletePasswordResetInput {
  token: string;
  emailCode: string;
  newPassword: string;
  totpCode?: string;
}

export interface CompletePasswordResetResult {
  user: AuthUser;
}

export type CompletePasswordResetError =
  | PasswordResetValidationError
  | PasswordResetCodeError
  | PasswordStrengthError
  | "account_not_found"
  | "invalid_totp"
  | "service_unavailable"
  | "two_factor_required";

export interface SetupTotpInput {
  userId: UserId;
  accountName?: string;
}

export interface VerifyTotpInput {
  userId: UserId;
  code: string;
  sessionId?: string;
  passwordResetSessionId?: string;
}

export interface VerifyTotpResult {
  credential: StoredTotpCredential;
  user: AuthUser;
}

export type TotpFlowError =
  | TotpVerificationError
  | "account_not_found"
  | "service_unavailable";

export interface RegisterWebAuthnCredentialResult {
  credential: StoredWebAuthnCredential;
  user: AuthUser;
}

export interface VerifyWebAuthnAssertionInput extends WebAuthnAssertionInput {
  sessionId?: string;
  passwordResetSessionId?: string;
}

export interface VerifyWebAuthnAssertionResult {
  credential: StoredWebAuthnCredential;
  user: AuthUser;
}

export type WebAuthnFlowError =
  | WebAuthnVerificationError
  | "account_not_found"
  | "service_unavailable";

export class AeonKeyService {
  private readonly accounts: AccountStore;
  private readonly sessions: SessionService;
  private readonly passwordHasher: PasswordHasher;
  private readonly emailVerification: EmailVerificationService | undefined;
  private readonly passwordReset: PasswordResetService | undefined;
  private readonly totp: TotpService | undefined;
  private readonly recoveryCodes: RecoveryCodeService | undefined;
  private readonly webAuthn: WebAuthnService | undefined;
  private readonly webAuthnChallenges: WebAuthnChallengeService | undefined;
  private readonly clock: Clock;
  private readonly accountIdGenerator: () => UserId;
  private readonly passwordPolicy: PasswordPolicy | undefined;

  constructor(options: AeonKeyServiceOptions) {
    this.accounts = options.accounts;
    this.sessions = options.sessions;
    this.passwordHasher = options.passwordHasher;
    this.emailVerification = options.emailVerification;
    this.passwordReset = options.passwordReset;
    this.totp = options.totp;
    this.recoveryCodes = options.recoveryCodes;
    this.webAuthn = options.webAuthn;
    this.webAuthnChallenges = options.webAuthnChallenges;
    this.clock = options.clock ?? systemClock;
    this.accountIdGenerator =
      options.accountIdGenerator ?? (() => generateAccountId());
    this.passwordPolicy = options.passwordPolicy;
  }

  public async signupWithPassword(
    input: SignupWithPasswordInput,
  ): Promise<AuthResult<SignupWithPasswordResult, SignupWithPasswordError>> {
    const strength = await checkPasswordStrength(
      input.password,
      this.passwordStrengthOptions(),
    );
    if (!strength.ok) {
      return strength;
    }

    const now = this.clock.now();
    const account: StoredAccount = {
      id: this.accountIdGenerator(),
      email: normalizeEmail(input.email),
      username: input.username ?? null,
      passwordHash: await this.passwordHasher.hash(input.password),
      emailVerified: input.emailVerified ?? false,
      profile: input.profile ?? {},
      createdAt: now,
      updatedAt: now,
    };

    const created = await this.accounts.createAccount(account);
    if (!created.ok) {
      return created;
    }

    const user = await this.toAuthUser(created.value);
    const session =
      input.createSession === false
        ? null
        : await this.sessions.createSession({
            userId: account.id,
            twoFactorVerified: true,
          });
    return ok({ user, session });
  }

  public async loginWithPassword(
    input: LoginWithPasswordInput,
  ): Promise<AuthResult<LoginWithPasswordResult, LoginWithPasswordError>> {
    const account = await this.accounts.getAccountByEmail(
      normalizeEmail(input.email),
    );
    if (account === null) {
      return err("invalid_credentials");
    }

    const validPassword = await this.passwordHasher.verify(
      account.passwordHash,
      input.password,
    );
    if (!validPassword) {
      return err("invalid_credentials");
    }
    if ((input.requireEmailVerified ?? false) && !account.emailVerified) {
      return err("email_not_verified");
    }

    const factors = await this.accounts.getAccountFactors(account.id);
    const user = accountToAuthUser(account, factors);
    const session = await this.sessions.createSession({
      userId: account.id,
      twoFactorVerified: !hasRegisteredFactors(factors),
    });
    return ok({ user, session });
  }

  public async logout(input: string | { sessionId: string }): Promise<void> {
    const sessionId = typeof input === "string" ? input : input.sessionId;
    await this.sessions.invalidateSession(sessionId);
  }

  public async getUser(userId: UserId): Promise<AuthUser | null> {
    const account = await this.accounts.getAccountById(userId);
    return account === null ? null : this.toAuthUser(account);
  }

  public async getUserByEmail(email: string): Promise<AuthUser | null> {
    const account = await this.accounts.getAccountByEmail(
      normalizeEmail(email),
    );
    return account === null ? null : this.toAuthUser(account);
  }

  public async startEmailVerification(
    userId: UserId,
  ): Promise<
    AuthResult<StartEmailVerificationResult, StartEmailVerificationError>
  > {
    if (this.emailVerification === undefined) {
      return err("service_unavailable");
    }
    const account = await this.accounts.getAccountById(userId);
    if (account === null) {
      return err("account_not_found");
    }

    const request = await this.emailVerification.createRequest({
      userId,
      email: account.email,
    });
    return ok({ user: await this.toAuthUser(account), request });
  }

  public async completeEmailVerification(
    input: CompleteEmailVerificationInput,
  ): Promise<AuthResult<AuthUser, CompleteEmailVerificationError>> {
    if (this.emailVerification === undefined) {
      return err("service_unavailable");
    }
    const account = await this.accounts.getAccountById(input.userId);
    if (account === null) {
      return err("account_not_found");
    }

    const verified = await this.emailVerification.verifyCode(
      input.userId,
      input.requestId,
      input.code,
    );
    if (!verified.ok) {
      return verified;
    }
    if (verified.value.email !== account.email) {
      return err("email_changed");
    }

    await this.accounts.setAccountEmailVerified(
      account.id,
      true,
      this.clock.now(),
    );
    const updated = await this.accounts.getAccountById(account.id);
    if (updated === null) {
      return err("account_not_found");
    }
    return ok(await this.toAuthUser(updated));
  }

  public async startPasswordReset(
    email: string,
  ): Promise<AuthResult<StartPasswordResetResult, "service_unavailable">> {
    if (this.passwordReset === undefined) {
      return err("service_unavailable");
    }
    const account = await this.accounts.getAccountByEmail(
      normalizeEmail(email),
    );
    if (account === null) {
      return ok({ accountFound: false, reset: null });
    }

    await this.passwordReset.invalidateUserSessions(account.id);
    const reset = await this.passwordReset.createSession({
      userId: account.id,
      email: account.email,
    });
    return ok({ accountFound: true, reset });
  }

  public async completePasswordReset(
    input: CompletePasswordResetInput,
  ): Promise<AuthResult<CompletePasswordResetResult, CompletePasswordResetError>> {
    if (this.passwordReset === undefined) {
      return err("service_unavailable");
    }

    const strength = await checkPasswordStrength(
      input.newPassword,
      this.passwordStrengthOptions(),
    );
    if (!strength.ok) {
      return strength;
    }

    const token = await this.passwordReset.validateToken(input.token);
    if (!token.ok) {
      return token;
    }

    const emailCode = await this.passwordReset.verifyEmailCode(
      token.value.id,
      input.emailCode,
    );
    if (!emailCode.ok) {
      return emailCode;
    }

    const account = await this.accounts.getAccountById(emailCode.value.userId);
    if (account === null) {
      return err("account_not_found");
    }

    const factors = await this.accounts.getAccountFactors(account.id);
    let twoFactorVerified = emailCode.value.twoFactorVerified;
    if (!twoFactorVerified && input.totpCode !== undefined && factors.totp) {
      if (this.totp === undefined) {
        return err("service_unavailable");
      }
      const totp = await this.totp.verifyCode(account.id, input.totpCode);
      if (!totp.ok) {
        return err("invalid_totp");
      }
      twoFactorVerified = true;
      await this.passwordReset.setTwoFactorVerified(emailCode.value.id);
    }

    if (hasRegisteredFactors(factors) && !twoFactorVerified) {
      return err("two_factor_required");
    }

    await this.accounts.updateAccountPassword(
      account.id,
      await this.passwordHasher.hash(input.newPassword),
      this.clock.now(),
    );
    await this.sessions.invalidateUserSessions(account.id);
    await this.passwordReset.invalidateUserSessions(account.id);

    const updated = await this.accounts.getAccountById(account.id);
    if (updated === null) {
      return err("account_not_found");
    }
    return ok({ user: await this.toAuthUser(updated) });
  }

  public async setupTotp(
    input: SetupTotpInput,
  ): Promise<AuthResult<CreatedTotpCredential, TotpFlowError>> {
    if (this.totp === undefined) {
      return err("service_unavailable");
    }
    const account = await this.accounts.getAccountById(input.userId);
    if (account === null) {
      return err("account_not_found");
    }

    return ok(
      await this.totp.createCredential({
        userId: input.userId,
        accountName: input.accountName ?? account.email,
      }),
    );
  }

  public async verifyTotp(
    input: VerifyTotpInput,
  ): Promise<AuthResult<VerifyTotpResult, TotpFlowError>> {
    if (this.totp === undefined) {
      return err("service_unavailable");
    }
    const account = await this.accounts.getAccountById(input.userId);
    if (account === null) {
      return err("account_not_found");
    }

    const verified = await this.totp.verifyCode(input.userId, input.code);
    if (!verified.ok) {
      return verified;
    }

    if (input.sessionId !== undefined) {
      await this.sessions.setTwoFactorVerified(input.sessionId);
    }
    if (
      input.passwordResetSessionId !== undefined &&
      this.passwordReset !== undefined
    ) {
      await this.passwordReset.setTwoFactorVerified(
        input.passwordResetSessionId,
      );
    }

    return ok({
      credential: verified.value,
      user: await this.toAuthUser(account),
    });
  }

  public async createRecoveryCode(
    userId: UserId,
  ): Promise<
    AuthResult<CreatedRecoveryCode, "account_not_found" | "service_unavailable">
  > {
    if (this.recoveryCodes === undefined) {
      return err("service_unavailable");
    }
    if ((await this.accounts.getAccountById(userId)) === null) {
      return err("account_not_found");
    }
    return ok(await this.recoveryCodes.createRecoveryCode(userId));
  }

  public async resetSecondFactorsWithRecoveryCode(
    userId: UserId,
    recoveryCode: string,
  ): Promise<
    AuthResult<
      RotatedRecoveryCode,
      RecoveryCodeResetError | "account_not_found" | "service_unavailable"
    >
  > {
    if (this.recoveryCodes === undefined) {
      return err("service_unavailable");
    }
    if ((await this.accounts.getAccountById(userId)) === null) {
      return err("account_not_found");
    }
    return this.recoveryCodes.resetSecondFactors(userId, recoveryCode);
  }

  public async createWebAuthnChallenge(): Promise<
    AuthResult<CreatedWebAuthnChallenge, "service_unavailable">
  > {
    if (this.webAuthnChallenges === undefined) {
      return err("service_unavailable");
    }
    return ok(await this.webAuthnChallenges.createChallenge());
  }

  public async registerWebAuthnCredential(
    input: WebAuthnRegistrationInput,
  ): Promise<
    AuthResult<RegisterWebAuthnCredentialResult, WebAuthnFlowError>
  > {
    if (this.webAuthn === undefined) {
      return err("service_unavailable");
    }
    const account = await this.accounts.getAccountById(input.userId);
    if (account === null) {
      return err("account_not_found");
    }
    const credential = await this.webAuthn.registerCredential(input);
    if (!credential.ok) {
      return credential;
    }
    return ok({
      credential: credential.value,
      user: await this.toAuthUser(account),
    });
  }

  public async verifyWebAuthnAssertion(
    input: VerifyWebAuthnAssertionInput,
  ): Promise<AuthResult<VerifyWebAuthnAssertionResult, WebAuthnFlowError>> {
    if (this.webAuthn === undefined) {
      return err("service_unavailable");
    }
    const credential = await this.webAuthn.verifyAssertion(input);
    if (!credential.ok) {
      return credential;
    }

    if (input.sessionId !== undefined) {
      await this.sessions.setTwoFactorVerified(input.sessionId);
    }
    if (
      input.passwordResetSessionId !== undefined &&
      this.passwordReset !== undefined
    ) {
      await this.passwordReset.setTwoFactorVerified(
        input.passwordResetSessionId,
      );
    }

    const account = await this.accounts.getAccountById(credential.value.userId);
    if (account === null) {
      return err("account_not_found");
    }
    return ok({
      credential: credential.value,
      user: await this.toAuthUser(account),
    });
  }

  private async toAuthUser(account: StoredAccount): Promise<AuthUser> {
    return accountToAuthUser(
      account,
      await this.accounts.getAccountFactors(account.id),
    );
  }

  private passwordStrengthOptions(): { policy?: PasswordPolicy } {
    return this.passwordPolicy === undefined
      ? {}
      : { policy: this.passwordPolicy };
  }
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function generateAccountId(bytes = 15): string {
  return encodeBase32LowerNoPadding(randomBytes(bytes));
}

export function accountToAuthUser(
  account: StoredAccount,
  factors: RegisteredFactors,
): AuthUser {
  const user: AuthUser = {
    id: account.id,
    email: account.email,
    emailVerified: account.emailVerified,
    factors,
  };
  if (account.username !== null) {
    user.username = account.username;
  }
  return user;
}

export function hasRegisteredFactors(factors: RegisteredFactors): boolean {
  return factors.totp || factors.passkey || factors.securityKey;
}
