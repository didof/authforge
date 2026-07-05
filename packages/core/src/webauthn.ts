import { encodeBase64Url, randomBytes, sha256Hex } from "./crypto.js";
import { ConfigurationError } from "./errors.js";
import type {
  StoredWebAuthnCredential,
  WebAuthnChallengeStore,
  WebAuthnCredentialStore,
} from "./stores.js";
import {
  type AuthResult,
  err,
  ok,
  type Clock,
  systemClock,
  type UserId,
} from "./types.js";

export interface RelyingPartyConfig {
  id: string;
  name: string;
  origins: string[];
}

export interface WebAuthnChallengeServiceOptions {
  store: WebAuthnChallengeStore;
  clock?: Clock;
  challengeBytes?: number;
  expiresInSeconds?: number;
}

export interface CreatedWebAuthnChallenge {
  challenge: Uint8Array;
  encodedChallenge: string;
  expiresAt: Date;
}

export type WebAuthnChallengeError = "expired_or_not_found";

export class WebAuthnChallengeService {
  private readonly store: WebAuthnChallengeStore;
  private readonly clock: Clock;
  private readonly challengeBytes: number;
  private readonly expiresInSeconds: number;

  constructor(options: WebAuthnChallengeServiceOptions) {
    this.store = options.store;
    this.clock = options.clock ?? systemClock;
    this.challengeBytes = options.challengeBytes ?? 20;
    this.expiresInSeconds = options.expiresInSeconds ?? 60 * 5;
  }

  public async createChallenge(): Promise<CreatedWebAuthnChallenge> {
    const challenge = randomBytes(this.challengeBytes);
    const expiresAt = new Date(
      this.clock.now().getTime() + this.expiresInSeconds * 1000,
    );
    await this.store.createChallenge({
      challengeHash: await hashChallenge(challenge),
      expiresAt,
    });
    return {
      challenge,
      encodedChallenge: encodeBase64Url(challenge),
      expiresAt,
    };
  }

  public async consumeChallenge(
    challenge: Uint8Array,
  ): Promise<AuthResult<true, WebAuthnChallengeError>> {
    const consumed = await this.store.consumeChallenge(
      await hashChallenge(challenge),
      this.clock.now(),
    );
    if (!consumed) {
      return err("expired_or_not_found");
    }
    return ok(true);
  }

  public async deleteExpiredChallenges(): Promise<void> {
    await this.store.deleteExpiredChallenges(this.clock.now());
  }
}

export interface WebAuthnRegistrationInput {
  userId: UserId;
  name: string;
  attestationObject: Uint8Array;
  clientDataJSON: Uint8Array;
  kind: StoredWebAuthnCredential["kind"];
}

export interface WebAuthnAssertionInput {
  credentialId: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  requireUserVerification?: boolean;
}

export interface VerifiedWebAuthnRegistration {
  credential: StoredWebAuthnCredential;
}

export interface VerifiedWebAuthnAssertion {
  credential: StoredWebAuthnCredential;
}

export type WebAuthnVerificationError =
  | "invalid_challenge"
  | "invalid_origin"
  | "invalid_relying_party"
  | "invalid_signature"
  | "unsupported_algorithm"
  | "credential_not_found"
  | "credential_limit_exceeded"
  | "invalid_data";

export interface WebAuthnVerifier {
  verifyRegistration(
    input: WebAuthnRegistrationInput,
    context: WebAuthnVerificationContext,
  ): Promise<
    AuthResult<VerifiedWebAuthnRegistration, WebAuthnVerificationError>
  >;
  verifyAssertion(
    input: WebAuthnAssertionInput,
    context: WebAuthnVerificationContext,
  ): Promise<AuthResult<VerifiedWebAuthnAssertion, WebAuthnVerificationError>>;
}

export interface WebAuthnVerificationContext {
  relyingParty: RelyingPartyConfig;
  challengeService: WebAuthnChallengeService;
  credentialStore: WebAuthnCredentialStore;
  clock: Clock;
}

export interface WebAuthnServiceOptions {
  relyingParty: RelyingPartyConfig;
  challengeService: WebAuthnChallengeService;
  credentialStore: WebAuthnCredentialStore;
  verifier: WebAuthnVerifier;
  clock?: Clock;
  maxCredentialsPerKind?: number;
}

export class WebAuthnService {
  private readonly relyingParty: RelyingPartyConfig;
  private readonly challengeService: WebAuthnChallengeService;
  private readonly credentialStore: WebAuthnCredentialStore;
  private readonly verifier: WebAuthnVerifier;
  private readonly clock: Clock;
  private readonly maxCredentialsPerKind: number;

  constructor(options: WebAuthnServiceOptions) {
    assertValidRelyingPartyConfig(options.relyingParty);
    this.relyingParty = options.relyingParty;
    this.challengeService = options.challengeService;
    this.credentialStore = options.credentialStore;
    this.verifier = options.verifier;
    this.clock = options.clock ?? systemClock;
    this.maxCredentialsPerKind = options.maxCredentialsPerKind ?? 5;
  }

  public async registerCredential(
    input: WebAuthnRegistrationInput,
  ): Promise<AuthResult<StoredWebAuthnCredential, WebAuthnVerificationError>> {
    const existing = await this.credentialStore.listUserCredentials(
      input.userId,
      input.kind,
    );
    if (existing.length >= this.maxCredentialsPerKind) {
      return err("credential_limit_exceeded");
    }
    const verified = await this.verifier.verifyRegistration(
      input,
      this.context(),
    );
    if (!verified.ok) {
      return verified;
    }
    await this.credentialStore.createCredential(verified.value.credential);
    return ok(verified.value.credential);
  }

  public async verifyAssertion(
    input: WebAuthnAssertionInput,
  ): Promise<AuthResult<StoredWebAuthnCredential, WebAuthnVerificationError>> {
    const verified = await this.verifier.verifyAssertion(input, this.context());
    if (!verified.ok) {
      return verified;
    }
    return ok(verified.value.credential);
  }

  private context(): WebAuthnVerificationContext {
    return {
      relyingParty: this.relyingParty,
      challengeService: this.challengeService,
      credentialStore: this.credentialStore,
      clock: this.clock,
    };
  }
}

export function assertValidRelyingPartyConfig(
  config: RelyingPartyConfig,
): void {
  if (config.id.trim() === "") {
    throw new ConfigurationError("WebAuthn relying-party id is required.");
  }
  if (config.name.trim() === "") {
    throw new ConfigurationError("WebAuthn relying-party name is required.");
  }
  if (config.origins.length === 0) {
    throw new ConfigurationError("At least one WebAuthn origin is required.");
  }
}

export async function hashChallenge(challenge: Uint8Array): Promise<string> {
  return sha256Hex(challenge);
}
