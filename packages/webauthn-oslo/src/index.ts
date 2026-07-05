import {
  type WebAuthnAssertionInput,
  type AuthResult,
  type WebAuthnRegistrationInput,
  type WebAuthnVerificationContext,
  type WebAuthnVerificationError,
  type WebAuthnVerifier,
  type VerifiedWebAuthnAssertion,
  type VerifiedWebAuthnRegistration,
  err,
  ok,
} from "@aeonkey/core";
import {
  AttestationStatementFormat,
  ClientDataType,
  coseAlgorithmES256,
  coseAlgorithmRS256,
  coseEllipticCurveP256,
  createAssertionSignatureMessage,
  parseAttestationObject,
  parseAuthenticatorData,
  parseClientDataJSON,
  type AttestationStatement,
  type AuthenticatorData,
  type ClientData,
  type COSEEC2PublicKey,
  type COSERSAPublicKey,
} from "@oslojs/webauthn";
import {
  decodePKIXECDSASignature,
  decodeSEC1PublicKey,
  ECDSAPublicKey,
  p256,
  verifyECDSASignature,
} from "@oslojs/crypto/ecdsa";
import { sha256 } from "@oslojs/crypto/sha2";
import {
  decodePKCS1RSAPublicKey,
  RSAPublicKey,
  sha256ObjectIdentifier,
  verifyRSASSAPKCS1v15Signature,
} from "@oslojs/crypto/rsa";

export interface OsloWebAuthnVerifierOptions {
  requireUserVerificationForRegistration?: boolean;
  requireUserVerificationForAssertion?: boolean;
}

export class OsloWebAuthnVerifier implements WebAuthnVerifier {
  private readonly requireUserVerificationForRegistration: boolean;
  private readonly requireUserVerificationForAssertion: boolean;

  constructor(options: OsloWebAuthnVerifierOptions = {}) {
    this.requireUserVerificationForRegistration =
      options.requireUserVerificationForRegistration ?? true;
    this.requireUserVerificationForAssertion =
      options.requireUserVerificationForAssertion ?? false;
  }

  public async verifyRegistration(
    input: WebAuthnRegistrationInput,
    context: WebAuthnVerificationContext,
  ): Promise<
    AuthResult<VerifiedWebAuthnRegistration, WebAuthnVerificationError>
  > {
    let attestationStatement: AttestationStatement;
    let authenticatorData: AuthenticatorData;
    try {
      const attestationObject = parseAttestationObject(input.attestationObject);
      attestationStatement = attestationObject.attestationStatement;
      authenticatorData = attestationObject.authenticatorData;
    } catch {
      return err("invalid_data");
    }

    if (attestationStatement.format !== AttestationStatementFormat.None) {
      return err("invalid_data");
    }
    if (
      !verifyAuthenticatorData(
        authenticatorData,
        context,
        this.requireUserVerificationForRegistration,
      )
    ) {
      return err("invalid_relying_party");
    }
    if (authenticatorData.credential === null) {
      return err("invalid_data");
    }

    const clientDataResult = await verifyClientData(
      input.clientDataJSON,
      ClientDataType.Create,
      context,
    );
    if (!clientDataResult.ok) {
      return clientDataResult;
    }

    const credentialResult = createStoredCredential(
      input,
      authenticatorData,
      context,
    );
    if (!credentialResult.ok) {
      return credentialResult;
    }

    return ok({
      credential: credentialResult.value,
    } satisfies VerifiedWebAuthnRegistration);
  }

  public async verifyAssertion(
    input: WebAuthnAssertionInput,
    context: WebAuthnVerificationContext,
  ): Promise<AuthResult<VerifiedWebAuthnAssertion, WebAuthnVerificationError>> {
    let authenticatorData: AuthenticatorData;
    try {
      authenticatorData = parseAuthenticatorData(input.authenticatorData);
    } catch {
      return err("invalid_data");
    }

    const requireUserVerification =
      input.requireUserVerification ?? this.requireUserVerificationForAssertion;
    if (
      !verifyAuthenticatorData(
        authenticatorData,
        context,
        requireUserVerification,
      )
    ) {
      return err("invalid_relying_party");
    }

    const clientDataResult = await verifyClientData(
      input.clientDataJSON,
      ClientDataType.Get,
      context,
    );
    if (!clientDataResult.ok) {
      return clientDataResult;
    }

    const credential = await context.credentialStore.getCredential(
      input.credentialId,
    );
    if (credential === null) {
      return err("credential_not_found");
    }

    const validSignature = verifyCredentialSignature(
      credential.algorithmId,
      credential.publicKey,
      input.signature,
      input.authenticatorData,
      input.clientDataJSON,
    );
    if (!validSignature.ok) {
      return validSignature;
    }

    return ok({
      credential,
    } satisfies VerifiedWebAuthnAssertion);
  }
}

async function verifyClientData(
  clientDataJSON: Uint8Array,
  expectedType: ClientDataType,
  context: WebAuthnVerificationContext,
): Promise<ReturnTypeFailureOrTrue> {
  let clientData: ClientData;
  try {
    clientData = parseClientDataJSON(clientDataJSON);
  } catch {
    return err("invalid_data");
  }

  if (clientData.type !== expectedType) {
    return err("invalid_data");
  }
  if (!context.relyingParty.origins.includes(clientData.origin)) {
    return err("invalid_origin");
  }
  if (clientData.crossOrigin === true) {
    return err("invalid_origin");
  }

  const challengeResult = await context.challengeService.consumeChallenge(
    clientData.challenge,
  );
  if (!challengeResult.ok) {
    return err("invalid_challenge");
  }

  return ok(true);
}

function verifyAuthenticatorData(
  authenticatorData: AuthenticatorData,
  context: WebAuthnVerificationContext,
  requireUserVerification: boolean,
): boolean {
  if (!authenticatorData.verifyRelyingPartyIdHash(context.relyingParty.id)) {
    return false;
  }
  if (!authenticatorData.userPresent) {
    return false;
  }
  if (requireUserVerification && !authenticatorData.userVerified) {
    return false;
  }
  return true;
}

function createStoredCredential(
  input: WebAuthnRegistrationInput,
  authenticatorData: AuthenticatorData,
  context: WebAuthnVerificationContext,
) {
  const credential = authenticatorData.credential;
  if (credential === null) {
    return err("invalid_data");
  }

  const algorithm = credential.publicKey.algorithm();
  if (algorithm === coseAlgorithmES256) {
    let cosePublicKey: COSEEC2PublicKey;
    try {
      cosePublicKey = credential.publicKey.ec2();
    } catch {
      return err("invalid_data");
    }
    if (cosePublicKey.curve !== coseEllipticCurveP256) {
      return err("unsupported_algorithm");
    }
    return ok({
      id: credential.id,
      userId: input.userId,
      name: input.name,
      algorithmId: coseAlgorithmES256,
      publicKey: new ECDSAPublicKey(
        p256,
        cosePublicKey.x,
        cosePublicKey.y,
      ).encodeSEC1Uncompressed(),
      kind: input.kind,
      createdAt: context.clock.now(),
    });
  }

  if (algorithm === coseAlgorithmRS256) {
    let cosePublicKey: COSERSAPublicKey;
    try {
      cosePublicKey = credential.publicKey.rsa();
    } catch {
      return err("invalid_data");
    }
    return ok({
      id: credential.id,
      userId: input.userId,
      name: input.name,
      algorithmId: coseAlgorithmRS256,
      publicKey: new RSAPublicKey(
        cosePublicKey.n,
        cosePublicKey.e,
      ).encodePKCS1(),
      kind: input.kind,
      createdAt: context.clock.now(),
    });
  }

  return err("unsupported_algorithm");
}

function verifyCredentialSignature(
  algorithmId: number,
  publicKey: Uint8Array,
  signature: Uint8Array,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array,
): ReturnTypeFailureOrTrue {
  const hash = sha256(
    createAssertionSignatureMessage(authenticatorData, clientDataJSON),
  );

  try {
    if (algorithmId === coseAlgorithmES256) {
      const ecdsaSignature = decodePKIXECDSASignature(signature);
      const ecdsaPublicKey = decodeSEC1PublicKey(p256, publicKey);
      return verifyECDSASignature(ecdsaPublicKey, hash, ecdsaSignature)
        ? ok(true)
        : err("invalid_signature");
    }
    if (algorithmId === coseAlgorithmRS256) {
      const rsaPublicKey = decodePKCS1RSAPublicKey(publicKey);
      return verifyRSASSAPKCS1v15Signature(
        rsaPublicKey,
        sha256ObjectIdentifier,
        hash,
        signature,
      )
        ? ok(true)
        : err("invalid_signature");
    }
  } catch {
    return err("invalid_signature");
  }

  return err("unsupported_algorithm");
}

type ReturnTypeFailureOrTrue =
  { ok: true; value: true } | { ok: false; error: WebAuthnVerificationError };
