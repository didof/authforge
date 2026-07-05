import { OsloWebAuthnVerifier } from "@aeonkey/webauthn-oslo";
import {
  MemoryWebAuthnChallengeStore,
  MemoryWebAuthnCredentialStore,
  WebAuthnChallengeService,
  WebAuthnService,
} from "@aeonkey/core";

const challengeService = new WebAuthnChallengeService({
  store: new MemoryWebAuthnChallengeStore(),
});
const credentialStore = new MemoryWebAuthnCredentialStore();

const webauthn = new WebAuthnService({
  relyingParty: {
    id: "localhost",
    name: "AeonKey Demo",
    origins: ["http://localhost:3000"],
  },
  challengeService,
  credentialStore,
  verifier: new OsloWebAuthnVerifier(),
});

const result = await webauthn.registerCredential({
  userId: "user-123",
  name: "Demo passkey",
  kind: "passkey",
  attestationObject: new Uint8Array([1, 2, 3]),
  clientDataJSON: new Uint8Array([1, 2, 3]),
});

console.log({
  module: "webauthn-verifier",
  verifierConfigured: true,
  invalidDemoPayloadRejected: !result.ok,
  error: result.ok ? null : result.error,
});
