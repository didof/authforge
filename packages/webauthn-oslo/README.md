# @authforge/webauthn-oslo

Oslo-backed WebAuthn verifier for AuthForge.

## Install

```sh
pnpm add @authforge/core @authforge/webauthn-oslo
```

## Usage

```ts
import { WebAuthnService } from "@authforge/core";
import { OsloWebAuthnVerifier } from "@authforge/webauthn-oslo";

const service = new WebAuthnService({
  relyingParty: {
    id: "example.com",
    name: "Example",
    origins: ["https://example.com"],
  },
  challengeService,
  credentialStore,
  verifier: new OsloWebAuthnVerifier(),
});
```

## Test Status

The package has invalid-input verifier tests. Positive-path registration/assertion tests are not included yet because the repository does not currently include deterministic raw authenticator fixtures for `attestationObject`, `authenticatorData`, `clientDataJSON`, and signatures. Add those fixtures before treating the verifier test suite as a complete authenticator conformance suite.
