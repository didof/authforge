import { describe, expect, it } from "vitest";
import {
  createMemoryAuthStores,
  WebAuthnChallengeService,
  systemClock,
} from "@authforge/core";
import { OsloWebAuthnVerifier } from "../src/index.js";

describe("OsloWebAuthnVerifier", () => {
  it("rejects invalid registration data without throwing", async () => {
    const stores = createMemoryAuthStores();
    const challengeService = new WebAuthnChallengeService({
      store: stores.webAuthnChallenges,
    });
    const verifier = new OsloWebAuthnVerifier();
    const result = await verifier.verifyRegistration(
      {
        userId: "user-1",
        name: "MacBook",
        kind: "passkey",
        attestationObject: new Uint8Array([1, 2, 3]),
        clientDataJSON: new Uint8Array([1, 2, 3]),
      },
      {
        relyingParty: {
          id: "localhost",
          name: "AuthForge",
          origins: ["http://localhost:3000"],
        },
        challengeService,
        credentialStore: stores.webAuthnCredentials,
        clock: systemClock,
      },
    );

    expect(result).toEqual({ ok: false, error: "invalid_data" });
  });
});
