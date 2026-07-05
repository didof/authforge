import {
  MemoryTotpCredentialStore,
  TotpService,
  generateTotpCode,
} from "@aeonkey/core";

const totp = new TotpService({
  store: new MemoryTotpCredentialStore(),
  issuer: "AeonKey Demo",
  window: 0,
});

const created = await totp.createCredential({
  userId: "user-123",
  accountName: "user@example.com",
});
const code = await generateTotpCode(created.credential.key);
const verified = await totp.verifyCode("user-123", code);

console.log({
  module: "totp",
  secretLength: created.secret.length,
  code,
  verified: verified.ok,
  otpauthUrlStartsCorrectly: created.otpauthUrl.startsWith("otpauth://totp/"),
});
