import { MemoryPasswordResetStore, PasswordResetService } from "@authforge/core";

const passwordReset = new PasswordResetService({
  store: new MemoryPasswordResetStore(),
});

const created = await passwordReset.createSession({
  userId: "user-123",
  email: "user@example.com",
});

const verified = await passwordReset.verifyEmailCode(
  created.session.id,
  created.session.code,
);
if (verified.ok) {
  await passwordReset.setTwoFactorVerified(verified.value.id);
}

console.log({
  module: "password-reset",
  tokenLength: created.token.length,
  emailVerified: verified.ok ? verified.value.emailVerified : false,
  twoFactorVerified: verified.ok,
});
