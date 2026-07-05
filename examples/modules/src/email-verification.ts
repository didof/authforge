import {
  EmailVerificationService,
  MemoryEmailVerificationStore,
} from "@authforge/core";

const emailVerification = new EmailVerificationService({
  store: new MemoryEmailVerificationStore(),
});

const request = await emailVerification.createRequest({
  userId: "user-123",
  email: "user@example.com",
});

const result = await emailVerification.verifyCode(
  "user-123",
  request.id,
  request.code,
);

console.log({
  module: "email-verification",
  code: request.code,
  verified: result.ok,
  email: result.ok ? result.value.email : null,
});
