import { getSecondFactorState, type AuthUser } from "@authforge/core";

const user: AuthUser = {
  id: "user-123",
  email: "user@example.com",
  emailVerified: true,
  factors: {
    passkey: false,
    securityKey: true,
    totp: true,
  },
};

console.log({
  module: "two-factor",
  state: getSecondFactorState(user, {
    twoFactorVerified: false,
  }),
});
