import { MemorySessionStore, SessionService } from "@authforge/core";

const sessions = new SessionService({
  store: new MemorySessionStore(),
});

const created = await sessions.createSession({
  userId: "user-123",
  twoFactorVerified: false,
});

const validated = await sessions.validateToken(created.token);

console.log({
  module: "sessions",
  tokenLength: created.token.length,
  storedTokenIsHashed: created.session.id !== created.token,
  validated: validated.ok,
  userId: validated.ok ? validated.value.userId : null,
});
