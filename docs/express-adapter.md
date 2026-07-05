# Express Adapter

`@aeonkey/express` provides middleware and route helpers. It does not own user registration, login forms, or application-specific authorization.

## Session Middleware

```ts
import express from "express";
import { MemorySessionStore, SessionService } from "@aeonkey/core";
import { createSessionMiddleware } from "@aeonkey/express";

const sessions = new SessionService({
  store: new MemorySessionStore(),
});

const app = express();
app.use(createSessionMiddleware({ sessions }));
```

The middleware validates the session cookie, refreshes it when needed, and stores the result in `res.locals.auth.session`.

## Router

```ts
import { createAuthRouter } from "@aeonkey/express";

app.use("/auth", createAuthRouter({ sessions }));
```

Current routes:

- `GET /auth/session`
- `POST /auth/logout`
- `POST /auth/webauthn/challenge` when a challenge service is provided

## CSRF Protection

Cookie-session POST routes need CSRF protection. The adapter includes a signed double-submit helper:

```ts
import {
  createCsrfProtection,
  createCsrfTokenHandler,
} from "@aeonkey/express";

app.get(
  "/csrf",
  createCsrfTokenHandler({
    secret: process.env.AEONKEY_CSRF_SECRET!,
  }),
);

app.use(
  createCsrfProtection({
    secret: process.env.AEONKEY_CSRF_SECRET!,
  }),
);
```

Clients send the returned token in the `x-csrf-token` header and keep the `csrf` cookie. Safe methods (`GET`, `HEAD`, `OPTIONS`) are ignored by default. Set a long random `AEONKEY_CSRF_SECRET` in production and rotate it like other application secrets.

## Cookie Defaults

- Cookie name: `session`
- `HttpOnly`
- `SameSite=Lax`
- Path `/`
- `Secure` when `NODE_ENV=production`

## Local Demo

`examples/express` is a SQLite-backed API demo, not a production app template. It demonstrates:

- signup and login
- session status and logout
- email verification through console output
- password reset through console output
- TOTP setup and verification
- recovery-code factor reset
- WebAuthn challenge, registration, and assertion wiring
- signed double-submit CSRF
- SQLite-backed rate limits

Run it:

```sh
pnpm build
pnpm --filter @aeonkey/example-express start
```

Fetch a CSRF token before POST requests:

```sh
curl -c /tmp/aeonkey-cookies http://localhost:3000/csrf
```
