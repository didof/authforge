# @aeonkey/express

Express adapter for AeonKey.

## Install

```sh
pnpm add @aeonkey/core @aeonkey/express express
```

## Usage

```ts
import express from "express";
import { MemorySessionStore, SessionService } from "@aeonkey/core";
import {
  createAuthRouter,
  createCsrfProtection,
  createCsrfTokenHandler,
  createSessionMiddleware,
} from "@aeonkey/express";

const sessions = new SessionService({
  store: new MemorySessionStore(),
});
const csrfSecret = process.env.AEONKEY_CSRF_SECRET!;

const app = express();
app.use(createSessionMiddleware({ sessions }));
app.get("/csrf", createCsrfTokenHandler({ secret: csrfSecret }));
app.use(createCsrfProtection({ secret: csrfSecret }));
app.use("/auth", createAuthRouter({ sessions }));
```

The router exposes session status, logout, and optional WebAuthn challenge routes. Build signup, login, and application authorization in your app with `@aeonkey/core`.

`createCsrfProtection()` implements a signed double-submit pattern for cookie-session POST routes.
