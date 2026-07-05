# @authforge/express

Express adapter for AuthForge.

## Install

```sh
pnpm add @authforge/core @authforge/express express
```

## Usage

```ts
import express from "express";
import { MemorySessionStore, SessionService } from "@authforge/core";
import {
  createAuthRouter,
  createCsrfProtection,
  createCsrfTokenHandler,
  createSessionMiddleware,
} from "@authforge/express";

const sessions = new SessionService({
  store: new MemorySessionStore(),
});
const csrfSecret = process.env.AUTHKIT_CSRF_SECRET!;

const app = express();
app.use(createSessionMiddleware({ sessions }));
app.get("/csrf", createCsrfTokenHandler({ secret: csrfSecret }));
app.use(createCsrfProtection({ secret: csrfSecret }));
app.use("/auth", createAuthRouter({ sessions }));
```

The router exposes session status, logout, and optional WebAuthn challenge routes. Build signup, login, and application authorization in your app with `@authforge/core`.

`createCsrfProtection()` implements a signed double-submit pattern for cookie-session POST routes.
