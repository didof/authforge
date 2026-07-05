import Database from "better-sqlite3";
import express, {
  type Request,
  type RequestHandler,
  type Response,
} from "express";
import {
  AuthForgeService,
  EmailVerificationService,
  PasswordResetService,
  PersistentRefillingTokenBucket,
  RecoveryCodeService,
  SessionService,
  TotpService,
  WebAuthnChallengeService,
  WebAuthnService,
  decodeBase64Url,
  type CompletePasswordResetInput,
  type SignupWithPasswordInput,
  type VerifyWebAuthnAssertionInput,
} from "@authforge/core";
import { Argon2PasswordHasher } from "@authforge/argon2";
import {
  createSqliteAuthSchema,
  SqliteAuthStore,
} from "@authforge/sqlite";
import { OsloWebAuthnVerifier } from "@authforge/webauthn-oslo";
import {
  clearAuthCookie,
  createAuthRouter,
  createCsrfProtection,
  createCsrfTokenHandler,
  createSessionMiddleware,
  getAuthSession,
  setCreatedSessionCookie,
} from "@authforge/express";

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "127.0.0.1";
const databasePath = process.env.AUTHKIT_EXAMPLE_DB ?? "authforge-example.sqlite";
const csrfSecret =
  process.env.AUTHKIT_CSRF_SECRET ??
  "local-development-csrf-secret-change-before-production";
const cookie = {
  secure: false,
  sameSite: "lax" as const,
};

const db = new Database(databasePath);
createSqliteAuthSchema(db);
const store = new SqliteAuthStore(db);
const passwordHasher = new Argon2PasswordHasher();

const sessions = new SessionService({ store });
const emailVerification = new EmailVerificationService({ store });
const passwordReset = new PasswordResetService({ store });
const totp = new TotpService({
  store,
  issuer: "AuthForge Express Demo",
});
const recoveryCodes = new RecoveryCodeService({
  store,
  hasher: passwordHasher,
});
const webAuthnChallenges = new WebAuthnChallengeService({ store });
const webAuthn = new WebAuthnService({
  relyingParty: {
    id: "localhost",
    name: "AuthForge Express Demo",
    origins: [`http://${host}:${port}`, `http://localhost:${port}`],
  },
  challengeService: webAuthnChallenges,
  credentialStore: store,
  verifier: new OsloWebAuthnVerifier({
    requireUserVerificationForRegistration: false,
  }),
});
const auth = new AuthForgeService({
  accounts: store,
  sessions,
  passwordHasher,
  emailVerification,
  passwordReset,
  totp,
  recoveryCodes,
  webAuthn,
  webAuthnChallenges,
  passwordPolicy: {
    minLength: 8,
    maxLength: 255,
  },
});

const signupLimiter = new PersistentRefillingTokenBucket({
  store,
  name: "signup",
  max: 5,
  refillIntervalSeconds: 60,
});
const loginLimiter = new PersistentRefillingTokenBucket({
  store,
  name: "login",
  max: 10,
  refillIntervalSeconds: 60,
});
const resetLimiter = new PersistentRefillingTokenBucket({
  store,
  name: "password-reset",
  max: 5,
  refillIntervalSeconds: 60,
});

const app = express();
app.use(express.json());
app.use(
  createSessionMiddleware({
    sessions,
    cookie,
  }),
);

app.get("/", (_req, res) => {
  res.json({
    name: "AuthForge Express SQLite demo",
    databasePath,
    routes: {
      csrf: "GET /csrf",
      signup: "POST /signup",
      login: "POST /login",
      session: "GET /auth/session",
      logout: "POST /auth/logout",
      emailVerificationStart: "POST /email-verification/start",
      emailVerificationComplete: "POST /email-verification/complete",
      passwordResetStart: "POST /password-reset/start",
      passwordResetComplete: "POST /password-reset/complete",
      totpSetup: "POST /totp/setup",
      totpVerify: "POST /totp/verify",
      recoveryCodeCreate: "POST /recovery-code/create",
      recoveryCodeResetFactors: "POST /recovery-code/reset-factors",
      webAuthnChallenge: "POST /auth/webauthn/challenge",
      webAuthnRegister: "POST /webauthn/register",
      webAuthnAssert: "POST /webauthn/assert",
    },
  });
});

app.get(
  "/csrf",
  createCsrfTokenHandler({
    secret: csrfSecret,
    cookie,
  }),
);

app.use(
  createCsrfProtection({
    secret: csrfSecret,
    cookie,
  }),
);

app.use(
  "/auth",
  createAuthRouter({
    sessions,
    webAuthnChallenges,
    cookie,
  }),
);

app.post("/signup", async (req, res, next) => {
  try {
    if (!(await signupLimiter.consume(clientKey(req), 1))) {
      rateLimited(res);
      return;
    }

    const body = readBody(req);
    const email = getString(body, "email");
    const password = getString(body, "password");
    const username = getOptionalString(body, "username");
    if (email === null || password === null) {
      badRequest(res, "email and password are required");
      return;
    }

    const signupInput: SignupWithPasswordInput = {
      email,
      password,
    };
    if (username !== undefined) {
      signupInput.username = username;
    }

    const result = await auth.signupWithPassword(signupInput);
    if (!result.ok) {
      res.status(400).json({ error: result.error });
      return;
    }
    if (result.value.session !== null) {
      setCreatedSessionCookie(res, result.value.session, cookie);
    }

    const verification = await auth.startEmailVerification(
      result.value.user.id,
    );
    if (verification.ok) {
      logEmailVerification(verification.value.request);
    }

    res.status(201).json({
      user: result.value.user,
      session: result.value.session?.session ?? null,
      emailVerificationRequestId: verification.ok
        ? verification.value.request.id
        : null,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/login", async (req, res, next) => {
  try {
    const body = readBody(req);
    const email = getString(body, "email");
    const password = getString(body, "password");
    if (email === null || password === null) {
      badRequest(res, "email and password are required");
      return;
    }
    if (!(await loginLimiter.consume(`${clientKey(req)}:${email}`, 1))) {
      rateLimited(res);
      return;
    }

    const result = await auth.loginWithPassword({ email, password });
    if (!result.ok) {
      res.status(401).json({ error: result.error });
      return;
    }

    setCreatedSessionCookie(res, result.value.session, cookie);
    res.status(200).json({
      user: result.value.user,
      session: result.value.session.session,
      requiresSecondFactor:
        !result.value.session.session.twoFactorVerified &&
        hasAnyFactor(result.value.user.factors),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/email-verification/start", requireSession(), async (_req, res) => {
  const session = getAuthSession(res);
  const result = await auth.startEmailVerification(session!.userId);
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  logEmailVerification(result.value.request);
  res.json({
    requestId: result.value.request.id,
    email: result.value.request.email,
  });
});

app.post("/email-verification/complete", requireSession(), async (req, res) => {
  const body = readBody(req);
  const requestId = getString(body, "requestId");
  const code = getString(body, "code");
  if (requestId === null || code === null) {
    badRequest(res, "requestId and code are required");
    return;
  }

  const session = getAuthSession(res);
  const result = await auth.completeEmailVerification({
    userId: session!.userId,
    requestId,
    code,
  });
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json({ user: result.value });
});

app.post("/password-reset/start", async (req, res, next) => {
  try {
    const body = readBody(req);
    const email = getString(body, "email");
    if (email === null) {
      badRequest(res, "email is required");
      return;
    }
    if (!(await resetLimiter.consume(`${clientKey(req)}:${email}`, 1))) {
      rateLimited(res);
      return;
    }

    const result = await auth.startPasswordReset(email);
    if (!result.ok) {
      res.status(400).json({ error: result.error });
      return;
    }
    if (result.value.reset !== null) {
      logPasswordReset(result.value.reset);
    }
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.post("/password-reset/complete", async (req, res) => {
  const body = readBody(req);
  const token = getString(body, "token");
  const emailCode = getString(body, "emailCode");
  const newPassword = getString(body, "newPassword");
  const totpCode = getOptionalString(body, "totpCode");
  if (token === null || emailCode === null || newPassword === null) {
    badRequest(res, "token, emailCode, and newPassword are required");
    return;
  }

  const resetInput: CompletePasswordResetInput = {
    token,
    emailCode,
    newPassword,
  };
  if (totpCode !== undefined) {
    resetInput.totpCode = totpCode;
  }

  const result = await auth.completePasswordReset(resetInput);
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  clearAuthCookie(res, cookie);
  res.json({ user: result.value.user });
});

app.post("/totp/setup", requireSession(), async (_req, res) => {
  const session = getAuthSession(res);
  const result = await auth.setupTotp({ userId: session!.userId });
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json({
    secret: result.value.secret,
    otpauthUrl: result.value.otpauthUrl,
  });
});

app.post("/totp/verify", requireSession(), async (req, res) => {
  const body = readBody(req);
  const code = getString(body, "code");
  if (code === null) {
    badRequest(res, "code is required");
    return;
  }

  const session = getAuthSession(res);
  const result = await auth.verifyTotp({
    userId: session!.userId,
    code,
    sessionId: session!.id,
  });
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json({ user: result.value.user });
});

app.post("/recovery-code/create", requireSession(), async (_req, res) => {
  const session = getAuthSession(res);
  const result = await auth.createRecoveryCode(session!.userId);
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json({ recoveryCode: result.value.code });
});

app.post("/recovery-code/reset-factors", async (req, res) => {
  const body = readBody(req);
  const email = getString(body, "email");
  const recoveryCode = getString(body, "recoveryCode");
  if (email === null || recoveryCode === null) {
    badRequest(res, "email and recoveryCode are required");
    return;
  }

  const user = await auth.getUserByEmail(email);
  if (user === null) {
    res.status(404).json({ error: "account_not_found" });
    return;
  }

  const result = await auth.resetSecondFactorsWithRecoveryCode(
    user.id,
    recoveryCode,
  );
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json({ recoveryCode: result.value.code });
});

app.post("/webauthn/register", requireSession(), async (req, res) => {
  const body = readBody(req);
  const name = getString(body, "name");
  const attestationObject = getString(body, "attestationObject");
  const clientDataJSON = getString(body, "clientDataJSON");
  const kind = getWebAuthnKind(body);
  if (
    name === null ||
    attestationObject === null ||
    clientDataJSON === null ||
    kind === null
  ) {
    badRequest(
      res,
      "name, kind, attestationObject, and clientDataJSON are required",
    );
    return;
  }

  const session = getAuthSession(res);
  const result = await auth.registerWebAuthnCredential({
    userId: session!.userId,
    name,
    kind,
    attestationObject: decodeBase64Url(attestationObject),
    clientDataJSON: decodeBase64Url(clientDataJSON),
  });
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.status(201).json({
    credentialId: Buffer.from(result.value.credential.id).toString("base64url"),
    user: result.value.user,
  });
});

app.post("/webauthn/assert", async (req, res) => {
  const body = readBody(req);
  const credentialId = getString(body, "credentialId");
  const authenticatorData = getString(body, "authenticatorData");
  const clientDataJSON = getString(body, "clientDataJSON");
  const signature = getString(body, "signature");
  const session = getAuthSession(res);
  if (
    credentialId === null ||
    authenticatorData === null ||
    clientDataJSON === null ||
    signature === null
  ) {
    badRequest(
      res,
      "credentialId, authenticatorData, clientDataJSON, and signature are required",
    );
    return;
  }

  const assertionInput: VerifyWebAuthnAssertionInput = {
    credentialId: decodeBase64Url(credentialId),
    authenticatorData: decodeBase64Url(authenticatorData),
    clientDataJSON: decodeBase64Url(clientDataJSON),
    signature: decodeBase64Url(signature),
  };
  if (session?.id !== undefined) {
    assertionInput.sessionId = session.id;
  }

  const result = await auth.verifyWebAuthnAssertion(assertionInput);
  if (!result.ok) {
    res.status(400).json({ error: result.error });
    return;
  }
  res.json({ user: result.value.user });
});

app.use(errorHandler);

app.listen(port, host, () => {
  console.log(`AuthForge Express demo listening on http://${host}:${port}`);
  console.log(`SQLite database: ${databasePath}`);
  console.log("Fetch a CSRF token from GET /csrf before POST requests.");
});

function requireSession(): RequestHandler {
  return (_req, res, next) => {
    if (getAuthSession(res) === null) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }
    next();
  };
}

function readBody(req: Request): Record<string, unknown> {
  return isRecord(req.body) ? req.body : {};
}

function getString(
  body: Record<string, unknown>,
  key: string,
): string | null {
  const value = body[key];
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : null;
}

function getOptionalString(
  body: Record<string, unknown>,
  key: string,
): string | undefined {
  return getString(body, key) ?? undefined;
}

function getWebAuthnKind(
  body: Record<string, unknown>,
): "passkey" | "security-key" | null {
  const value = getString(body, "kind");
  return value === "passkey" || value === "security-key" ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clientKey(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

function hasAnyFactor(factors: {
  totp: boolean;
  passkey: boolean;
  securityKey: boolean;
}): boolean {
  return factors.totp || factors.passkey || factors.securityKey;
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ error: "bad_request", message });
}

function rateLimited(res: Response): void {
  res.status(429).json({ error: "rate_limited" });
}

function logEmailVerification(request: {
  email: string;
  id: string;
  code: string;
}): void {
  console.log("[AuthForge demo email verification]");
  console.log(`email=${request.email}`);
  console.log(`requestId=${request.id}`);
  console.log(`code=${request.code}`);
}

function logPasswordReset(reset: {
  token: string;
  session: { email: string; code: string };
}): void {
  console.log("[AuthForge demo password reset]");
  console.log(`email=${reset.session.email}`);
  console.log(`token=${reset.token}`);
  console.log(`emailCode=${reset.session.code}`);
}

function errorHandler(
  error: unknown,
  _req: Request,
  res: Response,
  _next: express.NextFunction,
): void {
  console.error(error);
  res.status(500).json({ error: "internal_error" });
}
