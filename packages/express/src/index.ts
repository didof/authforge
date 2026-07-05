import { createHmac, timingSafeEqual } from "node:crypto";
import {
  Router,
  type Request,
  type RequestHandler,
  type Response,
} from "express";
import {
  encodeBase64Url,
  randomBytes,
  type CreatedSession,
  type SessionService,
  type StoredSession,
  type WebAuthnChallengeService,
} from "@authforge/core";

export interface CsrfOptions {
  secret: string;
  cookie?: AuthCookieOptions;
  headerName?: string;
  tokenBytes?: number;
  ignoredMethods?: string[];
}

export interface CreateCsrfTokenOptions {
  secret: string;
  tokenBytes?: number;
}

export interface VerifyCsrfTokenOptions {
  secret: string;
  token: string;
}

export interface CsrfTokenCookieOptions extends AuthCookieOptions {
  expiresAt?: Date;
}

export interface CsrfTokenHandlerOptions extends CsrfOptions {
  responseKey?: string;
}

export interface CsrfSessionLocals {
  csrfToken: string;
}

export interface CsrfFailureBody {
  error: "csrf_invalid";
}

/*
 * Signed double-submit CSRF token for cookie-session APIs.
 * The token is safe to expose to the browser; the signing secret is not.
 */
export function createCsrfToken(options: CreateCsrfTokenOptions): string {
  const nonce = encodeBase64Url(randomBytes(options.tokenBytes ?? 20));
  return `${nonce}.${signCsrfNonce(options.secret, nonce)}`;
}

export function verifyCsrfToken(options: VerifyCsrfTokenOptions): boolean {
  const [nonce, signature, extra] = options.token.split(".");
  if (nonce === undefined || signature === undefined || extra !== undefined) {
    return false;
  }
  return timingSafeStringEqual(signature, signCsrfNonce(options.secret, nonce));
}

export function setCsrfCookie(
  res: Response,
  token: string,
  options?: CsrfTokenCookieOptions,
): void {
  const cookie = resolveCookieOptions({
    name: "csrf",
    httpOnly: false,
    ...options,
  });
  const expiresAt =
    options?.expiresAt ?? new Date(Date.now() + 1000 * 60 * 60 * 24);
  const parts = [
    `${cookie.name}=${encodeURIComponent(token)}`,
    `Path=${cookie.path}`,
    `Expires=${expiresAt.toUTCString()}`,
    `SameSite=${cookie.sameSite}`,
  ];

  if (cookie.httpOnly) {
    parts.push("HttpOnly");
  }
  if (cookie.secure) {
    parts.push("Secure");
  }
  if (cookie.domain !== undefined) {
    parts.push(`Domain=${cookie.domain}`);
  }

  res.append("Set-Cookie", parts.join("; "));
}

export function createCsrfTokenHandler(
  options: CsrfTokenHandlerOptions,
): RequestHandler {
  return (_req, res) => {
    const token = createCsrfToken(options);
    setCsrfCookie(res, token, options.cookie);
    const responseKey = options.responseKey ?? "csrfToken";
    res.json({ [responseKey]: token });
  };
}

export function createCsrfProtection(options: CsrfOptions): RequestHandler {
  const headerName = (options.headerName ?? "x-csrf-token").toLowerCase();
  const ignoredMethods = new Set(
    options.ignoredMethods ?? ["GET", "HEAD", "OPTIONS"],
  );
  const cookie = resolveCookieOptions({
    name: "csrf",
    httpOnly: false,
    ...options.cookie,
  });

  return (req, res, next) => {
    if (ignoredMethods.has(req.method.toUpperCase())) {
      const existing = getCookie(req, cookie.name);
      if (
        existing === null ||
        !verifyCsrfToken({ secret: options.secret, token: existing })
      ) {
        const token = createCsrfToken(options);
        setCsrfCookie(res, token, options.cookie);
        res.locals.csrf = { csrfToken: token } satisfies CsrfSessionLocals;
      } else {
        res.locals.csrf = { csrfToken: existing } satisfies CsrfSessionLocals;
      }
      next();
      return;
    }

    const cookieToken = getCookie(req, cookie.name);
    const submitted = getHeader(req, headerName);
    if (
      cookieToken === null ||
      submitted === null ||
      !timingSafeStringEqual(cookieToken, submitted) ||
      !verifyCsrfToken({ secret: options.secret, token: cookieToken })
    ) {
      res.status(403).json({ error: "csrf_invalid" } satisfies CsrfFailureBody);
      return;
    }

    next();
  };
}

export function getCsrfToken(res: Response): string | null {
  const csrf = res.locals.csrf as CsrfSessionLocals | undefined;
  return csrf?.csrfToken ?? null;
}

export interface AuthCookieOptions {
  name?: string;
  path?: string;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  httpOnly?: boolean;
  domain?: string;
}

export interface AuthSessionLocals {
  session: StoredSession | null;
}

export interface AuthMiddlewareOptions {
  sessions: SessionService;
  cookie?: AuthCookieOptions;
}

export interface AuthRouterOptions extends AuthMiddlewareOptions {
  webAuthnChallenges?: WebAuthnChallengeService;
}

const defaultCookie: Required<
  Pick<AuthCookieOptions, "name" | "path" | "sameSite" | "httpOnly">
> = {
  name: "session",
  path: "/",
  sameSite: "lax",
  httpOnly: true,
};

interface ResolvedAuthCookieOptions {
  name: string;
  path: string;
  secure: boolean;
  sameSite: "strict" | "lax" | "none";
  httpOnly: boolean;
  domain?: string;
}

export function createAuthRouter(options: AuthRouterOptions): Router {
  const router = Router();

  router.get("/session", createSessionStatusHandler());
  router.post("/logout", createLogoutHandler(options));

  if (options.webAuthnChallenges !== undefined) {
    router.post(
      "/webauthn/challenge",
      createWebAuthnChallengeHandler(options.webAuthnChallenges),
    );
  }

  return router;
}

export function createSessionMiddleware(
  options: AuthMiddlewareOptions,
): RequestHandler {
  const cookie = resolveCookieOptions(options.cookie);

  return async (req, res, next) => {
    try {
      const token = getCookie(req, cookie.name);
      if (token === null) {
        res.locals.auth = { session: null } satisfies AuthSessionLocals;
        next();
        return;
      }

      const result = await options.sessions.validateToken(token);
      if (!result.ok) {
        clearAuthCookie(res, options.cookie);
        res.locals.auth = { session: null } satisfies AuthSessionLocals;
        next();
        return;
      }

      setAuthCookie(res, token, result.value.expiresAt, options.cookie);
      res.locals.auth = { session: result.value } satisfies AuthSessionLocals;
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function setCreatedSessionCookie(
  res: Response,
  createdSession: CreatedSession,
  options?: AuthCookieOptions,
): void {
  setAuthCookie(
    res,
    createdSession.token,
    createdSession.session.expiresAt,
    options,
  );
}

export function setAuthCookie(
  res: Response,
  token: string,
  expiresAt: Date,
  options?: AuthCookieOptions,
): void {
  const cookie = resolveCookieOptions(options);
  const parts = [
    `${cookie.name}=${encodeURIComponent(token)}`,
    `Path=${cookie.path}`,
    `Expires=${expiresAt.toUTCString()}`,
    `SameSite=${cookie.sameSite}`,
  ];

  if (cookie.httpOnly) {
    parts.push("HttpOnly");
  }
  if (cookie.secure) {
    parts.push("Secure");
  }
  if (cookie.domain !== undefined) {
    parts.push(`Domain=${cookie.domain}`);
  }

  res.append("Set-Cookie", parts.join("; "));
}

export function clearAuthCookie(
  res: Response,
  options?: AuthCookieOptions,
): void {
  const cookie = resolveCookieOptions(options);
  const parts = [
    `${cookie.name}=`,
    `Path=${cookie.path}`,
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "Max-Age=0",
    `SameSite=${cookie.sameSite}`,
  ];

  if (cookie.httpOnly) {
    parts.push("HttpOnly");
  }
  if (cookie.secure) {
    parts.push("Secure");
  }
  if (cookie.domain !== undefined) {
    parts.push(`Domain=${cookie.domain}`);
  }

  res.append("Set-Cookie", parts.join("; "));
}

export function getAuthSession(res: Response): StoredSession | null {
  const auth = res.locals.auth as AuthSessionLocals | undefined;
  return auth?.session ?? null;
}

function createSessionStatusHandler(): RequestHandler {
  return (_req, res) => {
    res.json({
      authenticated: getAuthSession(res) !== null,
      session: getAuthSession(res),
    });
  };
}

function createLogoutHandler(options: AuthMiddlewareOptions): RequestHandler {
  return async (_req, res, next) => {
    try {
      const session = getAuthSession(res);
      if (session !== null) {
        await options.sessions.invalidateSession(session.id);
      }
      clearAuthCookie(res, options.cookie);
      res.status(204).end();
    } catch (error) {
      next(error);
    }
  };
}

function createWebAuthnChallengeHandler(
  challenges: WebAuthnChallengeService,
): RequestHandler {
  return async (_req, res, next) => {
    try {
      const challenge = await challenges.createChallenge();
      res.json({
        challenge: challenge.encodedChallenge,
        expiresAt: challenge.expiresAt.toISOString(),
      });
    } catch (error) {
      next(error);
    }
  };
}

function signCsrfNonce(secret: string, nonce: string): string {
  return encodeBase64Url(
    createHmac("sha256", secret).update(nonce).digest(),
  );
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  if (aBuffer.byteLength !== bBuffer.byteLength) {
    return false;
  }
  return timingSafeEqual(aBuffer, bBuffer);
}

function getHeader(req: Request, name: string): string | null {
  const value = req.headers[name];
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }
  return typeof value === "string" ? value : null;
}

function getCookie(req: Request, name: string): string | null {
  const cookies = (req as Request & { cookies?: Record<string, unknown> })
    .cookies;
  const parsedCookie = cookies?.[name];
  if (typeof parsedCookie === "string") {
    return parsedCookie;
  }

  const header = req.headers.cookie;
  if (header === undefined) {
    return null;
  }

  for (const part of header.split(";")) {
    const [rawName, ...rawValueParts] = part.trim().split("=");
    if (rawName === name) {
      return decodeURIComponent(rawValueParts.join("="));
    }
  }

  return null;
}

function resolveCookieOptions(
  options: AuthCookieOptions = {},
): ResolvedAuthCookieOptions {
  const resolved: ResolvedAuthCookieOptions = {
    name: options.name ?? defaultCookie.name,
    path: options.path ?? defaultCookie.path,
    secure: options.secure ?? process.env.NODE_ENV === "production",
    sameSite: options.sameSite ?? defaultCookie.sameSite,
    httpOnly: options.httpOnly ?? defaultCookie.httpOnly,
  };
  if (options.domain !== undefined) {
    resolved.domain = options.domain;
  }
  return resolved;
}
