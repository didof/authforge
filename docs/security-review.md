# Security Review

Date: July 5, 2026

## Verification

- `pnpm audit` passed with no known vulnerabilities.
- `pnpm run verify:release` passed end to end.
- Express demo smoke test passed for CSRF, signup, session status, and WebAuthn challenge creation.

## Flow Review

- Sessions: tokens are random, stored as SHA-256 hashes, expire, refresh, and can be invalidated by session or user.
- Passwords: hashing is adapter-provided; the Node adapter uses Argon2id through `@node-rs/argon2`.
- Email verification: codes are time-limited, single-use, and tied to user id plus request id.
- Password reset: sessions are time-limited, email-code gated, can require second factor, and invalidate existing user sessions after password change.
- Recovery codes: codes are hashed, rotate after use, and clear registered second factors through the store contract.
- TOTP: verification uses a configurable time window; production storage should wrap secrets with `EncryptedTotpCredentialStore`.
- WebAuthn: relying-party id and origins are required; challenge storage is single-use.
- Cookies: session cookies default to `HttpOnly`, `SameSite=Lax`, path `/`, and `Secure` in production.
- CSRF: Express exposes signed double-submit helpers for cookie-session POST routes.
- Rate limits: SQLite-backed persistent buckets are available; deployments must choose keys and trusted proxy handling.

## Remaining Risks

- WebAuthn positive-path fixtures are not committed yet. The verifier has invalid-input tests, but complete authenticator conformance needs deterministic raw registration/assertion fixtures.
- The SQLite schema helper is a reference schema. Production applications should own migrations.
- Email delivery in the demo is console-only.
- Login timing and user-enumeration policy are application decisions; AuthForge exposes primitives but does not force one global policy.
