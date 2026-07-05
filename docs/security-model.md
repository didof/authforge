# Security Model

AuthForge provides authentication building blocks. It is not an identity provider and it does not replace application-specific authorization.

## Defaults

- Session tokens are generated with Web Crypto random bytes.
- Session tokens are stored as SHA-256 hashes.
- Session expiration rotates inside a configurable refresh window.
- Account email lookup is normalized by the high-level auth service.
- Email verification codes are single use.
- Password reset sessions are time-limited.
- Password reset completion invalidates existing user sessions.
- Recovery codes are hashed through the configured password hasher and rotate after use.
- TOTP storage can be wrapped with `EncryptedTotpCredentialStore` for AES-GCM encryption at rest.
- WebAuthn challenge storage is single use.
- WebAuthn relying-party ID and origins are explicit configuration.
- Cookie helpers default to `HttpOnly`, `SameSite=Lax`, path `/`, and `Secure` in production.
- Express CSRF helpers use signed double-submit tokens for cookie-session POST routes.
- SQLite can persist account, session, factor, WebAuthn, and rate-limit state.

## Required Production Decisions

- Use a durable session store.
- Use a shared durable rate limiter in multi-instance deployments.
- Configure trusted proxy/IP handling in the HTTP framework.
- Apply CSRF protection to every state-changing cookie-authenticated route.
- Configure WebAuthn `rpId` and allowed origins for the actual domain.
- Store the TOTP encryption key outside the database.
- Use HTTPS in production.
- Send email through a real provider.
- Choose whether login and reset flows should hide user-enumeration signals.
- Decide whether to require verified email before login.
- Decide how to rotate password hashes when Argon2 parameters change.

## Development-Only Pieces

The memory stores are for tests, examples, and local development. They are not durable, distributed, or concurrency-safe.

## Known Test Boundary

The WebAuthn verifier has robust invalid-input tests. Positive-path registration/assertion tests require deterministic raw authenticator fixtures for `attestationObject`, `authenticatorData`, `clientDataJSON`, and signatures. Those fixtures are not committed yet, so that work remains a release-hardening item rather than faking a credential path.

## Dependency Audit

Run:

```sh
pnpm audit
```

The release verification command includes this audit.
