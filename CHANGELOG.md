# Changelog

## 0.1.0

- Scaffold TypeScript monorepo.
- Add framework-free core package.
- Add session, email verification, password reset, rate limiting, 2FA policy, and WebAuthn challenge contracts.
- Add account store contracts and high-level `AuthForgeService`.
- Add durable SQLite account, factor-state, WebAuthn, and rate-limit storage.
- Add signed double-submit CSRF helpers for Express.
- Add development memory stores.
- Add Express adapter and SQLite-backed local demo server.
- Add module demos for password login and durable rate limits.
- Add CI workflow and release verification scripts.
- Add focused core, SQLite, and WebAuthn invalid-input tests.
