# Release Checklist

- [x] Core package has public exports for accounts, services, stores, rate limits, and WebAuthn contracts.
- [x] Express adapter has a working SQLite-backed local example.
- [x] Memory store is marked development-only.
- [x] Production storage adapter exists.
- [x] WebAuthn relying-party ID and origins are required config.
- [x] Rate limiting can use durable shared storage through SQLite.
- [x] Password hashing implementation is configurable.
- [x] HIBP checks are optional and documented.
- [x] README links to security model and release docs.
- [x] Tests cover accounts, sessions, password policy, OTP, rate limits, and reset flows.
- [x] Package metadata includes license, exports, files, engines, publish config, and side effects.
- [x] Package metadata includes real repository URLs for `didof/authforge`.
- [ ] WebAuthn positive-path fixture tests exist.

## Current 0.1.0 Preflight

- [x] `pnpm check` passed on July 5, 2026.
- [x] `pnpm test` passed on July 5, 2026.
- [x] `pnpm audit` passed with no known vulnerabilities on July 5, 2026.
- [x] `pnpm demo:modules` passed on July 5, 2026.
- [x] `pnpm run pack:packages` passed on July 5, 2026.
- [x] `pnpm run verify:release` passed end to end on July 5, 2026.
- [x] Express demo smoke test passed on July 5, 2026: `GET /csrf`, `POST /signup`, `GET /auth/session`, and `POST /auth/webauthn/challenge`.
- [x] Package tarballs include `README.md` and `LICENSE`.
- [x] npm registry returned 404 for `@authforge/core`, `@authforge/argon2`, and `@authforge/express` on July 5, 2026.
- [x] npm registry returned 404 for `@authforge/sqlite` and `@authforge/webauthn-oslo` on July 5, 2026.

## Not Yet 0.1.0

- [ ] Add positive-path WebAuthn registration/assertion fixtures.
