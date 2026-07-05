# AuthForge

AuthForge is a TypeScript authentication toolkit inspired by the architecture of the Lucia email/password, 2FA, and WebAuthn demo.

The goal is to provide framework-agnostic auth primitives first, then thin adapters for Express, Next.js, SvelteKit, Astro, and other HTTP frameworks.

## Modules

- Email and password authentication
- User/account store contracts
- Password hashing and Have I Been Pwned checks
- Sessions with rotating expiration
- Email verification
- Password reset with second-factor verification
- TOTP credentials
- Recovery codes
- Passkeys and security keys through WebAuthn
- In-memory development rate limiters
- Durable rate limiting through the store contract
- Development memory stores and a durable SQLite adapter
- Future storage adapters can target Postgres, Drizzle, Prisma, and other databases

## Package layout

```txt
packages/core      Framework-free auth primitives, services, and contracts
packages/argon2    Node.js Argon2 password hasher
packages/sqlite    SQLite storage adapter
packages/webauthn-oslo Oslo-backed WebAuthn verifier
packages/express   Express-compatible adapter
examples/express   SQLite-backed local HTTP demo
examples/modules   Independent runnable demos for each module
docs               Design notes and release checklist
```

## Status

This repository is being shaped toward a first public release. APIs are expected to change until `0.1.0`.

## Current implementation

- `@authforge/core`
  - Session tokens, hashing, rotation, invalidation
  - Account model and account store contract
  - High-level `AuthForgeService` for signup, login, verification, reset, TOTP, recovery code, and WebAuthn flows
  - Email verification request lifecycle
  - Password reset session lifecycle
  - TOTP credential lifecycle
  - Password policy and optional HIBP lookup
  - Memory token buckets, throttling, and persistent rate-limit bucket service
  - 2FA method selection
  - WebAuthn challenge and credential contracts
  - Development memory stores
- `@authforge/argon2`
  - Node.js Argon2 password hasher
- `@authforge/express`
  - Session middleware
  - Cookie helpers
  - Signed double-submit CSRF helpers
  - Auth router with session, logout, and WebAuthn challenge endpoints
- `@authforge/sqlite`
  - Durable SQLite implementation for accounts, sessions, verification, reset, TOTP, recovery codes, WebAuthn, and rate-limit buckets
- `@authforge/webauthn-oslo`
  - WebAuthn registration/assertion verifier implementation
- `examples/express`
  - SQLite-backed server with signup, login, logout, session status, console email verification, console password reset, TOTP, recovery codes, WebAuthn wiring, CSRF, and durable rate limits

## Quickstart

```sh
pnpm install
pnpm check
pnpm test
pnpm demo:modules
```

Run the Express demo:

```sh
pnpm build
pnpm --filter @authforge/example-express start
```

Fetch a CSRF token before POST requests:

```sh
curl -c /tmp/authforge-cookies http://localhost:3000/csrf
```

The Express demo prints email verification and password reset codes to the server console. It does not require third-party email, OAuth, or passkey services.

## Development

```sh
pnpm install
pnpm check
pnpm test
pnpm audit
pnpm demo:modules
pnpm run verify:release
```

## Documentation

- [Architecture](docs/architecture.md)
- [Core API](docs/core-api.md)
- [Express adapter](docs/express-adapter.md)
- [Security model](docs/security-model.md)
- [Security review](docs/security-review.md)
- [Local verification](docs/local-verification.md)
- [Publishing](docs/publishing.md)
- [Roadmap](docs/roadmap.md)

## Stack decision

The first HTTP adapter is Express because it keeps the project in the TypeScript ecosystem of the original Lucia examples and remains a stable integration target. FastAPI is a strong Python API framework, but choosing it first would turn this into a porting project before the TypeScript package API is stable.
