# Roadmap

## 0.1.0

- Freeze core service APIs after final verification.
- Expand production password hasher package docs with deployment guidance.
- Expand durable storage adapter docs with migration/versioning guidance.
- Add positive-path WebAuthn fixture tests.
- Publish API docs.
- Add real repository metadata after a public remote exists.

## Implemented for 0.1.0 Candidates

- Account store contract and SQLite account table.
- High-level `AeonKeyService` for signup, login, verification, reset, TOTP, recovery codes, and WebAuthn helpers.
- SQLite-backed rate-limit bucket store.
- Signed double-submit CSRF helpers for Express.
- Full local Express API demo backed by SQLite.

## 0.2.0

- Add Next.js adapter.
- Add SvelteKit adapter.
- Add Astro adapter.
- Add CLI scaffolding for migrations and routes.

## 0.3.0

- Add Drizzle or Prisma adapter.
- Add Redis-backed rate limiting and challenge storage.
- Add security review checklist and example threat model.
