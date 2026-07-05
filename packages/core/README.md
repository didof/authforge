# @aeonkey/core

Framework-free authentication primitives for TypeScript applications.

## Install

```sh
pnpm add @aeonkey/core
```

## Includes

- Account store contracts
- `AeonKeyService` high-level signup, login, verification, reset, TOTP, recovery-code, and WebAuthn flow helpers
- Sessions
- Email verification
- Password reset sessions
- Recovery codes
- TOTP credentials
- Password policy checks
- In-memory development rate limiters
- Persistent rate-limit bucket service
- 2FA method policy
- WebAuthn challenge and verifier contracts
- Development memory stores

Memory stores are for local development and tests. Use a durable adapter for production.

See the root repository docs for runnable examples and security notes.
