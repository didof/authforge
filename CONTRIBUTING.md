# Contributing

This project is pre-`0.1.0`, so the public API can still change quickly.

## Development

```sh
pnpm install
pnpm check
pnpm test
```

## Package boundaries

- Keep `@authkit/core` framework-free.
- Keep adapters thin. They should translate requests, cookies, redirects, and framework context into core calls.
- Put durable storage behind interfaces before adding database-specific code.
- Avoid copying demo route logic into adapters when the flow belongs in application code.

## Security-sensitive changes

Changes to sessions, password handling, recovery codes, TOTP, WebAuthn, or rate limiting need tests and a short note in the pull request explaining the threat model impact.
