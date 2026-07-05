# Module Examples

These examples show each AuthForge module separately.

Run all examples:

```sh
pnpm demo:modules
```

Run a single example:

```sh
pnpm build
pnpm --filter @authforge/example-modules demo:sessions
pnpm --filter @authforge/example-modules demo:passwords
pnpm --filter @authforge/example-modules demo:password-login
pnpm --filter @authforge/example-modules demo:email-verification
pnpm --filter @authforge/example-modules demo:password-reset
pnpm --filter @authforge/example-modules demo:recovery-codes
pnpm --filter @authforge/example-modules demo:totp
pnpm --filter @authforge/example-modules demo:rate-limits
pnpm --filter @authforge/example-modules demo:durable-rate-limits
pnpm --filter @authforge/example-modules demo:two-factor
pnpm --filter @authforge/example-modules demo:webauthn-challenges
pnpm --filter @authforge/example-modules demo:webauthn-verifier
```
