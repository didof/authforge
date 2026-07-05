# Publishing

The publishable packages are:

- `@authforge/core`
- `@authforge/argon2`
- `@authforge/sqlite`
- `@authforge/webauthn-oslo`
- `@authforge/express`

Live npm registry checks on July 5, 2026 returned `404 Not Found` for all package names above. Publishing still requires an npm account that can publish under the `@authforge` scope. If that scope is unavailable to the account, rename the packages before publishing.

## Preflight

```sh
pnpm run verify:release
```

This runs:

- type checks
- builds
- tests
- dependency audit
- module demos
- package tarball generation

## Publish

After confirming package names and npm access:

```sh
pnpm -C packages/core publish --access public
pnpm -C packages/argon2 publish --access public
pnpm -C packages/sqlite publish --access public
pnpm -C packages/webauthn-oslo publish --access public
pnpm -C packages/express publish --access public
```

Publish `@authforge/core` first because the other packages depend on it.

## Versioning

The first public package target is `0.1.0`. Until the API is stable, keep releases in the `0.x` line and use changelog entries for every externally visible behavior change.
