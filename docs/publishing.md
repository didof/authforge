# Publishing

The publishable packages are:

- `@authforge/core`
- `@authforge/argon2`
- `@authforge/sqlite`
- `@authforge/webauthn-oslo`
- `@authforge/express`

Live npm registry checks on July 5, 2026 returned `404 Not Found` for all package names above. Publishing still requires an npm account that can publish under the `@authforge` scope. If that scope is unavailable to the account, rename the packages before publishing.

## Recommended Path

Publishing is handled by `.github/workflows/publish.yml` with npm Trusted Publishing through GitHub Actions OIDC. Do not add an `NPM_TOKEN` secret for this workflow.

The workflow:

- runs only for pushed tags matching `v*`
- uses `permissions: contents: read` and `id-token: write`
- runs on a GitHub-hosted Ubuntu runner
- uses Node 24 and npm `^11.5.1`
- runs `pnpm run verify:release`
- publishes the generated tarballs in dependency order

GitHub Actions standard hosted runners are free for public repositories. Private repositories have account-plan quotas and billing rules.

## npm Trusted Publisher Setup

Configure the same Trusted Publisher settings for each publishable package:

```txt
Provider: GitHub Actions
Organization or user: didof
Repository: authforge
Workflow filename: publish.yml
Environment name: npm-publish
Allowed actions: npm publish
```

The environment name must be `npm-publish` because the workflow declares `environment: npm-publish`.

After Trusted Publishing works, set each package's publishing access to require 2FA and disallow tokens. Traditional npm tokens are not needed for this workflow because npm exchanges the GitHub OIDC identity for short-lived publish credentials.

For the strictest npm-side release gate, change the workflow commands from `npm publish` to `npm stage publish`, and configure each Trusted Publisher with `Allowed actions: npm stage publish`. That stages packages from CI and requires a maintainer approval step before the versions become public.

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

## Release

Create a version tag that matches the package version:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The workflow publishes `@authforge/core` first because the other packages depend on it.

If npm does not allow Trusted Publisher configuration before the first version exists, use a one-time granular access token with the smallest possible scope to bootstrap the packages, then immediately configure Trusted Publishing, disallow traditional tokens, and revoke the bootstrap token.

## Versioning

The first public package target is `0.1.0`. Until the API is stable, keep releases in the `0.x` line and use changelog entries for every externally visible behavior change.

## References

- npm Trusted Publishing: https://docs.npmjs.com/trusted-publishers/
- GitHub Actions billing: https://docs.github.com/en/billing/concepts/product-billing/github-actions
