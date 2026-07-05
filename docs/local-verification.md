# Local Verification

Run these commands from the repository root.

```sh
pnpm install
pnpm check
pnpm test
pnpm audit
pnpm demo:modules
pnpm run pack:packages
```

For a full release-readiness pass:

```sh
pnpm run verify:release
```

The package tarballs are written to `artifacts/`.

## Express example

```sh
pnpm build
pnpm --filter @authforge/example-express start
```

Then call:

```sh
curl http://localhost:3000/
CSRF=$(curl -s -c /tmp/authforge-cookies http://localhost:3000/csrf | node -e 'process.stdin.on("data", d => process.stdout.write(JSON.parse(d).csrfToken))')
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"email":"user@example.com","password":"correct horse battery staple"}' \
  http://localhost:3000/signup
curl -s -b /tmp/authforge-cookies http://localhost:3000/auth/session
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{}' \
  http://localhost:3000/auth/webauthn/challenge
```
