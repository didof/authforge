# Express SQLite Demo

This demo is a local API that wires AuthForge into Express with SQLite storage.

It includes:

- signup
- login
- logout
- session status
- email verification codes printed to the server console
- password reset tokens/codes printed to the server console
- TOTP setup and verification
- recovery-code factor reset
- WebAuthn challenge, registration, and assertion endpoints
- signed double-submit CSRF protection
- SQLite-backed rate limits

Run it:

```sh
pnpm build
pnpm --filter @authforge/example-express start
```

The server listens on `http://localhost:3000` by default and creates `authforge-example.sqlite` in this package directory unless `AUTHKIT_EXAMPLE_DB` is set.

## Curl Setup

Fetch a CSRF token and keep cookies:

```sh
CSRF=$(curl -s -c /tmp/authforge-cookies http://localhost:3000/csrf | node -e 'process.stdin.on("data", d => process.stdout.write(JSON.parse(d).csrfToken))')
```

Use the token in every POST:

```sh
-H "x-csrf-token: $CSRF" -b /tmp/authforge-cookies -c /tmp/authforge-cookies
```

## Signup

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"email":"user@example.com","password":"correct horse battery staple","username":"user"}' \
  http://localhost:3000/signup
```

The server console prints an email verification `requestId` and `code`.

## Session

```sh
curl -s -b /tmp/authforge-cookies http://localhost:3000/auth/session
```

## Email Verification

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"requestId":"REQUEST_ID_FROM_CONSOLE","code":"CODE_FROM_CONSOLE"}' \
  http://localhost:3000/email-verification/complete
```

## Login

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"email":"user@example.com","password":"correct horse battery staple"}' \
  http://localhost:3000/login
```

## TOTP

Setup:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{}' \
  http://localhost:3000/totp/setup
```

Verify using a code from an authenticator app:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"code":"123456"}' \
  http://localhost:3000/totp/verify
```

## Recovery Code

Create a recovery code while signed in:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{}' \
  http://localhost:3000/recovery-code/create
```

Reset second factors with that code:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"email":"user@example.com","recoveryCode":"CODE"}' \
  http://localhost:3000/recovery-code/reset-factors
```

## Password Reset

Start reset:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"email":"user@example.com"}' \
  http://localhost:3000/password-reset/start
```

The server console prints the reset `token` and `emailCode`.

Complete reset:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{"token":"TOKEN_FROM_CONSOLE","emailCode":"CODE_FROM_CONSOLE","newPassword":"new correct horse battery staple"}' \
  http://localhost:3000/password-reset/complete
```

If the account has TOTP registered, include `"totpCode":"123456"`.

## WebAuthn

Challenge creation is locally testable with curl:

```sh
curl -s -b /tmp/authforge-cookies -c /tmp/authforge-cookies \
  -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d '{}' \
  http://localhost:3000/auth/webauthn/challenge
```

Registration and assertion endpoints expect base64url-encoded WebAuthn payloads from a real client:

- `POST /webauthn/register`
- `POST /webauthn/assert`

## Notes

This is a local demo. Production apps must provide real email delivery, HTTPS, deployment-specific WebAuthn origins, proxy-aware IP handling for rate limits, and managed database migrations.
