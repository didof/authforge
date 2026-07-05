# Core API

`@aeonkey/core` is framework-free. It exposes services and storage interfaces.

## Accounts and High-Level Auth

Use `AeonKeyService` when you want a complete password-auth flow over the lower-level primitives.

```ts
import {
  AeonKeyService,
  EmailVerificationService,
  PasswordResetService,
  RecoveryCodeService,
  SessionService,
  TotpService,
  createMemoryAuthStores,
} from "@aeonkey/core";
import { Argon2PasswordHasher } from "@aeonkey/argon2";

const stores = createMemoryAuthStores();
const passwordHasher = new Argon2PasswordHasher();
const sessions = new SessionService({ store: stores.sessions });

const auth = new AeonKeyService({
  accounts: stores.accounts,
  sessions,
  passwordHasher,
  emailVerification: new EmailVerificationService({
    store: stores.emailVerifications,
  }),
  passwordReset: new PasswordResetService({
    store: stores.passwordResets,
  }),
  totp: new TotpService({
    store: stores.totpCredentials,
    issuer: "Your App",
  }),
  recoveryCodes: new RecoveryCodeService({
    store: stores.recoveryCodes,
    hasher: passwordHasher,
  }),
});

const signup = await auth.signupWithPassword({
  email: "user@example.com",
  password: "correct horse battery staple",
});

const login = await auth.loginWithPassword({
  email: "user@example.com",
  password: "correct horse battery staple",
});
```

`AeonKeyService` exposes:

- `signupWithPassword`
- `loginWithPassword`
- `logout`
- `startEmailVerification`
- `completeEmailVerification`
- `startPasswordReset`
- `completePasswordReset`
- `setupTotp`
- `verifyTotp`
- `createRecoveryCode`
- `resetSecondFactorsWithRecoveryCode`
- `createWebAuthnChallenge`
- `registerWebAuthnCredential`
- `verifyWebAuthnAssertion`

Memory stores are for development and tests. Use `@aeonkey/sqlite` or another durable adapter for real applications.

## Sessions

```ts
import { MemorySessionStore, SessionService } from "@aeonkey/core";

const sessions = new SessionService({
  store: new MemorySessionStore(),
});

const created = await sessions.createSession({
  userId: "user-123",
});

const result = await sessions.validateToken(created.token);
```

## Password Policy

```ts
import { checkPasswordStrength } from "@aeonkey/core";

const result = await checkPasswordStrength("correct horse battery staple", {
  policy: {
    rejectPwnedPasswords: false,
  },
});
```

## Email Verification

```ts
import {
  EmailVerificationService,
  MemoryEmailVerificationStore,
} from "@aeonkey/core";

const service = new EmailVerificationService({
  store: new MemoryEmailVerificationStore(),
});

const request = await service.createRequest({
  userId: "user-123",
  email: "user@example.com",
});
```

Send `request.code` through your email provider. Then verify:

```ts
await service.verifyCode("user-123", request.id, request.code);
```

## Password Reset

```ts
import { MemoryPasswordResetStore, PasswordResetService } from "@aeonkey/core";

const service = new PasswordResetService({
  store: new MemoryPasswordResetStore(),
});

const reset = await service.createSession({
  userId: "user-123",
  email: "user@example.com",
});
```

## Recovery Codes

```ts
import { Argon2PasswordHasher } from "@aeonkey/argon2";
import { MemoryRecoveryCodeStore, RecoveryCodeService } from "@aeonkey/core";

const service = new RecoveryCodeService({
  store: new MemoryRecoveryCodeStore(),
  hasher: new Argon2PasswordHasher(),
});

const created = await service.createRecoveryCode("user-123");
```

Show `created.code` once to the user. Store only the hash.

## TOTP

```ts
import {
  MemoryTotpCredentialStore,
  TotpService,
  generateTotpCode,
} from "@aeonkey/core";

const service = new TotpService({
  store: new MemoryTotpCredentialStore(),
  issuer: "Your App",
});

const created = await service.createCredential({
  userId: "user-123",
  accountName: "user@example.com",
});

const code = await generateTotpCode(created.credential.key);
await service.verifyCode("user-123", code);
```

Production storage adapters should encrypt TOTP secrets at rest.

```ts
import {
  EncryptedTotpCredentialStore,
  MemoryTotpCredentialStore,
} from "@aeonkey/core";

const encryptedStore = new EncryptedTotpCredentialStore({
  store: new MemoryTotpCredentialStore(),
  key: encryptionKeyBytes,
});
```

## Rate Limiting

```ts
import { RefillingTokenBucket, Throttler } from "@aeonkey/core";

const ipBucket = new RefillingTokenBucket<string>(20, 1);
const loginThrottler = new Throttler<string>([1, 2, 4, 8, 16, 30]);
```

For durable rate limits, use `PersistentRefillingTokenBucket` with a `RateLimitStore`.

```ts
import { PersistentRefillingTokenBucket } from "@aeonkey/core";
import { SqliteAuthStore } from "@aeonkey/sqlite";

const sqliteAuthStore = new SqliteAuthStore(db);
const loginBucket = new PersistentRefillingTokenBucket({
  store: sqliteAuthStore,
  name: "login",
  max: 10,
  refillIntervalSeconds: 60,
});

if (!(await loginBucket.consume("ip:127.0.0.1:user@example.com", 1))) {
  throw new Error("Too many login attempts.");
}
```

The SQLite adapter stores rate buckets durably. It is still the application operator's responsibility to configure trusted proxy/IP handling and choose keys that match the deployment.

## WebAuthn Challenges

```ts
import {
  MemoryWebAuthnChallengeStore,
  WebAuthnChallengeService,
} from "@aeonkey/core";

const challenges = new WebAuthnChallengeService({
  store: new MemoryWebAuthnChallengeStore(),
});

const challenge = await challenges.createChallenge();
```

The challenge service handles creation and single-use consumption.

## WebAuthn Verifier

```ts
import { WebAuthnService } from "@aeonkey/core";
import { OsloWebAuthnVerifier } from "@aeonkey/webauthn-oslo";

const service = new WebAuthnService({
  relyingParty: {
    id: "example.com",
    name: "Example",
    origins: ["https://example.com"],
  },
  challengeService,
  credentialStore,
  verifier: new OsloWebAuthnVerifier(),
});
```
