# @aeonkey/argon2

Argon2 password hasher for AeonKey on Node.js.

## Install

```sh
pnpm add @aeonkey/argon2
```

## Usage

```ts
import { Argon2PasswordHasher } from "@aeonkey/argon2";

const hasher = new Argon2PasswordHasher();
const hash = await hasher.hash("password");
const valid = await hasher.verify(hash, "password");
```
