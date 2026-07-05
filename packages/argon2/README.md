# @authforge/argon2

Argon2 password hasher for AuthForge on Node.js.

## Install

```sh
pnpm add @authforge/argon2
```

## Usage

```ts
import { Argon2PasswordHasher } from "@authforge/argon2";

const hasher = new Argon2PasswordHasher();
const hash = await hasher.hash("password");
const valid = await hasher.verify(hash, "password");
```
