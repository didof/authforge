# @authforge/sqlite

SQLite storage adapter for AuthForge.

## Install

```sh
pnpm add @authforge/core @authforge/sqlite better-sqlite3
```

## Usage

```ts
import Database from "better-sqlite3";
import { SessionService } from "@authforge/core";
import { SqliteAuthStore, createSqliteAuthSchema } from "@authforge/sqlite";

const db = new Database("auth.db");
createSqliteAuthSchema(db);

const store = new SqliteAuthStore(db);
const sessions = new SessionService({ store });
```

The store implements the durable AuthForge contracts for:

- accounts
- sessions
- email verification requests
- password reset sessions
- recovery codes
- TOTP credentials
- WebAuthn challenges and credentials
- persistent rate-limit buckets

`createSqliteAuthSchema()` creates the demo/reference schema. Review and own migrations in production applications.
