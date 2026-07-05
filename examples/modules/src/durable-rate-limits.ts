import Database from "better-sqlite3";
import { PersistentRefillingTokenBucket } from "@authforge/core";
import { SqliteAuthStore, createSqliteAuthSchema } from "@authforge/sqlite";

const db = new Database(":memory:");
createSqliteAuthSchema(db);
const store = new SqliteAuthStore(db);

const loginBucket = new PersistentRefillingTokenBucket({
  store,
  name: "login",
  max: 2,
  refillIntervalSeconds: 60,
});

const key = "ip:127.0.0.1:user@example.com";
const first = await loginBucket.consume(key, 1);
const second = await loginBucket.consume(key, 1);
const third = await loginBucket.consume(key, 1);
const stored = await store.getRateLimitBucket("login", key);

console.log({
  module: "durable-rate-limits",
  first,
  second,
  thirdBlocked: !third,
  persistedCount: stored?.count ?? null,
});
