import { type Clock, systemClock } from "./types.js";
import type { RateLimitStore, StoredRateLimitBucket } from "./stores.js";

export interface PersistentRefillingTokenBucketOptions {
  store: RateLimitStore;
  name: string;
  max: number;
  refillIntervalSeconds: number;
  clock?: Clock;
}

export class PersistentRefillingTokenBucket {
  private readonly store: RateLimitStore;
  private readonly name: string;
  private readonly clock: Clock;
  public readonly max: number;
  public readonly refillIntervalSeconds: number;

  constructor(options: PersistentRefillingTokenBucketOptions) {
    this.store = options.store;
    this.name = options.name;
    this.clock = options.clock ?? systemClock;
    this.max = options.max;
    this.refillIntervalSeconds = options.refillIntervalSeconds;
  }

  public async check(key: string, cost: number): Promise<boolean> {
    const bucket = await this.store.getRateLimitBucket(this.name, key);
    if (bucket === null) {
      return true;
    }
    return this.refill(bucket).count >= cost;
  }

  public async consume(key: string, cost: number): Promise<boolean> {
    const now = this.clock.now();
    const stored = await this.store.getRateLimitBucket(this.name, key);
    const bucket =
      stored === null
        ? {
            name: this.name,
            key,
            count: this.max,
            updatedAt: now,
            expiresAt: this.expiresAt(now),
          }
        : this.refill(stored);

    bucket.updatedAt = now;
    bucket.expiresAt = this.expiresAt(now);

    if (bucket.count < cost) {
      await this.store.setRateLimitBucket(bucket);
      return false;
    }

    bucket.count -= cost;
    await this.store.setRateLimitBucket(bucket);
    return true;
  }

  public async reset(key: string): Promise<void> {
    await this.store.deleteRateLimitBucket(this.name, key);
  }

  public async deleteExpiredBuckets(): Promise<void> {
    await this.store.deleteExpiredRateLimitBuckets(this.clock.now());
  }

  private refill(bucket: StoredRateLimitBucket): StoredRateLimitBucket {
    const now = this.clock.now();
    const elapsed = now.getTime() - bucket.updatedAt.getTime();
    const tokens = Math.floor(elapsed / (this.refillIntervalSeconds * 1000));
    return {
      ...bucket,
      count: Math.min(bucket.count + tokens, this.max),
    };
  }

  private expiresAt(now: Date): Date {
    return new Date(
      now.getTime() + this.max * this.refillIntervalSeconds * 1000,
    );
  }
}

export class RefillingTokenBucket<Key> {
  private readonly storage = new Map<Key, RefillBucket>();
  private readonly clock: Clock;

  constructor(
    public readonly max: number,
    public readonly refillIntervalSeconds: number,
    options: { clock?: Clock } = {},
  ) {
    this.clock = options.clock ?? systemClock;
  }

  public check(key: Key, cost: number): boolean {
    const bucket = this.storage.get(key);
    if (bucket === undefined) {
      return true;
    }
    const refill = this.getRefill(bucket);
    return Math.min(bucket.count + refill, this.max) >= cost;
  }

  public consume(key: Key, cost: number): boolean {
    const now = this.clock.now().getTime();
    const bucket = this.storage.get(key) ?? {
      count: this.max,
      refilledAt: now,
    };
    const refill = this.getRefill(bucket);
    bucket.count = Math.min(bucket.count + refill, this.max);
    bucket.refilledAt = now;

    if (bucket.count < cost) {
      this.storage.set(key, bucket);
      return false;
    }

    bucket.count -= cost;
    this.storage.set(key, bucket);
    return true;
  }

  public reset(key: Key): void {
    this.storage.delete(key);
  }

  private getRefill(bucket: RefillBucket): number {
    const elapsed = this.clock.now().getTime() - bucket.refilledAt;
    return Math.floor(elapsed / (this.refillIntervalSeconds * 1000));
  }
}

export class ExpiringTokenBucket<Key> {
  private readonly storage = new Map<Key, ExpiringBucket>();
  private readonly clock: Clock;

  constructor(
    public readonly max: number,
    public readonly expiresInSeconds: number,
    options: { clock?: Clock } = {},
  ) {
    this.clock = options.clock ?? systemClock;
  }

  public check(key: Key, cost: number): boolean {
    const bucket = this.storage.get(key);
    if (bucket === undefined || this.isExpired(bucket)) {
      return true;
    }
    return bucket.count >= cost;
  }

  public consume(key: Key, cost: number): boolean {
    const now = this.clock.now().getTime();
    let bucket = this.storage.get(key);

    if (bucket === undefined || this.isExpired(bucket)) {
      bucket = { count: this.max, createdAt: now };
    }

    if (bucket.count < cost) {
      this.storage.set(key, bucket);
      return false;
    }

    bucket.count -= cost;
    this.storage.set(key, bucket);
    return true;
  }

  public reset(key: Key): void {
    this.storage.delete(key);
  }

  private isExpired(bucket: ExpiringBucket): boolean {
    return (
      this.clock.now().getTime() - bucket.createdAt >=
      this.expiresInSeconds * 1000
    );
  }
}

export class Throttler<Key> {
  private readonly storage = new Map<Key, ThrottlingCounter>();
  private readonly clock: Clock;

  constructor(
    public readonly timeoutSeconds: number[],
    options: { clock?: Clock } = {},
  ) {
    this.clock = options.clock ?? systemClock;
  }

  public consume(key: Key): boolean {
    const now = this.clock.now().getTime();
    const counter = this.storage.get(key);
    if (counter === undefined) {
      this.storage.set(key, { timeout: 0, updatedAt: now });
      return true;
    }

    const waitSeconds =
      this.timeoutSeconds[counter.timeout] ?? this.timeoutSeconds.at(-1) ?? 0;

    if (now - counter.updatedAt < waitSeconds * 1000) {
      this.storage.set(key, counter);
      return false;
    }

    counter.updatedAt = now;
    counter.timeout = Math.min(
      counter.timeout + 1,
      Math.max(this.timeoutSeconds.length - 1, 0),
    );
    this.storage.set(key, counter);
    return true;
  }

  public reset(key: Key): void {
    this.storage.delete(key);
  }
}

interface RefillBucket {
  count: number;
  refilledAt: number;
}

interface ExpiringBucket {
  count: number;
  createdAt: number;
}

interface ThrottlingCounter {
  timeout: number;
  updatedAt: number;
}
