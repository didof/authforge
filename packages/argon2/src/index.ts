import { hash, verify } from "@node-rs/argon2";
import type { PasswordHasher } from "@aeonkey/core";

export interface Argon2PasswordHasherOptions {
  memoryCost?: number;
  timeCost?: number;
  outputLen?: number;
  parallelism?: number;
}

export class Argon2PasswordHasher implements PasswordHasher {
  private readonly options: Required<Argon2PasswordHasherOptions>;

  constructor(options: Argon2PasswordHasherOptions = {}) {
    this.options = {
      memoryCost: options.memoryCost ?? 19456,
      timeCost: options.timeCost ?? 2,
      outputLen: options.outputLen ?? 32,
      parallelism: options.parallelism ?? 1,
    };
  }

  public async hash(password: string): Promise<string> {
    return hash(password, this.options);
  }

  public async verify(hashValue: string, password: string): Promise<boolean> {
    return verify(hashValue, password);
  }
}
