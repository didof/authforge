import { generateRecoveryCode } from "./otp.js";
import type { PasswordHasher } from "./passwords.js";
import type { RecoveryCodeStore } from "./stores.js";
import { type AuthResult, err, ok, type UserId } from "./types.js";

export interface RecoveryCodeServiceOptions {
  store: RecoveryCodeStore;
  hasher: PasswordHasher;
  codeBytes?: number;
}

export interface CreatedRecoveryCode {
  code: string;
}

export interface RotatedRecoveryCode {
  code: string;
}

export type RecoveryCodeResetError = "not_found" | "invalid_code" | "conflict";

export class RecoveryCodeService {
  private readonly store: RecoveryCodeStore;
  private readonly hasher: PasswordHasher;
  private readonly codeBytes: number;

  constructor(options: RecoveryCodeServiceOptions) {
    this.store = options.store;
    this.hasher = options.hasher;
    this.codeBytes = options.codeBytes ?? 10;
  }

  public async createRecoveryCode(
    userId: UserId,
  ): Promise<CreatedRecoveryCode> {
    const code = generateRecoveryCode({ bytes: this.codeBytes });
    await this.store.setRecoveryCodeHash(userId, await this.hasher.hash(code));
    return { code };
  }

  public async resetSecondFactors(
    userId: UserId,
    recoveryCode: string,
  ): Promise<AuthResult<RotatedRecoveryCode, RecoveryCodeResetError>> {
    const currentHash = await this.store.getRecoveryCodeHash(userId);
    if (currentHash === null) {
      return err("not_found");
    }

    const valid = await this.hasher.verify(currentHash, recoveryCode);
    if (!valid) {
      return err("invalid_code");
    }

    const nextCode = generateRecoveryCode({ bytes: this.codeBytes });
    const replaced = await this.store.replaceRecoveryCodeHashAndClearFactors({
      userId,
      currentHash,
      nextHash: await this.hasher.hash(nextCode),
    });

    if (!replaced) {
      return err("conflict");
    }

    return ok({ code: nextCode });
  }
}
