import { Argon2PasswordHasher } from "@aeonkey/argon2";
import { MemoryRecoveryCodeStore, RecoveryCodeService } from "@aeonkey/core";

const recoveryCodes = new RecoveryCodeService({
  store: new MemoryRecoveryCodeStore(),
  hasher: new Argon2PasswordHasher({
    memoryCost: 4096,
    timeCost: 1,
  }),
});

const created = await recoveryCodes.createRecoveryCode("user-123");
const reset = await recoveryCodes.resetSecondFactors("user-123", created.code);
const replay = await recoveryCodes.resetSecondFactors("user-123", created.code);

console.log({
  module: "recovery-codes",
  firstCodeLength: created.code.length,
  resetAccepted: reset.ok,
  replayRejected: !replay.ok,
  rotatedCodeLength: reset.ok ? reset.value.code.length : null,
});
