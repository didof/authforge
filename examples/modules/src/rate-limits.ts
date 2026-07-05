import {
  ExpiringTokenBucket,
  RefillingTokenBucket,
  Throttler,
} from "@aeonkey/core";

const postBucket = new RefillingTokenBucket<string>(2, 60);
const totpBucket = new ExpiringTokenBucket<string>(2, 60 * 30);
const loginThrottler = new Throttler<string>([1, 2, 4]);

console.log({
  module: "rate-limits",
  firstPost: postBucket.consume("127.0.0.1", 1),
  secondPost: postBucket.consume("127.0.0.1", 1),
  thirdPostBlocked: !postBucket.consume("127.0.0.1", 1),
  firstTotpAttempt: totpBucket.consume("user-123", 1),
  loginAttemptAllowed: loginThrottler.consume("user-123"),
});
