import { Argon2PasswordHasher } from "@aeonkey/argon2";
import { checkPasswordStrength } from "@aeonkey/core";

const password = "correct horse battery staple";
const strength = await checkPasswordStrength(password);
const hasher = new Argon2PasswordHasher({
  memoryCost: 4096,
  timeCost: 1,
});
const hash = await hasher.hash(password);

console.log({
  module: "passwords",
  strongEnough: strength.ok,
  hashPreview: `${hash.slice(0, 24)}...`,
  verifies: await hasher.verify(hash, password),
  rejectsWrongPassword: !(await hasher.verify(hash, "wrong password")),
});
