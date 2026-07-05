import { Argon2PasswordHasher } from "@aeonkey/argon2";
import {
  AeonKeyService,
  SessionService,
  createMemoryAuthStores,
} from "@aeonkey/core";

const stores = createMemoryAuthStores();
const sessions = new SessionService({ store: stores.sessions });
const passwordHasher = new Argon2PasswordHasher({
  memoryCost: 4096,
  timeCost: 1,
});
const auth = new AeonKeyService({
  accounts: stores.accounts,
  sessions,
  passwordHasher,
  accountIdGenerator: () => "user-123",
});

const signup = await auth.signupWithPassword({
  email: "User@example.com",
  password: "correct horse battery staple",
  createSession: false,
});
const login = await auth.loginWithPassword({
  email: "user@example.com",
  password: "correct horse battery staple",
});
const wrongPassword = await auth.loginWithPassword({
  email: "user@example.com",
  password: "wrong password",
});

console.log({
  module: "password-login",
  signupOk: signup.ok,
  normalizedEmail: signup.ok ? signup.value.user.email : null,
  loginOk: login.ok,
  sessionCreated: login.ok,
  wrongPasswordRejected: !wrongPassword.ok,
});
