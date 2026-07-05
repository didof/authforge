import { describe, expect, it } from "vitest";
import { Argon2PasswordHasher } from "../src/index.js";

describe("Argon2PasswordHasher", () => {
  it("hashes and verifies passwords", async () => {
    const hasher = new Argon2PasswordHasher({
      memoryCost: 4096,
      timeCost: 1,
    });
    const hash = await hasher.hash("correct horse battery staple");

    expect(hash).not.toBe("correct horse battery staple");
    expect(await hasher.verify(hash, "correct horse battery staple")).toBe(
      true,
    );
    expect(await hasher.verify(hash, "wrong password")).toBe(false);
  });
});
