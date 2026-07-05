import {
  MemoryWebAuthnChallengeStore,
  WebAuthnChallengeService,
} from "@aeonkey/core";

const challenges = new WebAuthnChallengeService({
  store: new MemoryWebAuthnChallengeStore(),
});

const created = await challenges.createChallenge();
const firstUse = await challenges.consumeChallenge(created.challenge);
const replay = await challenges.consumeChallenge(created.challenge);

console.log({
  module: "webauthn-challenges",
  challenge: created.encodedChallenge,
  firstUseAccepted: firstUse.ok,
  replayRejected: !replay.ok,
});
