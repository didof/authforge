import type { AuthUser } from "./types.js";

export type SecondFactorMethod = "passkey" | "security-key" | "totp";

export interface SecondFactorPolicy {
  preferredOrder?: SecondFactorMethod[];
  setupPath?: string;
  verifyPaths?: Partial<Record<SecondFactorMethod, string>>;
}

export interface SecondFactorState {
  registered: boolean;
  verified: boolean;
  nextPath: string | null;
  method: SecondFactorMethod | null;
}

const defaultOrder: SecondFactorMethod[] = ["passkey", "security-key", "totp"];

export function hasRegisteredSecondFactor(user: AuthUser): boolean {
  return user.factors.passkey || user.factors.securityKey || user.factors.totp;
}

export function getPreferredSecondFactor(
  user: AuthUser,
  preferredOrder: SecondFactorMethod[] = defaultOrder,
): SecondFactorMethod | null {
  for (const method of preferredOrder) {
    if (method === "passkey" && user.factors.passkey) {
      return method;
    }
    if (method === "security-key" && user.factors.securityKey) {
      return method;
    }
    if (method === "totp" && user.factors.totp) {
      return method;
    }
  }
  return null;
}

export function getSecondFactorState(
  user: AuthUser,
  session: { twoFactorVerified: boolean },
  policy: SecondFactorPolicy = {},
): SecondFactorState {
  const order = policy.preferredOrder ?? defaultOrder;
  const method = getPreferredSecondFactor(user, order);
  const registered = method !== null;

  if (!registered) {
    return {
      registered: false,
      verified: false,
      method: null,
      nextPath: policy.setupPath ?? "/2fa/setup",
    };
  }

  if (session.twoFactorVerified) {
    return {
      registered: true,
      verified: true,
      method,
      nextPath: null,
    };
  }

  return {
    registered: true,
    verified: false,
    method,
    nextPath: policy.verifyPaths?.[method] ?? `/2fa/${method}`,
  };
}
