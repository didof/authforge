export type UserId = string | number;

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export interface AuthUser {
  id: UserId;
  email: string;
  username?: string;
  emailVerified: boolean;
  factors: RegisteredFactors;
}

export interface RegisteredFactors {
  totp: boolean;
  passkey: boolean;
  securityKey: boolean;
}

export interface AuthResultSuccess<T> {
  ok: true;
  value: T;
}

export interface AuthResultFailure<E extends string = string> {
  ok: false;
  error: E;
}

export type AuthResult<T, E extends string = string> =
  AuthResultSuccess<T> | AuthResultFailure<E>;

export function ok<T>(value: T): AuthResultSuccess<T> {
  return { ok: true, value };
}

export function err<E extends string>(error: E): AuthResultFailure<E> {
  return { ok: false, error };
}
