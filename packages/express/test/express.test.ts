import { describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";
import {
  clearAuthCookie,
  createCsrfProtection,
  createCsrfToken,
  setAuthCookie,
  verifyCsrfToken,
} from "../src/index.js";

describe("cookie helpers", () => {
  it("sets and clears auth cookies with secure defaults", () => {
    const res = createMockResponse();

    setAuthCookie(res, "token", new Date("2026-01-01T00:00:00.000Z"), {
      secure: true,
    });
    clearAuthCookie(res, { secure: true });

    expect(res.setCookies[0]).toContain("session=token");
    expect(res.setCookies[0]).toContain("HttpOnly");
    expect(res.setCookies[0]).toContain("Secure");
    expect(res.setCookies[1]).toContain("Max-Age=0");
  });
});

describe("CSRF helpers", () => {
  it("creates signed tokens and rejects tampering", () => {
    const token = createCsrfToken({ secret: "test-secret" });

    expect(verifyCsrfToken({ secret: "test-secret", token })).toBe(true);
    expect(
      verifyCsrfToken({
        secret: "test-secret",
        token: token.replace(".", "x."),
      }),
    ).toBe(false);
  });

  it("sets a token cookie on safe methods and requires it on unsafe methods", () => {
    const middleware = createCsrfProtection({ secret: "test-secret" });
    const getResponse = createMockResponse();
    const next = vi.fn();

    middleware(createMockRequest("GET"), getResponse, next);

    expect(next).toHaveBeenCalledOnce();
    expect(getResponse.setCookies[0]).toContain("csrf=");

    const csrfToken = decodeURIComponent(
      getResponse.setCookies[0]!.match(/^csrf=([^;]+)/)![1]!,
    );
    const postResponse = createMockResponse();
    const postNext = vi.fn();
    middleware(
      createMockRequest("POST", {
        cookie: `csrf=${encodeURIComponent(csrfToken)}`,
        "x-csrf-token": csrfToken,
      }),
      postResponse,
      postNext,
    );

    expect(postNext).toHaveBeenCalledOnce();

    const blockedResponse = createMockResponse();
    middleware(createMockRequest("POST"), blockedResponse, vi.fn());
    expect(blockedResponse.statusCode).toBe(403);
    expect(blockedResponse.body).toEqual({ error: "csrf_invalid" });
  });
});

interface MockResponse extends Response {
  body: unknown;
  setCookies: string[];
  statusCode: number;
}

function createMockResponse(): MockResponse {
  const response = {
    body: null,
    locals: {},
    setCookies: [] as string[],
    statusCode: 200,
    append(name: string, value: string) {
      if (name.toLowerCase() === "set-cookie") {
        this.setCookies.push(value);
      }
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
    status(statusCode: number) {
      this.statusCode = statusCode;
      return this;
    },
  };
  return response as unknown as MockResponse;
}

function createMockRequest(
  method: string,
  headers: Record<string, string> = {},
): Request {
  return {
    headers,
    method,
  } as Request;
}
