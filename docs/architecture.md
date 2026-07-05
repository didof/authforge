# Architecture

AeonKey is split into a framework-free core and small adapters.

## Core

The core package owns:

- auth state machines
- token generation and hashing
- password policies
- session validation
- verification and reset request lifecycles
- 2FA policy decisions
- WebAuthn challenge lifecycle contracts
- persistence interfaces

The core must not import Express, Next.js, SvelteKit, Astro, or any UI framework.

## Adapters

Adapters translate framework concerns into core calls:

- request body parsing
- cookies
- redirects
- trusted client IP extraction
- route handlers and middleware
- framework-specific cache/local context

## Storage

Storage is a replaceable boundary. The first implementation should be memory-only for tests and examples. Production adapters should follow after the public API is stable.

## WebAuthn

WebAuthn verification is security-sensitive. The core should expose stable challenge and credential contracts. Cryptographic registration/assertion verification should be implemented through a dedicated verifier module with explicit relying-party configuration.
