# Security Policy

AuthForge is not production-ready yet. Until the first audited release, use it as a reference implementation or experimental toolkit.

## Reporting vulnerabilities

Please report security issues privately before opening a public issue. Add enough detail to reproduce the behavior, including affected package, version, and configuration.

## Security goals

- Session tokens are stored hashed at rest.
- Verification and reset codes are single use.
- WebAuthn relying-party ID and allowed origins are explicit configuration.
- Rate limiting is pluggable so production deployments can use durable shared stores.
- Password hashing is configurable so applications can choose their operational parameters.

## Non-goals

- AuthForge is not an identity provider.
- AuthForge does not manage user profile schemas.
- AuthForge does not hide all user-enumeration signals by default; applications should choose their UX and threat model.
