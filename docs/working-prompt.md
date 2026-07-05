# Working Prompt

Build AuthForge into a release-quality open-source TypeScript authentication toolkit that real developers can install, understand, run locally, test, and safely extend.

## Acceptance criteria

- The repository is package-first and publish-ready.
- Every public package has clear metadata, exports, license, build scripts, and tests.
- Core APIs are documented with practical examples.
- Security-sensitive behavior is explicit: session token hashing, cookie defaults, password hashing, password reset, recovery codes, WebAuthn relying-party configuration, and rate limiting.
- Each module has a runnable local demo or example.
- Demos are small, testable, and do not require third-party accounts.
- Verification commands pass from a clean checkout: install, build, check, test, audit where possible.
- Known production gaps are documented plainly rather than hidden.
- No framework adapter contains business logic that belongs in the core.
- No storage implementation is presented as production-ready unless it is durable and concurrency-aware.

## Current stack decision

- TypeScript is the implementation language.
- Express is the first HTTP adapter because it is stable, widely adopted, and keeps the project aligned with the original TypeScript source material.
- FastAPI is not the first target because it would require a Python port before the TypeScript API is stable.

## Immediate priorities

1. Package metadata and publish configuration.
2. Runnable demos per module.
3. Security and dependency audit.
4. Documentation that explains both use and threat-model boundaries.
5. Release checklist with concrete pass/fail commands.
