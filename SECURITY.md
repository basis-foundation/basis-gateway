# Security Policy

## Scope

This repository contains `basis-gateway`, the authentication, identity normalization, and HTTP enforcement boundary for the BASIS ecosystem. It authenticates callers via OIDC/JWT, delegates authorization decisions to `basis-core`, enforces decisions at the HTTP boundary, and emits structured audit evidence.

`basis-gateway` is a pre-production proof of concept. It is not yet suitable for deployment in production operational technology environments without additional security review, hardening, and integration work. The known limitations are documented in [`docs/release-readiness.md`](docs/release-readiness.md).

## Reporting Security Issues

Please report security vulnerabilities by opening a **private security advisory** on GitHub (Security → Advisories → New draft security advisory), or by contacting the repository owners directly via the profiles listed in this organization.

Do not open a public issue for security vulnerabilities.

Appropriate reports include:

- Authentication or token verification bypasses
- Identity normalization errors that could lead to incorrect subject assignment
- Audit evidence gaps that could allow undetected authorization events
- Correlation ID handling weaknesses that could allow audit trail manipulation
- Committed secrets, credentials, or sensitive configuration
- Unsafe deployment examples or documentation that could lead to insecure configurations
- Dependencies with known vulnerabilities that affect the gateway's security properties

## Out of Scope

- Vulnerabilities in `basis-core` (report to the `basis-core` repository)
- Deployment environment security (network segmentation, IdP configuration, host hardening)
- Vulnerabilities in the underlying OIDC/IdP used with the gateway
- Theoretical attacks that require attacker control of the configured OIDC issuer

## Security Model

`basis-gateway` operates on the following security assumptions:

- The configured OIDC issuer is trusted and its JWKS endpoint is authentic
- The `basis-core` `EnforcementPoint` is trusted to evaluate policy correctly
- The process log backend is trusted for audit evidence delivery
- Callers are untrusted: all identity is derived from verified JWT claims, never from request body fields
- The gateway fails closed: unexpected errors produce DENY, not ALLOW

These assumptions are documented in detail in [`basis-architecture/docs/architecture/basis-gateway.md`](../basis-architecture/docs/architecture/basis-gateway.md).

## Known Limitations

See [`docs/release-readiness.md`](docs/release-readiness.md) for the full list of known limitations. Security-relevant limitations include:

- **Log-backed audit only**: audit events are written to the process log. There is no durable storage, guaranteed delivery, or tamper-evidence mechanism.
- **In-process JWKS cache**: JWKS keys are cached in process memory. Key rotation depends on TTL expiry; revocation is not supported.
- **Single-instance only**: multi-instance deployments are untested. Audit failure thresholds and readiness state are per-process.
- **`RequestValidationError` handler**: a latent audit gap exists if the `/v1/evaluate` route signature is changed to use FastAPI-managed body parameters. See [`docs/audit-model.md`](docs/audit-model.md) §9.

## Not a Production Security Control

`basis-gateway` is a proof-of-concept implementation. It should not be treated as a production-ready security control for operational technology environments without completing the hardening, testing, and operational work that a production deployment would require.
