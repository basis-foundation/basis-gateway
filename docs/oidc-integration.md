# OIDC Integration Guide

basis-gateway validates identity using signed JWTs issued by an OIDC-compatible identity provider. This guide covers configuration, supported algorithms, startup behavior, and local development.

---

## Required Environment Variables

| Variable | Description |
|---|---|
| `OIDC_ISSUER` | The issuer URL of your identity provider (e.g., `https://accounts.example.com`). Must match the `iss` claim in incoming JWTs. |
| `OIDC_AUDIENCE` | The expected `aud` claim value. Requests bearing tokens with a mismatched audience are rejected. |

## Optional Environment Variables

| Variable | Description |
|---|---|
| `OIDC_JWKS_URI` | Override the JWKS endpoint. If not set, basis-gateway derives it from `OIDC_ISSUER` via OIDC discovery (`/.well-known/openid-configuration`). |

---

## JWKS Discovery

On startup, basis-gateway fetches the JWKS from the configured or discovered `jwks_uri`. Public keys are cached in memory and refreshed when an unknown `kid` is encountered in an incoming token header.

If `OIDC_JWKS_URI` is set explicitly, discovery is skipped and the endpoint is used directly. This is useful in air-gapped or internal environments where the issuer URL does not host a discovery document.

---

## Supported Algorithms

basis-gateway accepts asymmetric signing algorithms only:

- `RS256`, `RS384`, `RS512`
- `ES256`, `ES384`, `ES512`

## Rejected Algorithms

The following are unconditionally rejected regardless of key configuration:

- `alg=none` — unsigned tokens are never accepted
- Symmetric algorithms (`HS256`, `HS384`, `HS512`) — shared-secret verification is not supported

Tokens using rejected algorithms are rejected at the validation boundary with a `401` response before reaching any policy evaluation.

---

## Startup and Readiness Behavior

basis-gateway performs a JWKS fetch during startup. If the JWKS endpoint is unreachable and no cached keys are available, the gateway will not serve requests until the fetch succeeds.

The `/health/ready` endpoint returns `200` only after JWKS initialization completes. Liveness (`/health/live`) is available immediately.

In environments where the IdP may be temporarily unavailable during startup, configure your orchestration platform to use the readiness probe and allow the gateway time to initialize before routing traffic.

---

## Local Development

Tests in this repository do not require a live identity provider. The test suite uses pre-signed JWTs and in-process key material to exercise validation logic.

To run integration tests against a real IdP locally, set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and optionally `OIDC_JWKS_URI` in your environment before running the test suite.

---

## Identity Source

> **Warning:** Subject identity (`sub`, `email`, or other claims) is derived exclusively from the verified JWT payload. The request body and headers are not trusted as identity sources. Middleware or downstream services that rely on request-body identity fields will receive the gateway-asserted identity from the JWT, not from the request itself.

This is intentional. basis-gateway is the identity verification boundary. Downstream components should read identity from the forwarded and verified claims, not from the original request.

---

## See Also

- [Gateway Architecture](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/basis-gateway.md)
- [Enforcement Boundary](https://github.com/basis-foundation/basis-architecture/blob/main/docs/enforcement-boundary.md)
- [Audit Model](https://github.com/basis-foundation/basis-architecture/blob/main/docs/audit-model.md)
