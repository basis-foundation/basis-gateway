# OIDC Integration Guide

`basis-gateway` validates identity using signed JWTs issued by an OIDC-compatible identity
provider. This guide covers architecture, configuration, JWT validation behavior, identity
normalization, startup and readiness, local development, troubleshooting, and operational
technology considerations.

---

## Purpose and Scope

`basis-gateway` uses OIDC/JWT validation to authenticate callers before invoking `basis-core`.

The responsibilities are deliberately separated:

```
OIDC authenticates.
basis-gateway normalizes identity and enforces.
basis-core evaluates authorization.
```

This guide covers operator-facing configuration and behavior. It does not cover:

- How to administer or configure every supported identity provider
- Production hardening of the identity provider itself
- Policy authoring or the policy file format
- Protocol adapters
- Console or UI integration

---

## Architectural Flow

Every authorization request follows this path:

```
Caller
  ↓
OIDC Provider
  ↓
Signed JWT
  ↓
basis-gateway
  ↓
JWT validation
  (signature, issuer, audience, algorithm, expiry)
  ↓
Identity normalization
  (verified claims → NormalizedSubject)
  ↓
basis-core EnforcementPoint
  ↓
DecisionResponse
  ↓
HTTP enforcement + audit evidence
```

The caller presents a Bearer token issued by the configured OIDC provider. `basis-gateway`
validates the token cryptographically, maps the verified claims to a normalized identity
structure, and passes that structure to `basis-core` for authorization evaluation.
`basis-core` returns a decision. The gateway enforces it at the HTTP boundary and emits
an audit record.

If any step in the authentication path fails, the request is denied before policy evaluation
is reached.

---

## Gateway and Kernel Responsibilities

### basis-gateway owns

- Bearer token extraction from the `Authorization` header
- OIDC discovery (`{issuer}/.well-known/openid-configuration`)
- JWKS fetching and in-memory caching
- JWT signature validation
- Issuer (`iss`) validation
- Audience (`aud`) validation
- Algorithm allowlisting
- Identity normalization (verified claims → `NormalizedSubject`)
- HTTP enforcement (200 / 403 / 401 / 503)
- Gateway-level audit evidence

### basis-core owns

- Authorization semantics
- Policy evaluation
- Decision response generation (ALLOW / DENY / NOT_APPLICABLE)
- Kernel-level audit contracts

A key invariant:

```
basis-core never parses JWTs.
basis-core never contacts the identity provider.
```

`basis-core` receives a `NormalizedSubject` derived from verified claims. It has no
knowledge of the token, the issuer, or the JWKS endpoint.

---

## Required Configuration

All configuration is sourced from environment variables.

| Variable                 | Required                | Default  | Description                                                                                                                           |
| ------------------------ | ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `OIDC_ISSUER`            | When evaluation enabled | _(none)_ | Token issuer URL. Used for OIDC discovery and `iss` claim validation. Setting this variable enables the `/v1/evaluate` endpoint.      |
| `OIDC_AUDIENCE`          | Recommended             | _(none)_ | Expected `aud` claim. If unset, audience is not validated — not recommended for production.                                           |
| `OIDC_JWKS_URI`          | No                      | _(none)_ | Override the JWKS endpoint. If not set, derived from `OIDC_ISSUER` via OIDC discovery. Useful in air-gapped or internal environments. |
| `JWKS_CACHE_TTL_SECONDS` | No                      | `300`    | JWKS in-memory cache TTL in seconds. Keys are held for this duration; on unknown `kid` the cache is refreshed regardless of TTL.      |
| `POLICY_PATH`            | When evaluation enabled | _(none)_ | Path to the JSON policy file. Required when `OIDC_ISSUER` is set; startup fails fast if absent.                                       |
| `POLICY_VERSION`         | No                      | _(none)_ | Version string included in evaluation responses and audit records. Aids correlation across deployments.                               |

"Evaluation enabled" means `OIDC_ISSUER` is set. When `OIDC_ISSUER` is absent, the gateway
starts without OIDC or policy initialization. `/v1/evaluate` rejects all requests with
`401 Authentication not configured`. This is the expected local-dev state.

When `OIDC_ISSUER` is set and `POLICY_PATH` is absent, startup fails immediately with a
clear error before the service becomes ready.

---

## Provider Compatibility

`basis-gateway` works with any standards-compatible OIDC provider that exposes:

- An issuer metadata document at `{issuer}/.well-known/openid-configuration`
- A `jwks_uri` field in that document pointing to a JWKS endpoint
- Signed JWTs using one of the supported asymmetric algorithms (see [JWT Validation Behavior](#jwt-validation-behavior))

Providers known to be compatible include (examples only, not exhaustive or endorsed):

- Keycloak
- Auth0
- Okta
- Microsoft Entra ID
- Ping Identity
- ForgeRock

Any provider that issues standard RS256/RS384/RS512/ES256/ES384/ES512 JWTs with a
discoverable JWKS endpoint should work without modification.

---

## Example Provider Configurations

Exact issuer and audience values depend on the IdP and the client/API registration.
Use the values from your IdP's metadata document, not guesses.

### Keycloak

```bash
OIDC_ISSUER=https://id.example.com/realms/building-ops
OIDC_AUDIENCE=basis-gateway
POLICY_PATH=policies/default.json
```

### Auth0

```bash
OIDC_ISSUER=https://example.us.auth0.com/
OIDC_AUDIENCE=https://basis-gateway
POLICY_PATH=policies/default.json
```

### Microsoft Entra ID

```bash
OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_AUDIENCE=<application-client-id-or-api-audience>
POLICY_PATH=policies/default.json
```

### Explicit JWKS Override

Use when the issuer URL does not serve a discovery document, or when the JWKS endpoint
is on a different host (common in air-gapped environments):

```bash
OIDC_ISSUER=https://id.internal.example.com/realms/building-ops
OIDC_JWKS_URI=https://jwks.internal.example.com/keys
OIDC_AUDIENCE=basis-gateway
POLICY_PATH=policies/default.json
```

When `OIDC_JWKS_URI` is set, discovery is skipped entirely and the override URI is used
directly. The `OIDC_ISSUER` value is still used for `iss` claim validation.

---

## JWT Validation Behavior

### Validation sequence

Every incoming JWT is validated in the following order:

1. **Bearer extraction** — the `Authorization` header must be present and use the `Bearer` scheme with a non-empty token value.
2. **Algorithm check** — the `alg` header is inspected before any key lookup. Tokens using unsupported or disallowed algorithms are rejected immediately.
3. **Key resolution** — the `kid` header is used to look up the corresponding public key in the cached JWKS. If no matching key is found, the JWKS is re-fetched once. If the key is still not found, the token is rejected.
4. **Signature verification** — the token signature is verified against the resolved public key.
5. **Claims validation** — `iss`, `aud` (if `OIDC_AUDIENCE` is set), and `exp` are validated.

Any failure at any step results in a `401` response before policy evaluation is reached.

### Supported algorithms

```
RS256, RS384, RS512
ES256, ES384, ES512
```

### Rejected algorithms

The following are unconditionally rejected regardless of key configuration:

- `alg=none` — unsigned tokens are never accepted
- Symmetric algorithms (`HS256`, `HS384`, `HS512`) — shared-secret verification is not supported

### Claim validation details

| Claim           | Behavior                                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------------------------ |
| `iss`           | Must exactly match `OIDC_ISSUER`. Mismatch → 401.                                                            |
| `aud`           | Must contain `OIDC_AUDIENCE` if set. Mismatch → 401. If `OIDC_AUDIENCE` is unset, audience is not validated. |
| `exp`           | Token must not be expired. Expired → 401.                                                                    |
| `kid`           | Used for JWKS key lookup. Unknown `kid` triggers a JWKS re-fetch before rejecting.                           |
| Signature       | Verified using the resolved public key. Invalid signature → 401.                                             |
| Malformed token | Any token that cannot be decoded → 401.                                                                      |
| Missing header  | Absent or non-Bearer `Authorization` header → 401.                                                           |

Invalid authentication fails before policy evaluation. A token that fails any of these
checks never reaches `basis-core`.

---

## Identity Normalization

After a JWT passes validation, the verified claims are translated into a `NormalizedSubject`
for use by `basis-core`. The request body and headers are never used as identity sources.
Caller-supplied identity fields in the request body are ignored.

### Claim mapping (as implemented)

| JWT claim            | NormalizedSubject field     | Notes                                                    |
| -------------------- | --------------------------- | -------------------------------------------------------- |
| `sub`                | `subject_id`                | Required. Missing `sub` → 401.                           |
| `preferred_username` | `name`                      | Falls back to `sub` if absent.                           |
| `realm_access.roles` | `roles`                     | Keycloak-style nested claim; checked first.              |
| `roles`              | `roles`                     | Flat list claim; used if `realm_access.roles` is absent. |
| `email`              | `attributes["email"]`       | Included when present.                                   |
| `given_name`         | `attributes["given_name"]`  | Included when present.                                   |
| `family_name`        | `attributes["family_name"]` | Included when present.                                   |
| `name`               | `attributes["name"]`        | Included when present.                                   |

Role extraction behavior: `realm_access.roles` is checked first (Keycloak-style nested
structure). If absent or not a list, the flat `roles` claim is checked. Malformed role
structures (non-list values) normalize to an empty role set, which will DENY in policy
evaluation. Individual non-string role entries are silently dropped. Roles are
deduplicated and sorted.

### Example

```
JWT claims
  sub: user-123
  preferred_username: operator-console
  email: operator@example.com
  realm_access:
    roles: ["operator", "viewer"]

NormalizedSubject
  subject_id: user-123
  name: operator-console
  roles: ("operator", "viewer")
  attributes:
    email: operator@example.com
```

`basis-core` receives `subject_id` and `roles`. It does not receive the raw JWT or any
unverified claim.

---

## Startup and Readiness

### Startup sequence

When `OIDC_ISSUER` is set, startup proceeds in this order:

1. **Configuration loaded** — environment variables are parsed and validated.
2. **OIDC discovery** — if `OIDC_JWKS_URI` is not set, the discovery document is fetched from `{OIDC_ISSUER}/.well-known/openid-configuration`. The discovered issuer is validated against `OIDC_ISSUER`.
3. **JWKS initialization** — the JWKS endpoint is fetched and keys are loaded into memory. Startup fails and the service does not become ready if the JWKS endpoint is unreachable.
4. **Policy loading** — the JSON policy file at `POLICY_PATH` is loaded and parsed.
5. **Evaluator initialization** — the `basis-core` `EnforcementPoint` is constructed from the loaded policy.

If any step fails, the service starts (so `/health` responds), but `/ready` returns `503`
until all components initialize successfully. This is intentional fail-closed behavior.

### Readiness components

`/ready` tracks the following components:

| Component               | Marks ready when                                                |
| ----------------------- | --------------------------------------------------------------- |
| `configuration_loaded`  | Environment variables parsed and validated                      |
| `oidc_configured`       | OIDC verifier initialized (discovery + JWKS client constructed) |
| `jwks_available`        | Initial JWKS fetch succeeded                                    |
| `policy_loaded`         | Policy file loaded and parsed                                   |
| `audit_writer`          | Audit writer initialized                                        |
| `evaluator_initialized` | `EnforcementPoint` constructed                                  |

### Endpoints

| Endpoint      | Purpose         | Returns                                                               |
| ------------- | --------------- | --------------------------------------------------------------------- |
| `GET /health` | Liveness probe  | Always `200 {"status": "ok"}` while the process is running            |
| `GET /ready`  | Readiness probe | `200` when all components ready; `503` with component detail when not |

Example not-ready response:

```json
{
  "status": "not_ready",
  "service": "basis-gateway",
  "components": {
    "configuration_loaded": true,
    "oidc_configured": false
  },
  "reason": "OIDC verifier initialization failed: ...",
  "correlation_id": "..."
}
```

### Evaluation disabled (no OIDC_ISSUER)

When `OIDC_ISSUER` is not set, the `oidc_configured`, `jwks_available`, `policy_loaded`,
`audit_writer`, and `evaluator_initialized` components are not registered. `/ready` reflects
only `configuration_loaded`. `/v1/evaluate` returns `401 Authentication not configured` for
all requests. This is the expected local-dev state.

---

## Local Development

Tests in this repository do not require a live identity provider. The test suite uses
pre-signed JWTs and in-process key material to exercise all validation logic.

When running the service without `OIDC_ISSUER`:

- The service starts and `/health` responds immediately.
- `/ready` reflects only `configuration_loaded`.
- `/v1/evaluate` rejects all requests with `401 Authentication not configured`.
- No OIDC discovery or JWKS fetch is attempted.

To run integration tests against a real IdP, set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and
optionally `OIDC_JWKS_URI` in your environment before running the test suite. Use the
exact issuer and audience values from your IdP's client registration.

---

## Troubleshooting

| Symptom                                                 | Likely Cause                                             | Fix                                                                                       |
| ------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `401 Missing Authorization header`                      | No `Authorization` header in the request                 | Send `Authorization: Bearer <token>`                                                      |
| `401 Token verification failed` (invalid issuer)        | `OIDC_ISSUER` does not match the token's `iss` claim     | Use the exact issuer value from the IdP's discovery document                              |
| `401 Token verification failed` (invalid audience)      | `OIDC_AUDIENCE` does not match the token's `aud` claim   | Configure the correct client/API audience in `OIDC_AUDIENCE`                              |
| `401 Token verification failed` (unknown kid)           | The JWKS does not contain the signing key for this token | Check key rotation; verify the JWKS endpoint; consider setting `OIDC_JWKS_URI` explicitly |
| `401 Token verification failed` (expired)               | Token `exp` is in the past                               | Refresh the token; check clock skew between client and IdP                                |
| `401 Token verification failed` (unsupported algorithm) | Token uses `alg=none` or a symmetric algorithm           | Reconfigure the IdP client to use RS256, RS384, RS512, ES256, ES384, or ES512             |
| `401 Authentication not configured`                     | `OIDC_ISSUER` is not set                                 | Set `OIDC_ISSUER` and `POLICY_PATH` to enable evaluation                                  |
| `/ready` returns `503` with `oidc_configured: false`    | OIDC discovery failed                                    | Verify `OIDC_ISSUER` is reachable; check `{issuer}/.well-known/openid-configuration`      |
| `/ready` returns `503` with `jwks_available: false`     | JWKS endpoint unreachable at startup                     | Check network connectivity to the JWKS endpoint; set `OIDC_JWKS_URI` to override          |
| `/ready` returns `503` with `policy_loaded: false`      | `POLICY_PATH` missing or file invalid                    | Verify `POLICY_PATH` exists and contains a valid JSON policy                              |
| Token rejected before policy evaluation                 | Authentication failed                                    | Fix IdP/token configuration first; policy is not reached until authentication succeeds    |

If a readiness component is failing, inspect startup logs. Each failed component produces a
log entry at ERROR level with the component name and the specific reason.

---

## Operational Technology Considerations

`basis-gateway` is designed for environments where the identity boundary matters. In
operational technology deployments — building automation, industrial control, or other
semi-connected environments — the following apply:

**Internal identity providers.** Many OT environments run internal IdPs (Keycloak, Entra
ID in hybrid deployments, or similar) rather than cloud-hosted providers. Set `OIDC_ISSUER`
to the internal issuer URL. If the discovery document is not accessible at runtime but the
JWKS endpoint is, use `OIDC_JWKS_URI` to bypass discovery.

**Air-gapped or semi-connected environments.** When the gateway cannot reach the IdP
discovery endpoint at runtime, set `OIDC_JWKS_URI` explicitly. The JWKS endpoint must be
reachable at startup and on cache refresh. In fully air-gapped environments, consider
whether JWKS key rotation is feasible and plan for controlled restarts when keys change.

**Fail-closed behavior.** If JWKS initialization fails at startup, the gateway does not
serve authorization requests. It remains alive (liveness probe responds) but not ready
(readiness probe returns 503). Orchestration platforms should use the readiness probe to
prevent traffic routing until the gateway is fully initialized.

**Readiness probes.** Configure your orchestration platform to use `GET /ready` as the
readiness probe and `GET /health` as the liveness probe. The gateway will not serve
evaluation requests until all required components are initialized.

**Identity boundary placement.** `basis-gateway` should be the first BASIS enforcement boundary that accepts application-level authorization requests. It may sit behind infrastructure such as a load balancer, reverse proxy, VPN, ingress controller, or WAF, but those layers should not replace gateway identity verification or authorization enforcement. `basis-core` should not be directly reachable by external callers;
all access should flow through the gateway. This ensures that every authorization decision
is preceded by authenticated identity verification.

**Avoiding direct exposure of basis-core.** `basis-core` has no authentication layer — it
trusts the identity context it receives. Exposing it directly to untrusted callers bypasses
the authentication boundary. The gateway is the intended and only trusted caller.

**Audit correlation and traceability.** Every gateway response includes an `X-Correlation-ID`
header containing a UUIDv4. All audit records for that request share the same ID. In OT
environments where event correlation across system boundaries matters, this ID should be
propagated through upstream systems and logged alongside gateway decisions.

These notes are grounded in the current implementation. They do not constitute a security
certification or production-readiness claim for any specific OT environment.

---

## Security Notes

- Unsigned tokens (`alg=none`) are rejected unconditionally.
- Symmetric algorithms (`HS256`, `HS384`, `HS512`) are rejected unconditionally.
- Caller-supplied identity in the request body is ignored. Subject identity is derived
  exclusively from the verified JWT payload.
- The gateway should sit at a trusted enforcement boundary. Placing it behind an
  untrusted reverse proxy that strips or rewrites the `Authorization` header will break
  authentication.
- TLS termination and reverse proxy hardening are deployment concerns outside the scope
  of this guide.
- Identity provider compromise is outside the gateway's threat model. The gateway trusts
  tokens signed by the configured issuer. If the IdP is compromised, signed tokens may be
  issued for arbitrary subjects.
- Gateway authorization depends on both authentication correctness and policy correctness.
  A correctly authenticated subject with an overly permissive policy will receive more
  access than intended. Policy authoring is a separate concern.
- Raw JWT strings are never logged or included in error responses.

---

## See Also

- [`basis-gateway/README.md`](../README.md) — environment variable reference, evaluation flow, policy format, and general setup
- [`basis-gateway/docs/audit-model.md`](audit-model.md) — audit boundary, correlation ID flow, identity evidence, failure behavior
- [`basis-gateway/docs/troubleshooting.md`](troubleshooting.md) — startup failures, readiness diagnostics, OIDC/JWKS issues, policy errors
- [`basis-architecture/docs/architecture/basis-gateway.md`](../../basis-architecture/docs/architecture/basis-gateway.md) — architectural boundaries, trust model, invariants, component responsibilities _(sibling repository)_
- [`basis-core/docs/public-api.md`](../../basis-core/docs/public-api.md) — the stable public API this gateway calls into _(sibling repository)_
