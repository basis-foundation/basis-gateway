# basis-gateway Configuration Reference

This is the canonical environment-variable reference for `basis-gateway`. Every variable name,
default, and constraint below is derived directly from `src/basis_gateway/config.py`'s
`GatewayConfig` model — nothing here is aspirational or planned. If this document and
`config.py` ever disagree, `config.py` is authoritative.

See [`.env.example`](../.env.example) for an annotated, copy-pasteable template using clearly
synthetic values. See the [README](../README.md#quick-configuration-overview) for a quick-start
summary of the minimum variables needed per concern.

---

## General

| Variable | Default | Notes |
|---|---|---|
| `SERVICE_NAME` | `basis-gateway` | Service identifier reported in `/health` and `/ready` responses. |
| `ENVIRONMENT` | `local` | One of `local`, `development`, `staging`, `production`. Any other value is rejected at startup. |
| `LOG_LEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive; normalized to uppercase). Any other value is rejected at startup. |
| `HOST` | `0.0.0.0` | Bind address (consumed by the ASGI server, e.g. `uvicorn`; not enforced by `GatewayConfig` itself beyond storing the value). |
| `PORT` | `8000` | Bind port. Must be between 1 and 65535. |

---

## Authentication

`AUTH_MODE` selects which verifier authenticates Bearer tokens — on **both** `/v1/evaluate` and
`/v1/evaluate/operation-aware`. This selection is explicit configuration only; it is never
inferred from a token's shape, and there is no fallback from one mode to the other. Only the
active mode's readiness components are registered at startup (see
[`docs/readiness.md`](readiness.md)): in `oidc` mode, `basis_local_token_configured` is never
registered; in `basis_local_token` mode, `oidc_configured`/`jwks_available` are never registered.

| Variable | Default | Notes |
|---|---|---|
| `AUTH_MODE` | `oidc` | `oidc` or `basis_local_token`. |

### OIDC (`AUTH_MODE=oidc`, the default)

| Variable | Default | Notes |
|---|---|---|
| `OIDC_ISSUER` | _(none)_ | Token issuer URL. Setting this is what enables `/v1/evaluate` in `oidc` mode (see `evaluation_enabled` below). Used for OIDC discovery and `iss` validation. Not required or validated in `basis_local_token` mode. |
| `OIDC_AUDIENCE` | _(none)_ | Expected `aud` claim. If unset, audience is not validated. |
| `OIDC_JWKS_URI` | _(none)_ | Overrides the JWKS endpoint discovered via OIDC discovery. |
| `JWKS_CACHE_TTL_SECONDS` | `300` | JWKS in-memory cache TTL, in seconds. Must be greater than 0. |

### BASIS-local token trust (`AUTH_MODE=basis_local_token` only)

Not required, and not validated, unless `AUTH_MODE=basis_local_token`. See
[`docs/basis-local-token-trust.md`](basis-local-token-trust.md) for the verifier these configure.

| Variable | Default | Notes |
|---|---|---|
| `BASIS_LOCAL_TOKEN_ISSUER` | _(none)_ | Expected `iss` claim on BASIS-local tokens. Required when `AUTH_MODE=basis_local_token`. |
| `BASIS_LOCAL_TOKEN_AUDIENCE` | _(none)_ | Expected `aud` claim(s); comma-separated for multiple entries. Required when `AUTH_MODE=basis_local_token`. |
| `BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON` | _(none)_ | JSON object string mapping key id to PEM-encoded **public** key. Required when `AUTH_MODE=basis_local_token`. Example shape: `{"basis-identity-key-1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}`. Never put a private key here — a private-key-shaped value is rejected. |
| `BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS` | `RS256` | Comma-separated algorithm allow-list. `none` and any symmetric `HS*` algorithm are always rejected regardless of this setting. |
| `BASIS_LOCAL_TOKEN_LEEWAY_SECONDS` | `0` | Clock-skew leeway (seconds) applied to token timing validation. Must be ≥ 0. |

---

## v0.1 authorization

| Variable | Default | Notes |
|---|---|---|
| `POLICY_PATH` | _(none)_ | Path to the JSON role-table policy file loaded once at startup. Required when evaluation is enabled (`OIDC_ISSUER` set in `oidc` mode, or `AUTH_MODE=basis_local_token`). Structurally unrelated to the operation-aware `PolicyBundle` format below. |
| `POLICY_VERSION` | _(none)_ | Optional version string included in `/v1/evaluate` responses and kernel audit records. Provenance metadata only. |

---

## Operation-aware authorization

Disabled by default. Structurally and configuration-wise independent of the v0.1 settings above
— the two policy formats and the two evaluators are validated separately, and enabling one does
not require or affect the other.

| Variable | Default | Notes |
|---|---|---|
| `OPERATION_AWARE_ENABLED` | `false` | Enables `POST /v1/evaluate/operation-aware` and the four operation-aware readiness components. Disabled by default — with this unset or `false`, no operation-aware bundle is required, no operation-aware evaluator is initialized, and the route is not registered at all. |
| `OPERATION_AWARE_POLICY_BUNDLE_PATH` | _(none)_ | Path to the JSON operation-aware `PolicyBundle` file. Required when `OPERATION_AWARE_ENABLED=true`; not required or validated otherwise. |
| `OPERATION_PRODUCER_SUBJECT_IDS` | _(empty)_ | Comma-separated exact-match allowlist of authenticated subject IDs permitted to assert operation-producer-only context. Defaults to empty — an empty list trusts no producer; this is the safe default. **Legacy/compatibility mechanism** — consulted only when `OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED` is `false` (the default); see [Two producer-trust mechanisms](#two-producer-trust-mechanisms) below. |
| `OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED` | `false` | Trusted-proxy producer-mTLS ingress mode ([ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md)). When `true`, the gateway's internal certificate-header retrieval primitive (`src/basis_gateway/auth/producer_mtls_trusted_proxy.py`) looks for the private `X-BASIS-Producer-Client-Cert` header, and producer trust for `POST /v1/evaluate/operation-aware` is established **exclusively** through the mTLS certificate pipeline below — `OPERATION_PRODUCER_SUBJECT_IDS` is never consulted for a request received while this is `true` (no fallback). Safe only behind the ADR-0009 NGINX → Unix-domain-socket ingress (`examples/producer-mtls/`) that unconditionally overwrites that header — enabling this setting does not itself make the header trustworthy. Disabled by default: an ordinary deployment observes no behavior change. Wired into the live route as of Phase 1B.3 — see [`docs/implementation/producer-mtls-phase-1b3.md`](implementation/producer-mtls-phase-1b3.md). |
| `OPERATION_PRODUCER_MTLS_ADMITTED_URIS` | `[]` (empty) | JSON array of exact producer workload identity strings (certificate URI SANs) admitted as trusted mTLS operation producers when `OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED=true`. Example: `["spiffe://example.test/basis/reference-producer-01"]`. Defaults to an empty array — an empty admission set trusts no mTLS producer; this is the safe default, and is a legitimate deployment configuration even with trusted-proxy mode enabled (it simply means no producer-owned context can be asserted yet). Matching is exact and case-sensitive; no wildcard, prefix, suffix, or case-insensitive matching exists, and no URI canonicalization is performed — every entry is preserved exactly as configured. A scalar string, malformed JSON, a JSON object, or a JSON array containing a non-string or empty-string entry are all rejected at startup. See [Phase 1B.3](implementation/producer-mtls-phase-1b3.md). |

### Two producer-trust mechanisms

`POST /v1/evaluate/operation-aware` recognizes exactly two, mutually exclusive producer-trust
mechanisms, selected per request by `OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED`:

**Legacy mode** (`OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED=false`, the default):
`OPERATION_PRODUCER_SUBJECT_IDS` remains the compatibility/development/migration producer-trust
mechanism — an exact, case-sensitive allowlist checked against the already bearer-authenticated
caller's verified `subject_id`. This describes *authorization to act as an operation producer* for
an already-authenticated subject; it does not independently authenticate a producer *workload*.

**Trusted-proxy mTLS mode** (`OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED=true`): producer trust
is established by an independently authenticated certificate:

```text
authenticated producer client certificate (validated by the trusted NGINX ingress)
    → exactly one URI SAN (basis_gateway.auth.producer_mtls)
    → OPERATION_PRODUCER_MTLS_ADMITTED_URIS exact admission
    → OperationProducerTrust
```

This is a *workload* authentication fact, independent of and never substituted for the bearer
subject that `basis-core` evaluates. Neither role membership, network position, the bearer token's
issuer, nor any other subject attribute is producer workload authentication — only the certificate
pipeline above establishes it in this mode.

Required statements about this configuration group:

- The bundle is structurally loaded at startup (JSON parsed, shape-validated against
  `PolicyBundle`), and the evaluator is constructed once from that loaded bundle — both happen
  exactly once per process lifetime, with no dynamic reload.
- A semantic startup preflight must also pass before the operation-aware evaluator is considered
  ready — structural loading proves the bundle is *shaped* correctly, not that it is
  *semantically* valid (no duplicate rule IDs, no unsupported condition operators). See
  [`docs/readiness.md`](readiness.md).
- Startup remains live (`/health` responds) but not ready (`/ready` returns `503`) if any of the
  four operation-aware stages fails.
- The enabled route remains registered even when a later startup stage fails — a request to it
  then returns a governed `503`, never FastAPI's ordinary `404`.
- Both producer-trust mechanisms use exact, case-sensitive matching — no wildcard, prefix, or
  case-insensitive matching exists in either.
- Roles and the token issuer do not imply producer trust under either mechanism.
- When trusted-proxy mTLS mode is enabled, a bearer subject's presence in
  `OPERATION_PRODUCER_SUBJECT_IDS` has no effect on that request's producer-trust outcome — the two
  mechanisms never combine or fall back into one another within a single request.
- When trusted-proxy mTLS mode is enabled and a request reaches `basis-gateway` without the internal
  `X-BASIS-Producer-Client-Cert` assertion, this is a fail-closed Layer-2 proxy/backend
  trust-boundary failure (per `basis-architecture`'s `producer-mtls-proxy-trust-boundary.md` §11/§18)
  — not an ordinary untrusted-producer outcome. The request is rejected before kernel evaluation, no
  `OperationProducerTrust` is constructed, and there is no fallback to `OPERATION_PRODUCER_SUBJECT_IDS`
  even when the bearer subject is itself allowlisted. See
  [Phase 1B.3](implementation/producer-mtls-phase-1b3.md#missing-assertion-semantics-architecture-reconciled).

---

## Audit

The audit writer (`GatewayAuditWriter`) is a single, shared instance used by both `/v1/evaluate`
and `/v1/evaluate/operation-aware` — initialized once, whenever either evaluation path requires
one (`POLICY_PATH` is set, or `OPERATION_AWARE_ENABLED=true`). There is one failure count and one
degraded/recovered state shared by both endpoints, not two independent writers.

| Variable | Default | Notes |
|---|---|---|
| `AUDIT_FAILURE_THRESHOLD` | `10` | Consecutive audit write failures before the `audit_writer` readiness component degrades. Must be ≥ 1. |
| `AUDIT_FAIL_CLOSED` | `false` | When `true`, a degraded audit writer additionally causes both evaluation endpoints to return `503` (strict mode). Default `false` degrades readiness only — evaluation continues to be served (Model B; see [`docs/audit-failure-escalation.md`](audit-failure-escalation.md)). |

Behavioral notes:

- Default mode (`AUDIT_FAIL_CLOSED=false`) preserves current-request availability: a request that
  is already being evaluated is never blocked because of audit degradation.
- Strict mode (`AUDIT_FAIL_CLOSED=true`) checks the writer's degraded state *before* evaluation on
  each incoming request, via a lightweight recovery probe — see
  [`docs/audit-failure-escalation.md`](audit-failure-escalation.md).
- A failed current-request audit write never alters that already-computed decision — the response
  already returned to the caller stands regardless of whether its audit record was durably
  written.
- Readiness degrades once the configured consecutive-failure threshold is crossed; recovery is
  automatic on the next successful write.

---

## Example values

Use clearly synthetic values in configuration examples and templates:

```bash
OIDC_ISSUER=https://idp.example.com
OPERATION_PRODUCER_SUBJECT_IDS=adapter-warehouse-1
OPERATION_AWARE_POLICY_BUNDLE_PATH=/path/to/policy-bundle.json
```

Never commit real secrets, certificates, tokens, account identifiers, or infrastructure addresses
to a configuration example or template.

---

## Related documents

- [`.env.example`](../.env.example) — copy-pasteable template
- [`docs/basis-local-token-trust.md`](basis-local-token-trust.md) — BASIS-local token trust contract
- [`docs/operation-aware-endpoint.md`](operation-aware-endpoint.md) — operation-aware endpoint reference
- [`docs/readiness.md`](readiness.md) — readiness components and failure matrix
- [`docs/audit-failure-escalation.md`](audit-failure-escalation.md) — audit failure escalation architecture
