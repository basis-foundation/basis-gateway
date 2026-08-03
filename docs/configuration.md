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
| `OPERATION_PRODUCER_SUBJECT_IDS` | _(empty)_ | Comma-separated exact-match allowlist of authenticated subject IDs permitted to assert operation-producer-only context. Defaults to empty — an empty list trusts no producer; this is the safe default. |

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
- Operation-producer identifier matching is exact and case-sensitive — no wildcard, prefix, or
  case-insensitive matching exists.
- Roles and the token issuer do not imply producer trust. Only exact `OPERATION_PRODUCER_SUBJECT_IDS`
  membership does.

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
