# BASIS-Local Token Trust

`basis-gateway` can verify signed **BASIS-local identity tokens** issued by `basis-identity`, in addition to the OIDC/JWT verification described in [`docs/oidc-integration.md`](oidc-integration.md). This document covers the trust contract, the verifier's behavior, what it deliberately does not do, and how it relates to the existing OIDC path.

---

## Purpose and scope

`basis-identity` can issue a signed **BASIS-local identity token** — a JWT that carries a subject's canonical identity context, established through `basis-identity`'s own normalization pipeline (OIDC or otherwise), without requiring `basis-gateway` to trust an external IdP's JWKS endpoint for that identity. `basis-gateway` needs a way to verify that such a token was genuinely issued by `basis-identity`, is still valid, and carries the identity claims the gateway requires — without either repository depending on the other's internals.

`src/basis_gateway/auth/basis_local_token.py` is that verifier. It is additive: it does not replace, wrap, or modify the existing OIDC verifier (`src/basis_gateway/auth/oidc.py`). Request-time selection between the two verifiers is a separate, explicit configuration choice — `AUTH_MODE=basis_local_token` — handled by `src/basis_gateway/auth/runtime.py`, described in [Runtime wiring: choosing a verifier at request time](#runtime-wiring-choosing-a-verifier-at-request-time) below.

```
BASIS-local signed token
        |
        v
gateway trust configuration (BasisLocalTokenTrustConfig)
        |
        v
signature / issuer / audience / time verification (PyJWT)
        |
        v
required identity claim validation
        |
        v
gateway trusted identity context (BasisLocalTokenVerificationResult)
```

---

## The trust contract

The trust contract between `basis-identity` and `basis-gateway` is expressed entirely through ordinary configuration values — never a shared type:

- **Issuer** — the expected `iss` claim.
- **Audience** — the expected `aud` claim (at least one entry must match).
- **Algorithm allow-list** — which signing algorithms are accepted (`RS256` by default; `none` and any symmetric `HS*` algorithm are always rejected, regardless of configuration).
- **Public keys by key ID** — a mapping of `kid` to PEM-encoded public verification key. Only public keys are accepted; a value that looks like a private key (`"PRIVATE KEY"` in the PEM body) is rejected at configuration time.
- **Required identity claim paths** — the minimum set of claim paths that must be present (and non-null) in a verified token before it is trusted.

```python
from basis_gateway.auth.basis_local_token import BasisLocalTokenTrustConfig

trust_config = BasisLocalTokenTrustConfig(
    issuer="https://identity.basis.example.com",
    audience=("basis-gateway",),
    public_keys_by_id={"basis-local-key-1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"},
    # allowed_algorithms=("RS256",) and required_claims=DEFAULT_REQUIRED_BASIS_TOKEN_CLAIMS
    # by default — see below.
)
```

### Default required claim paths

```
iss
sub
aud
iat
exp
jti
typ
basis.session_id
basis.provider_id
basis.authority_mode
basis.authentication_protocol
basis.canonical_identity
```

These mirror the shape `basis-identity` documents in its own gateway trust contract (`basis_identity.tokens.gateway_contract.DEFAULT_GATEWAY_REQUIRED_CLAIM_PATHS`) — the claim names are duplicated as plain strings here, not imported, so the two repositories can evolve independently. A `required_claims` entry that looks authorization-shaped (contains `allow`, `deny`, `decision`, `policy`, `permission`, `grant`, `matched_rule`, `enforce`, or `obligation` as a substring) is rejected at configuration time; this trust contract is identity-only.

---

## Verifying a token

```python
from basis_gateway.auth.basis_local_token import (
    BasisLocalTokenClaimsError,
    BasisLocalTokenHeaderError,
    BasisLocalTokenSignatureError,
    BasisLocalTokenVerificationError,
    verify_basis_local_identity_token,
)

try:
    result = verify_basis_local_identity_token(token, trust_config=trust_config)
except (
    BasisLocalTokenHeaderError,
    BasisLocalTokenSignatureError,
    BasisLocalTokenVerificationError,
    BasisLocalTokenClaimsError,
) as exc:
    ...  # reject the request; every case above is a BasisLocalTokenError -> AuthenticationError
```

`verify_basis_local_identity_token` performs, in order:

1. Rejects a blank token.
2. Parses the JOSE header. Requires a non-blank `kid` and `alg`.
3. Rejects `alg=none` (unsigned tokens) and any symmetric `HS*` algorithm, before any key lookup.
4. Requires the header's `alg` to be in `trust_config.allowed_algorithms`.
5. Selects the public key by `kid`; rejects an unknown `kid`.
6. Verifies the signature and standard claims (issuer, audience, expiration, not-before, issued-at) via PyJWT — the same library, the same primitives, and the same never-trust-before-verify discipline as the existing OIDC verifier.
7. Validates that every path in `trust_config.required_claims` is present and non-null in the verified payload.
8. Validates the token's `typ` claim is the expected BASIS-local identity token type.
9. Returns a `BasisLocalTokenVerificationResult` — never before every prior step has succeeded.

Decoded claims are never used before signature verification succeeds.

### The result: identity trust only

`BasisLocalTokenVerificationResult` carries exactly: `subject_id`, `issuer`, `audience`, `token_id`, `token_type`, `session_id`, `provider_id`, `authority_mode`, `authentication_protocol`, `canonical_identity`, and the full verified `claims`. It is deterministic, JSON-safe, and safe to log — it never contains the raw signed token, a public or private key value, or any authorization/enforcement-shaped field. Construction actively rejects a `canonical_identity` or `claims` payload that carries a key that looks like a permission, a policy ID, a matched rule, an allow/deny decision, an obligation, or a grant.

This is the load-bearing distinction:

> **Token verification answers:** *who is this subject, and did `basis-identity` issue this token for this gateway?*
> **Authorization evaluation answers:** *may this subject perform this operation?*

Only the first question is answered here. Authorization continues to happen exactly where it always has — `basis-core`, via `/v1/evaluate`.

---

## Optional adapter into the existing subject model

`basis_local_verification_result_to_gateway_identity(result)` converts a `BasisLocalTokenVerificationResult` into the same `(NormalizedSubject, IdentityContext)` pair `basis_gateway.auth.subject_mapper.map_claims` already produces from a verified OIDC token. This lets downstream code treat a BASIS-local-verified identity exactly like an OIDC-verified one, without needing two parallel subject shapes. Subject identity is derived only from the verified result — never from a caller-supplied field.

This is the exact helper `basis_gateway.auth.runtime.authenticate()` calls when `AUTH_MODE=basis_local_token` — see the next section.

---

## Runtime wiring: choosing a verifier at request time

`src/basis_gateway/auth/runtime.py` is the small dispatcher that selects which verifier authenticates an incoming Bearer token, based on the gateway's configured `AUTH_MODE`:

```
Authorization: Bearer <token>
        |
        v
configured auth mode
        +-- oidc              -> OIDCVerifier.verify() + map_claims()
        +-- basis_local_token -> verify_basis_local_identity_token()
        |                        + basis_local_verification_result_to_gateway_identity()
        v
(NormalizedSubject, IdentityContext)
```

Rules, enforced by the dispatcher rather than by convention:

- **The mode is explicit configuration** (`GatewayConfig.auth_mode`, driven by the `AUTH_MODE` environment variable). It is never inferred from the token's shape, header, or claims.
- **There is no fallback between modes.** If the configured mode's verifier fails, the request fails closed — the other mode's verifier is never attempted, and an OIDC token is never attempted as a BASIS-local token (or vice versa) unless that mode is actually configured.
- **Default is `oidc`.** Deployments that do not set `AUTH_MODE` see exactly the pre-existing OIDC-only behavior.
- Both verifiers produce the same `(NormalizedSubject, IdentityContext)` pair, so `/v1/evaluate`'s request handling, `DecisionRequest` construction, and `basis-core` evaluation are identical regardless of which mode authenticated the caller.

### Configuring BASIS-local token trust

Set `AUTH_MODE=basis_local_token` plus:

```bash
AUTH_MODE=basis_local_token
BASIS_LOCAL_TOKEN_ISSUER=https://identity.basis.example.com
BASIS_LOCAL_TOKEN_AUDIENCE=basis-gateway
BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON={"basis-identity-key-1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}
POLICY_PATH=policies/default.json
```

`BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON` is a JSON object string mapping key id to PEM-encoded public key — the smallest environment-variable-friendly shape for multiline PEM values. `BASIS_LOCAL_TOKEN_AUDIENCE` accepts a comma-separated list for more than one audience entry. `BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS` (default `RS256`) and `BASIS_LOCAL_TOKEN_LEEWAY_SECONDS` (default `0`) are optional. See [`.env.example`](../.env.example) for the full annotated reference.

`AUTH_MODE=basis_local_token` is an explicit choice to enable evaluation: `BASIS_LOCAL_TOKEN_ISSUER`, `BASIS_LOCAL_TOKEN_AUDIENCE`, `BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON`, and `POLICY_PATH` are all required, or startup fails before the service becomes ready — the same fail-fast discipline `OIDC_ISSUER` + `POLICY_PATH` already have in `oidc` mode. OIDC settings (`OIDC_ISSUER`, etc.) are not required and are not validated in this mode, and vice versa.

### Readiness in `basis_local_token` mode

`/ready` tracks a `basis_local_token_configured` component in this mode instead of `oidc_configured` / `jwks_available` — those two are simply not registered when `AUTH_MODE=basis_local_token`, so they never block readiness. Symmetrically, `basis_local_token_configured` is never registered in `oidc` mode. No network check is performed for BASIS-local token trust: constructing the trust configuration is pure in-memory parsing and validation, so there is nothing to fetch or reach at startup.

### What this does not imply

Wiring a verifier into request authentication is not the same as owning identity lifecycle. Runtime auth-mode selection still:

- **Does not add a login, logout, or refresh endpoint.** Token issuance and session lifecycle remain entirely `basis-identity`'s responsibility.
- **Does not fetch JWKS, load a key from a file, generate a key, or handle a private key.** `basis_gateway.auth.runtime.build_basis_local_token_trust_config` only parses already-loaded environment-sourced strings into the same in-memory `BasisLocalTokenTrustConfig` described above.
- **Does not change `/v1/evaluate`'s request/response schema, its evaluation logic, or its `basis-core` integration.** The dispatcher only decides which verifier produces the `(NormalizedSubject, IdentityContext)` pair the rest of the handler already expected.

---

## What this verifier does not do

- **Does not import `basis_identity`.** The BASIS-local token shape (claim names, the `basis` namespace, the default required claim paths) is mirrored here as plain strings, never as a shared type. The two repositories remain independently deployable. Neither does `auth/runtime.py`.
- **Does not import `basis_core`** and does not evaluate authorization, carry a permission, a policy ID, a matched rule, or an enforcement result.
- **Does not sign, issue, generate, rotate, or publish a JWKS for any key.** `public_keys_by_id` is an ordinary, caller-constructed, in-memory mapping of verification material only.
- **Does not load a key from a file.** Configuration is in-memory only, parsed from an already-loaded environment variable string; there is no file-based key loading or JWKS fetching anywhere in this path.
- **Does not add a login, logout, refresh, or admin endpoint.** Token issuance and session lifecycle remain entirely `basis-identity`'s responsibility.

---

## Relationship to OIDC verification

| | OIDC verifier (`auth/oidc.py`) | BASIS-local verifier (`auth/basis_local_token.py`) |
|---|---|---|
| Issuer | External IdP (Keycloak, etc.) | `basis-identity` |
| Key discovery | OIDC discovery + JWKS endpoint, cached with TTL | Caller-supplied `public_keys_by_id`, no discovery |
| Algorithms | RS256/RS384/RS512/ES256/ES384/ES512 | Caller-configured allow-list (RS256 by default) |
| Claim shape | Provider-specific (Keycloak `realm_access.roles`, etc.) | Fixed `basis.*` namespace from `basis-identity`'s trust contract |
| Selected via | `AUTH_MODE=oidc` (default) | `AUTH_MODE=basis_local_token` |

Both verifiers produce data compatible with the same downstream subject model (`NormalizedSubject` / `IdentityContext`), so `auth/runtime.py` selects between them per the configured mode without reshaping anything downstream. There is no per-request fallback between modes and no dual-mode ("try both") behavior.

See also: [`docs/oidc-integration.md`](oidc-integration.md) for the existing OIDC authentication path.
