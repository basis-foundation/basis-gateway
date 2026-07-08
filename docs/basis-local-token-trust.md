# BASIS-Local Token Trust

`basis-gateway` can verify signed **BASIS-local identity tokens** issued by `basis-identity`, in addition to the OIDC/JWT verification described in [`docs/oidc-integration.md`](oidc-integration.md). This document covers the trust contract, the verifier's behavior, what it deliberately does not do, and how it relates to the existing OIDC path.

---

## Purpose and scope

`basis-identity` can issue a signed **BASIS-local identity token** — a JWT that carries a subject's canonical identity context, established through `basis-identity`'s own normalization pipeline (OIDC or otherwise), without requiring `basis-gateway` to trust an external IdP's JWKS endpoint for that identity. `basis-gateway` needs a way to verify that such a token was genuinely issued by `basis-identity`, is still valid, and carries the identity claims the gateway requires — without either repository depending on the other's internals.

`src/basis_gateway/auth/basis_local_token.py` is that verifier. It is additive: it does not replace, wrap, or modify the existing OIDC verifier (`src/basis_gateway/auth/oidc.py`), and it is not wired into `/v1/evaluate`'s request authentication in this change. It exists as a standalone, fully tested capability that a later change can wire into runtime authentication once the surrounding auth-mode selection is designed.

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

This helper is provided so a future change can wire BASIS-local verification into request authentication without re-deriving the conversion. It is not called anywhere in this change.

---

## What this verifier does not do

- **Does not import `basis_identity`.** The BASIS-local token shape (claim names, the `basis` namespace, the default required claim paths) is mirrored here as plain strings, never as a shared type. The two repositories remain independently deployable.
- **Does not import `basis_core`** and does not evaluate authorization, carry a permission, a policy ID, a matched rule, or an enforcement result.
- **Does not sign, issue, generate, rotate, or publish a JWKS for any key.** `public_keys_by_id` is an ordinary, caller-constructed, in-memory mapping of verification material only.
- **Does not load a key from a file or environment variable.** Configuration is in-memory only in this change; file/env-based key loading is left to a later, separate change if operational needs require it.
- **Does not replace OIDC authentication or change `/v1/evaluate`'s existing request-authentication behavior.** This is a standalone verifier and an optional conversion helper; runtime auth-mode wiring (choosing OIDC vs. BASIS-local vs. both per request) is left to a later PR.
- **Does not add a login, logout, refresh, or admin endpoint.** Token issuance and session lifecycle remain entirely `basis-identity`'s responsibility.

---

## Relationship to OIDC verification

| | OIDC verifier (`auth/oidc.py`) | BASIS-local verifier (`auth/basis_local_token.py`) |
|---|---|---|
| Issuer | External IdP (Keycloak, etc.) | `basis-identity` |
| Key discovery | OIDC discovery + JWKS endpoint, cached with TTL | Caller-supplied `public_keys_by_id`, no discovery |
| Algorithms | RS256/RS384/RS512/ES256/ES384/ES512 | Caller-configured allow-list (RS256 by default) |
| Claim shape | Provider-specific (Keycloak `realm_access.roles`, etc.) | Fixed `basis.*` namespace from `basis-identity`'s trust contract |
| Wired into `/v1/evaluate` | Yes | Not in this change |

Both verifiers produce data compatible with the same downstream subject model (`NormalizedSubject` / `IdentityContext`), so a future runtime change can select between them per request without reshaping anything downstream.

See also: [`docs/oidc-integration.md`](oidc-integration.md) for the existing OIDC authentication path.
