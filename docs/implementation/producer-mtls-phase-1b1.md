# Producer mTLS: Phase 1B.1 — Certificate Identity and Exact Admission Foundation

**Status: foundation slice only. Not producer mTLS end to end. Not wired to any live endpoint.**

This document describes exactly what Phase 1B.1 implements, using the architectural authority of
[ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md)
("Producer Workload Authentication and Gateway Admission") and
[ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md)
("Trusted Producer mTLS Ingress and Gateway Certificate Handoff"), both `Accepted`, and the
companion
[`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md)
architecture document.

## What Phase 1B.1 implements

`src/basis_gateway/auth/producer_mtls.py` implements the reusable, gateway-owned half of the
certificate-identity pipeline those ADRs authorize:

```text
trusted authenticated leaf-certificate assertion
    -> strict URL-escaped PEM decoding
    -> X.509 parsing
    -> exactly one URI SAN
    -> exact case-sensitive producer admission
```

Concretely:

- `decode_producer_certificate_assertion()` — strict, single-pass percent-decoding of the accepted
  ADR-0009 internal transport representation (URL-escaped PEM, corresponding to nginx's
  `$ssl_client_escaped_cert`). Malformed percent-encoding or a non-ASCII character fails closed;
  `+` is never reinterpreted as a space.
- `parse_producer_leaf_certificate()` — structural X.509 parsing only (no chain validation, no
  expiry checking, no CRL/OCSP), using the `cryptography` library.
- `derive_producer_identity()` — the ADR-0008 exactly-one-eligible-URI-SAN rule: zero or multiple
  URI SANs fail closed; Common Name is never consulted, not even as a fallback.
- `admit_producer()` — exact, case-sensitive admission matching against an explicitly supplied
  collection of admitted producer identities; no wildcard, prefix, suffix, substring, regex, or
  case-insensitive matching exists anywhere in this module.

`cryptography` was promoted from a `basis-gateway` dev-only dependency to an explicit runtime
dependency in this PR, because `producer_mtls.py` is production gateway code that imports it
directly.

## What Phase 1B.1 deliberately does not implement

- The trusted NGINX ingress configuration described by ADR-0009 is not built.
- The `X-BASIS-Producer-Client-Cert` internal transport header is not read anywhere. No FastAPI/
  Starlette `Request` is accepted by any function in `producer_mtls.py`.
- `POST /v1/evaluate/operation-aware` is unchanged. No live request path in this repository is
  reachable to `producer_mtls.py`'s functions today.
- `OperationProducerTrust` (`src/basis_gateway/auth/operation_producer.py`) and
  `OPERATION_PRODUCER_SUBJECT_IDS` are unchanged. The existing bearer-authenticated legacy producer
  path behaves exactly as released.
- No gateway configuration surface (trusted-proxy-mode toggle, admitted-identity set) is added in
  this PR — admission is exercised directly via `admit_producer(uri, admitted_uris)` in tests only.
- No Unix-domain-socket gateway startup mode, no protected backend channel, no header-overwrite
  behavior, and no duplicate/missing-header handling are implemented.
- No certificate-chain validation, no trust-anchor evaluation, and no expiration/CRL/OCSP checking
  are implemented in the gateway — those remain the trusted ingress's responsibility under
  ADR-0009, once a later PR wires it.

This is intentional decomposition, not an oversight: it proves certificate decoding, X.509 identity
derivation, URI SAN cardinality, and exact admission independently, before any of them are wired to
a live, trusted-ingress-authenticated request boundary.

## Deferred to a later Phase 1B PR

- Explicit trusted-proxy mTLS mode configuration (a new gateway boolean, default off).
- An NGINX reference configuration and a protected Unix-domain-socket gateway startup mode.
- Strict live retrieval and validation of the `X-BASIS-Producer-Client-Cert` header (missing/
  duplicate/malformed handling) from an actual request.
- Live `OperationProducerTrust` integration recording which mechanism (legacy allowlist vs. mTLS)
  established trust for a given request.
- Dual producer/subject conformance tests, spoof-resistance integration tests (a caller-supplied
  header must never reach parsing), and direct-backend-bypass tests, all run against a real NGINX
  instance per the architecture document's Appendix B test matrix.

## References

- [ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md) — producer workload authentication and admission
- [ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md) — trusted mTLS ingress and certificate handoff
- [`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md) — full topology, trust-fact matrix, and Phase 1B test matrix (Appendix B)
- [`bounded-operation-producer-reference-implementation-plan.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/bounded-operation-producer-reference-implementation-plan.md) — the implementation plan this slice is the first narrow PR of
- `docs/spikes/producer-mtls-certificate-exposure.md` — the Phase 1A spike whose PKI fixtures (`tests/integration/mtls_certs.py`) this PR's unit tests partially reuse
- `src/basis_gateway/auth/operation_producer.py` — the existing, unchanged legacy bearer-subject producer classification this mTLS path is additive to
