# Producer mTLS: Phase 1B.2 — Trusted Producer mTLS Ingress Boundary

**Status: trust-boundary/topology slice only. Not wired to the live operation-aware endpoint. Not
producer mTLS end to end.**

This document describes exactly what Phase 1B.2 implements, using the architectural authority of
[ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md)
("Producer Workload Authentication and Gateway Admission") and
[ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md)
("Trusted Producer mTLS Ingress and Gateway Certificate Handoff"), both `Accepted`, and the
companion
[`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md)
architecture document. It builds directly on
[Phase 1B.1](producer-mtls-phase-1b1.md), which proved certificate identity semantics
(`src/basis_gateway/auth/producer_mtls.py`) operating on an already-supplied assertion value. Phase
1B.2 proves the boundary that makes an assertion value trustworthy in the first place.

## Implemented

- **Trusted-proxy mode configuration foundation.** `GatewayConfig.operation_producer_mtls_trusted_proxy_enabled`
  (`OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED`), a boolean, default `False`. See
  `src/basis_gateway/config.py` and [`docs/configuration.md`](../configuration.md). No producer CA
  path, no NGINX TLS private key, and no gateway-side TLS trust-anchor configuration is added to
  `GatewayConfig` — NGINX owns producer TLS validation entirely; the gateway configuration surface
  is a single enablement boolean.
- **Strict internal certificate-header retrieval.** `src/basis_gateway/auth/producer_mtls_trusted_proxy.py`'s
  `retrieve_trusted_producer_certificate_assertion()`:
  - when trusted-proxy mode is disabled, the private header is never inspected — no lookup, no
    parsing trigger, no behavior change for ordinary TCP deployments;
  - when enabled and the header is absent, returns `None` (no producer certificate assertion for
    this request — this does not by itself reject the request; that endpoint-level decision remains
    out of scope, see **Still not implemented** below);
  - when enabled and the header appears more than once (case-insensitive by header name, checked
    against the raw ASGI header list so a non-lowercased occurrence cannot defeat detection), raises
    `DuplicateProducerCertificateAssertionError` — fails closed;
  - when enabled and the value exceeds `MAX_ASSERTION_SIZE_BYTES` (16 KiB), raises
    `OversizedProducerCertificateAssertionError` — fails closed before any decoding or parsing;
  - never includes the raw header value in an exception message.
- **Tested NGINX reference configuration.** `examples/producer-mtls/nginx.conf.template` — the
  single source configuration the integration suite renders and executes (no separate
  documentation-only copy). Requires and validates producer client certificates
  (`ssl_verify_client on;`, `ssl_client_certificate`), exposes only
  `POST /v1/evaluate/operation-aware`, proxies to a Unix-domain-socket upstream, and unconditionally
  overwrites `X-BASIS-Producer-Client-Cert` with `$ssl_client_escaped_cert`. No directive touches
  `Authorization`.
- **Unix-domain-socket backend topology.** `tests/integration/trusted_proxy_harness.py`'s
  `TrustedProxyBackend` starts the test ASGI application
  (`tests/integration/trusted_proxy_app.py`) via `uvicorn ... --uds <path>` only — no `--host`/
  `--port` is passed, so no TCP application listener is opened. Socket permissions are set to
  `0770` after creation.
- **Real certificate validation at NGINX, executed against a real process.** Valid/missing/
  untrusted-CA/expired producer certificates are exercised against a real `nginx` subprocess and
  real TLS handshakes (`tests/integration/test_producer_mtls_trusted_proxy_boundary.py`), reusing
  the retained Phase 1A PKI fixtures (`tests/integration/mtls_certs.py`).
- **Header overwrite / spoof resistance, proven empirically.** An admitted producer certificate
  connects while simultaneously supplying an attacker-controlled
  `X-BASIS-Producer-Client-Cert` value (a different, real, multi-URI-SAN certificate); the test
  asserts the backend derives the *real* TLS peer certificate's URI SAN, never the attacker's value
  or an error the attacker's value would have caused if it had leaked through.
- **Direct-backend-bypass evidence.** `/proc`-based introspection confirms the backend process holds
  no listening TCP socket; a plaintext-HTTP attempt against the ingress's own (TLS-only) port fails
  at the transport level.
- **Route scoping.** The operation-aware `POST` route is proxied; an unrelated path and an
  unsupported method on the operation-aware route both return `404`/`403`/`405` directly from nginx
  without ever reaching the backend (verified via the backend's own request log).
- **Authorization preservation.** A synthetic, non-secret bearer value is proven to reach the
  backend unchanged, on the same request where the certificate identity is independently derived
  correctly — proving the two facts travel the proxy hop independently, without validating the
  token itself.

## Still not implemented

- Live `OperationProducerTrust` mTLS classification — `src/basis_gateway/auth/operation_producer.py`
  is unchanged.
- `classify_operation_producer()` is unchanged; `OPERATION_PRODUCER_SUBJECT_IDS` behavior is
  unchanged.
- Live producer admission in the operation-aware endpoint. `POST /v1/evaluate/operation-aware` does
  not call anything in `producer_mtls.py` or `producer_mtls_trusted_proxy.py` — both remain
  reachable only from tests.
- Dual mTLS-producer-plus-bearer-subject authorization evaluation.
- Production audit enrichment for producer trust (`GatewayAuditEvent` is unchanged).
- A producer runtime, evidence persistence, `reference_id` minting, or any protocol execution — none
  of the bounded reference slice's steps beyond the trust boundary itself are implemented here.
- An admitted-producer-URI-SAN configuration surface. Phase 1B.1 already owns the admission
  primitive (`admit_producer`); no new gateway configuration for the admitted-identity *set* is
  added in this PR, consistent with `producer-mtls-proxy-trust-boundary.md` deferring that wiring to
  Phase 1B.3.

## Trust boundary this PR proves (and does not assume)

The private header `X-BASIS-Producer-Client-Cert` is not trusted because of its name. It is
trustworthy only because, together:

1. NGINX requires and validates a producer client certificate before any HTTP request is forwarded.
2. NGINX unconditionally overwrites the header on every forwarded request
   (`proxy_set_header` replaces, never appends).
3. The ingress-to-gateway hop is a Unix domain socket with restrictive permissions — no ordinary
   network caller can write to it directly.
4. `basis-gateway` opens no TCP application listener in this mode.
5. Trusted-proxy mode is explicitly, and safely, disabled by default.
6. Gateway code validates the assertion's shape (single occurrence, size-bounded) before any of it
   is handed to Phase 1B.1's decoder/parser.

No code in this PR assumes "header present → producer authenticated." Producer identity
interpretation and admission remain entirely gateway-owned, unchanged from ADR-0008, and are not
invoked from any live request path as of this PR.

## Residual risk (accepted, not solved here)

A same-host process running with sufficient filesystem permission to the Unix socket could connect
directly and present arbitrary headers, including a forged internal certificate header. This is the
same accepted residual risk `producer-mtls-proxy-trust-boundary.md` §9 and §19 item 3 already
document; it is bounded by restrictive socket permissions, not eliminated, and this PR does not
attempt to solve it further.

## References

- [ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md) — producer workload authentication and admission
- [ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md) — trusted mTLS ingress and certificate handoff
- [`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md) — full topology, trust-fact matrix, and Phase 1B test matrix (Appendix B)
- [Phase 1B.1](producer-mtls-phase-1b1.md) — certificate identity and exact admission foundation, reused unchanged by this PR
- `src/basis_gateway/auth/producer_mtls_trusted_proxy.py` — this PR's retrieval primitive
- `examples/producer-mtls/` — the reference NGINX configuration and its own README
- `tests/integration/test_producer_mtls_trusted_proxy_boundary.py`,
  `tests/integration/trusted_proxy_harness.py`, `tests/integration/trusted_proxy_app.py` — the real-NGINX
  integration harness this PR adds
- `tests/test_producer_mtls_trusted_proxy.py` — unit coverage for the retrieval primitive
