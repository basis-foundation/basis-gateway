# Producer mTLS: Phase 1B.3 — Live mTLS Producer Trust Integration

**Status: gateway-side Phase 1B completion slice. Producer mTLS is now real in the live
`POST /v1/evaluate/operation-aware` path. The broader bounded operation-producer reference
implementation (producer runtime, evidence retention, `reference_id` minting, adapter-to-gateway
submission, protocol execution) remains not implemented — see "Still not implemented" below.**

This document describes exactly what Phase 1B.3 implements, using the architectural authority of
[ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md)
("Producer Workload Authentication and Gateway Admission") and
[ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md)
("Trusted Producer mTLS Ingress and Gateway Certificate Handoff"), both `Accepted`, and the
companion
[`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md)
architecture document. It builds directly on
[Phase 1B.1](producer-mtls-phase-1b1.md) (certificate identity and exact admission primitives,
`src/basis_gateway/auth/producer_mtls.py`) and
[Phase 1B.2](producer-mtls-phase-1b2.md) (the trusted-proxy internal certificate-header retrieval
boundary, `src/basis_gateway/auth/producer_mtls_trusted_proxy.py`, and the real-NGINX trust-boundary
integration suite). Neither of those modules' own proven logic is duplicated here — Phase 1B.3 is
strictly an orchestration and wiring slice.

## Implemented

- **Admitted mTLS URI-SAN configuration.** `GatewayConfig.operation_producer_mtls_admitted_uris`
  (`OPERATION_PRODUCER_MTLS_ADMITTED_URIS`), a `frozenset[str]`, default empty, parsed from a JSON
  array of exact strings (not the comma-separated convention `OPERATION_PRODUCER_SUBJECT_IDS`
  uses — a deliberately distinct trust mechanism, distinct parser). See `src/basis_gateway/config.py`
  and [`docs/configuration.md`](../configuration.md#operation-aware-authorization).
- **Live mTLS producer trust orchestration.** A new module,
  `src/basis_gateway/auth/operation_producer_mtls.py`, composes Phase 1B.2's
  `retrieve_trusted_producer_certificate_assertion()` and Phase 1B.1's
  `decode_producer_certificate_assertion()` / `parse_producer_leaf_certificate()` /
  `derive_producer_identity()` / `admit_producer()` into one request-scoped
  `OperationProducerTrust` result (`resolve_mtls_operation_producer_trust`), and mode-selects
  between that pipeline and the unchanged legacy `classify_operation_producer()`
  (`resolve_operation_producer_trust`), based on
  `GatewayConfig.operation_producer_mtls_trusted_proxy_enabled`. No certificate parsing, header
  retrieval, or admission-matching logic is reimplemented.
- **Additive `OperationProducerTrust`.** `OperationProducerTrustSource` gains two new members
  (`MTLS_ADMITTED_URI_SAN`, `MTLS_URI_SAN_NOT_ADMITTED`), and
  `OperationProducerTrust` gains one new field, `producer_workload_identity: str | None = None` —
  the mTLS producer's derived URI SAN, populated only on the `MTLS_*` sources, and never written to
  `operation_producer_subject_id`, `authorization_subject_id`, or any other field `basis-core`
  consumes as the authorization subject. The three original legacy members/behavior are byte-for-byte
  unchanged. See `src/basis_gateway/auth/operation_producer.py`. There is no third `MTLS_*` member
  representing a missing certificate assertion — see "Missing-assertion semantics" below.
- **Live route integration.** `POST /v1/evaluate/operation-aware`
  (`basis_gateway.api.routes.evaluate_operation_aware`) now calls
  `resolve_operation_producer_trust()` instead of unconditionally calling
  `classify_operation_producer()`. A missing, malformed, duplicated, oversized, or
  certificate-identity-invalid mTLS assertion is rejected with `400` before request composition or
  kernel evaluation, with a dedicated audit action (`gateway.operation_aware_producer_mtls_trust_failed`)
  and a distinguishing internal reason code — never `basis-core` invocation, never certificate/PEM
  content in the response or logs.
- **Trusted-mode/legacy-mode coexistence, no fallback.** When trusted-proxy mode is enabled, the
  legacy `OPERATION_PRODUCER_SUBJECT_IDS` allowlist is never consulted for that request — there is
  no code path by which a bearer subject's legacy-allowlist membership can substitute for a failed
  or absent mTLS admission. When trusted-proxy mode is disabled (the default), the legacy path
  behaves exactly as released; the private certificate header is never inspected.
- **Independent bearer authorization subject.** Bearer authentication
  (`basis_gateway.auth.runtime.authenticate`) is unchanged and remains mandatory regardless of
  producer-mTLS outcome. An admitted mTLS producer does not authenticate the bearer subject; a valid
  bearer subject does not authenticate the mTLS producer. The mTLS producer's URI SAN is never
  assigned to `subject_id` or any authorization-subject field.
- **Producer-owned-context enforcement, reused unchanged.** The existing
  `compose_operation_aware_input()` gate (`UntrustedOperationProducerContextError`) is reused
  unchanged for the mTLS path — it inspects only `producer_trust.status`, not the mechanism, so no
  new gate was invented. Its internal identity-consistency invariant (Step 2) was extended
  additively, mechanism-aware, so a `TRUSTED` result reached via `MTLS_ADMITTED_URI_SAN` is checked
  against the mTLS-specific invariant (must carry a URI SAN, must never carry a subject id as
  `operation_producer_subject_id`) rather than the legacy invariant (must carry the bearer subject
  id) — see `src/basis_gateway/core/operation_aware_composition.py`.
- **Real NGINX → live gateway proof.** A new integration suite,
  `tests/integration/test_producer_mtls_live_gateway.py`, drives the real
  `basis_gateway.main:app` (not a minimal test stand-in) behind the same real NGINX + Unix-domain-
  socket topology Phase 1B.2 proved, using `AUTH_MODE=basis_local_token` so no external OIDC
  issuer is required. See "Real-NGINX live-gateway suite" below.
- **Gateway-side Phase 1B completion.** Producer TLS authentication → trusted certificate handoff →
  URI-SAN identity → exact producer admission → independent bearer-subject authentication → live
  operation-aware authorization is now fully implemented end to end inside `basis-gateway`.

## Still not implemented

- `basis-operation-producer-reference` (the operation-producer runtime repository itself).
- Adapter invocation runtime (`basis-adapters` normalization → evidence construction, wired to a
  live producer process).
- Evidence persistence (digest-addressed blob retention, reference-binding records).
- Retain-before-mint lifecycle (`reference_id` minted only after confirmed blob retention).
- `reference_id` binding (the `reference_id` → digest/storage-key durable record).
- Final `AdapterEvidenceReference` producer assembly.
- An mTLS producer *client* (a real workload holding a certificate/private key and submitting
  requests) — Phase 1B.3 proves the gateway side only; the producer side of this boundary is
  exercised by test fixtures (`tests/integration/mtls_certs.py`), not a real runtime.
- Producer-side bearer credential handling (issuance, storage, rotation of the *second* credential
  a real producer would hold).
- End-to-end adapter → gateway submission (a live `basis-adapters` REST normalization result
  actually submitted through this boundary).
- Protocol execution of any kind (REST, BACnet, Modbus, OPC UA, MQTT, DNP3, IEC 61850, KNX, Niagara,
  or any other OT protocol).
- Execution evidence.

> Gateway-side producer authentication/admission is implemented, but the bounded operation-producer
> reference slice is not yet complete.

## Configuration

See [`docs/configuration.md`](../configuration.md#operation-aware-authorization) for the
authoritative reference. Summary:

| Variable | Type | Default | Notes |
|---|---|---|---|
| `OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED` | `bool` | `false` | Selects the live producer-trust mechanism for `POST /v1/evaluate/operation-aware`. `false` (default): legacy `OPERATION_PRODUCER_SUBJECT_IDS`. `true`: mTLS certificate pipeline, exclusively. |
| `OPERATION_PRODUCER_MTLS_ADMITTED_URIS` | `frozenset[str]`, from a JSON array | `[]` (empty) | Exact-match admitted producer URI SANs. Empty trusts no mTLS producer — a legitimate, fail-closed configuration even with trusted-proxy mode enabled. |

## Live route wiring — order of operations

```text
1. AUDIT_FAIL_CLOSED strict-mode precheck (unchanged)
2. parse and shape-validate the request body (unchanged)
3. bearer extraction + runtime authentication (unchanged) -- establishes the
   authorization subject, independent of producer trust
4. operation-producer trust classification (Phase 1B.3):
     trusted-proxy mode disabled -> classify_operation_producer() (unchanged)
     trusted-proxy mode enabled  -> resolve_mtls_operation_producer_trust():
         retrieve internal certificate assertion (Phase 1B.2)
             -> missing: MissingProducerCertificateAssertionError raised;
                reject 400, no kernel evaluation, no OperationProducerTrust
                constructed, no legacy-allowlist fallback (Layer 2)
             -> duplicate/oversized: reject 400, no kernel evaluation
         decode + parse + derive URI SAN (Phase 1B.1)
             -> malformed encoding/certificate, zero/multiple URI SAN:
                reject 400, no kernel evaluation
         admit_producer() (Phase 1B.1)
             -> admitted: TRUSTED / MTLS_ADMITTED_URI_SAN
             -> not admitted: UNTRUSTED / MTLS_URI_SAN_NOT_ADMITTED
5. provenance-gated composition (unchanged, compose_operation_aware_input) --
   rejects producer-only fields from a non-TRUSTED caller before any other
   composition work; mechanism-aware identity-consistency invariant (Phase
   1B.3) validates the TRUSTED case against the correct mechanism-specific
   rule
6. retrieve the initialized operation-aware evaluator (unchanged)
7. invoke the kernel exactly once (unchanged)
8. classify the HTTP response (unchanged)
9. durable gateway audit record (unchanged, additively enriched --
   operation_producer_workload_identity)
```

Bearer authentication (step 3) always precedes producer-trust classification (step 4) in this
handler's mechanical order — this is the route's pre-existing order, unchanged by Phase 1B.3. This
does not weaken any security invariant: producer trust and subject authentication remain two
independent facts regardless of which is computed first, and the kernel is invoked only after both
have completed (step 3 succeeding and step 4 not raising a fail-closed exception). A malformed mTLS
assertion is therefore rejected *after* bearer authentication has already succeeded, but *before*
any kernel evaluation — the "admitted producer + invalid bearer" and "invalid producer + valid
bearer" cases both still reach a pre-kernel rejection, just via different steps depending on which
check fails.

## Missing-assertion semantics (architecture reconciled)

An earlier revision of this document reported a stop condition: `producer-mtls-proxy-trust-boundary.md`
contained two passages that appeared to be in tension for the specific case of a **missing** (not
malformed, not duplicated) internal certificate assertion while trusted-proxy mode is enabled — §11's
"Missing-value behavior" (read as authorizing the request to proceed as an ordinary bearer-only
caller) versus §18's Layer 2 failure-semantics table (read as grouping "missing" with "duplicated"/
"malformed" under a uniform "fail closed" requirement). That tension has since been **reconciled and
merged** in `basis-architecture` (`docs: reconcile producer mTLS missing assertion semantics`,
updating §11/§17/§18/§19 item 17 and Appendix B of `producer-mtls-proxy-trust-boundary.md`). The
merged architecture is now unambiguous, and this implementation conforms to it:

> Missing internal certificate assertion after a request reaches `basis-gateway` in trusted-proxy
> mode is a **fail-closed Layer-2 trust-boundary failure**, not an ordinary untrusted-producer
> classification.

Concretely, when trusted-proxy producer-mTLS mode is enabled and a request reaches `basis-gateway`
without `X-BASIS-Producer-Client-Cert`:

- `basis_gateway.auth.operation_producer_mtls.resolve_mtls_operation_producer_trust` raises
  `MissingProducerCertificateAssertionError` (a subtype of the existing
  `producer_mtls_trusted_proxy.TrustedProxyAssertionError` hierarchy, alongside
  `DuplicateProducerCertificateAssertionError`/`OversizedProducerCertificateAssertionError`) instead
  of returning an `OperationProducerTrust` result.
- **No `OperationProducerTrust` is constructed** for that request — there is no longer an
  `MTLS_ASSERTION_ABSENT` source; that member has been removed from `OperationProducerTrustSource`.
- **No fallback** to the legacy `OPERATION_PRODUCER_SUBJECT_IDS` allowlist occurs, even when the
  request's bearer subject is itself present in that allowlist — allowlist membership authenticates a
  bearer subject, not the trusted-proxy boundary, and cannot repair a Layer-2 failure.
- **No `basis-core` evaluation** occurs — the live route
  (`basis_gateway.api.routes.evaluate_operation_aware`) catches
  `MissingProducerCertificateAssertionError` alongside the other producer-mTLS trust-boundary
  exceptions, rejects the request with the existing `producer_certificate_rejected` `400` response
  shape, records a dedicated audit reason
  (`basis_gateway.audit.operation_aware_gateway_events.REASON_PRODUCER_MTLS_MISSING_ASSERTION`), and
  never invokes the kernel.

This is deliberately distinguished from two other conditions the merged architecture treats
differently:

- **Layer 1 — no client certificate presented to NGINX.** NGINX rejects the TLS handshake before any
  HTTP request is forwarded; `basis-gateway` is never reached; no `OperationProducerTrust` exists for
  the attempt because no application-level request occurred.
- **Layer 4 — valid certificate, URI SAN not admitted.** The trusted-proxy boundary worked correctly
  and produced a genuine, parseable certificate identity that simply is not in
  `OPERATION_PRODUCER_MTLS_ADMITTED_URIS`. This remains an ordinary `UNTRUSTED` /
  `MTLS_URI_SAN_NOT_ADMITTED` admission outcome, unchanged by this correction — the request may still
  proceed as an ordinary bearer-only caller if it asserts no producer-owned context, subject to the
  existing `UntrustedOperationProducerContextError` gate.

The Phase 1B.2 retrieval primitive
(`producer_mtls_trusted_proxy.retrieve_trusted_producer_certificate_assertion`) is unchanged by this
correction and still returns `None` for absence — it remains a low-level shape/retrieval primitive
that only reports whether an internal assertion was present. Phase 1B.3's live, mode-aware resolver
is the layer that knows a given request is actually operating under live trusted-proxy semantics, and
therefore that a `None` retrieval result is fatal for that request; the retrieval primitive itself is
not required to know that endpoint-level policy.

## Real-NGINX live-gateway suite

`tests/integration/test_producer_mtls_live_gateway.py` reuses the Phase 1B.2 harness
(`tests/integration/trusted_proxy_harness.py`, `tests/integration/mtls_certs.py`) but points the
Unix-socket backend at the **real** `basis_gateway.main:app` (via `uvicorn basis_gateway.main:app
--uds ...`) instead of the Phase 1B.2 minimal test stand-in
(`tests/integration/trusted_proxy_app.py`), configured with:

- `AUTH_MODE=basis_local_token` (no external OIDC issuer or JWKS endpoint required);
- `OPERATION_AWARE_ENABLED=true` and a temporary, checked-in-shape operation-aware policy bundle;
- `OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED=true`;
- `OPERATION_PRODUCER_MTLS_ADMITTED_URIS=["spiffe://example.test/basis/reference-producer-01"]`
  (the Phase 1A/1B.2 PKI fixture's own `ONE_URI_SAN` constant);
- `OPERATION_PRODUCER_SUBJECT_IDS` unset (empty) — the positive-path bearer subject
  (`service-maintenance-operator-01`) is deliberately never a member of the legacy allowlist.

Skipped, with the same explicit reason Phase 1B.2 already uses, when the `nginx` executable is not
on `PATH`.

## References

- [ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md)
- [ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md)
- [`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md)
- [Phase 1B.1](producer-mtls-phase-1b1.md), [Phase 1B.2](producer-mtls-phase-1b2.md)
- `src/basis_gateway/auth/operation_producer_mtls.py` — this PR's orchestration module
- `src/basis_gateway/auth/operation_producer.py` — additive `OperationProducerTrust`/`OperationProducerTrustSource`
- `src/basis_gateway/api/routes.py` — live route wiring
- `src/basis_gateway/core/operation_aware_composition.py` — mechanism-aware identity-consistency invariant
- `tests/integration/test_producer_mtls_live_gateway.py` — the real-NGINX live-gateway suite
