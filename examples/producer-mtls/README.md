# Producer mTLS Reference Ingress (Phase 1B.2, live-wired as of Phase 1B.3)

This directory holds the one reference NGINX configuration for the bounded
operation-producer mTLS ingress topology defined by
[ADR-0009](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md)
and
[`producer-mtls-proxy-trust-boundary.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/producer-mtls-proxy-trust-boundary.md).

`nginx.conf.template` is the **single source configuration** exercised by
both `tests/integration/test_producer_mtls_trusted_proxy_boundary.py`
(Phase 1B.2's boundary-only proof, against a minimal test backend) and
`tests/integration/test_producer_mtls_live_gateway.py` (Phase 1B.3's
live-gateway proof, against the real `basis_gateway.main:app`) — both via
`tests/integration/trusted_proxy_harness.py` — there is deliberately no
separate "documentation copy" of this file that could drift from what the
integration tests actually run.

## What this is

A bounded **reference** topology for the first producer slice:

```text
operation producer
    |  HTTPS + required client certificate
    v
NGINX (this template)
    |  ssl_verify_client on; validates against a configured producer CA
    |  unconditionally overwrites X-BASIS-Producer-Client-Cert
    |  forwards Authorization unchanged
    v
Unix domain socket (restrictive permissions)
    v
basis-gateway (Uvicorn --uds; no TCP listener in this mode)
```

Only `POST /v1/evaluate/operation-aware` is exposed. Every other path
returns `404` directly from nginx and never reaches the Unix-socket backend.

## What this is not

- Not a general-purpose reverse-proxy ingress for `/health`, `/ready`,
  `/v1/evaluate`, console traffic, or any other route.
- Not a producer admission mechanism — nginx performs TLS-level certificate
  validation only. URI SAN derivation and exact producer admission remain
  entirely inside `basis-gateway`
  (`src/basis_gateway/auth/producer_mtls.py`,
  `src/basis_gateway/auth/producer_mtls_trusted_proxy.py`).
- As of Phase 1B.2, this topology was not wired to any live `basis-gateway`
  endpoint. As of Phase 1B.3, it is: `test_producer_mtls_live_gateway.py`
  drives the real `POST /v1/evaluate/operation-aware` route behind exactly
  this configuration — see `docs/implementation/producer-mtls-phase-1b3.md`
  for exactly what is and is not implemented at the gateway side, and
  `docs/implementation/producer-mtls-phase-1b2.md` for this topology's own
  original scope.
- Not a `basis-deploy` packaging artifact. No such repository exists.

## Rendering

`@@TOKEN@@`-style placeholders (chosen because nginx configuration syntax
itself uses `$` and `{ }`) are substituted by
`tests/integration/trusted_proxy_harness.py` for the integration-test
topology: ephemeral ports, temporary certificate paths, and a temporary
Unix-socket path, all scoped to a single test run. A deployment reusing this
template for a real reference environment must substitute the same tokens
with its own paths and CA bundle — this template does not ship a production
CA, certificate, or socket path.

## Requirements

Real NGINX (any recent distribution build with `ngx_http_ssl_module`, which
ships in the standard prebuilt packages for Debian/Ubuntu and most other
distributions) is required to exercise the integration suite. Tests that
depend on it are skipped, with an explicit reason, when the `nginx`
executable is not found on `PATH`.
