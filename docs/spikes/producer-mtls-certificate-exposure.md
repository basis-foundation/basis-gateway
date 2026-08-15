# Phase 1A Spike: Producer mTLS Topology and Peer-Certificate Exposure

## Status

**Outcome B — direct application termination not viable.**

## Question

Can `basis-gateway` safely terminate producer mTLS and obtain the validated client certificate's
URI SAN through a documented, trustworthy application boundary, without relying on
caller-controlled HTTP fields?

## Governing Constraints

From accepted [ADR-0008](https://github.com/basis-foundation/basis-architecture/blob/main/docs/adr/0008-producer-workload-authentication-and-admission.md)
(`basis-architecture`) and its supporting documents:

- mTLS is the first normative producer workload-authentication profile.
- Producer identity derives from exactly one eligible URI SAN. Common Name is never a fallback.
- Authentication and admission are separate decisions; this spike touches neither admission nor
  any later decision.
- Producer identity is distinct from authorization-subject identity.
- Producer identity must never come from request-body assertions.
- Caller-controlled HTTP headers must not become producer identity merely because they contain
  certificate-looking data.
- The first reference slice separately authenticates the authorization subject using the existing
  bearer path (unaffected by this spike).
- No protocol execution is in scope.

This spike does not reopen ADR-0008. It resolves the one question ADR-0008's supporting
implementation plan left as a blocking, unresolved gate before any producer-admission
implementation (Phase 1B) may begin.

## Current Gateway Baseline

Verified by direct source inspection before any spike code was written (`src/basis_gateway/`):

- **App construction / launch**: `main.py:create_app()` builds a `FastAPI` app; TLS termination
  is not configured anywhere in application code. The repository's deployment guidance assumes
  TLS is terminated upstream (no TLS-related settings in `config.py`, no `ssl_*` arguments
  anywhere in `main.py`).
- **Auth**: two independent bearer-token modes (`AuthMode.OIDC`, `AuthMode.BASIS_LOCAL_TOKEN`),
  both verifying a signed token's claims — no transport-level workload authentication exists
  today.
- **Operation-producer trust** (`auth/operation_producer.py`): `classify_operation_producer()`
  classifies an **already-authenticated** `NormalizedSubject` (established by the bearer-token
  path above) against the `OPERATION_PRODUCER_SUBJECT_IDS` allowlist. It has no relationship to
  transport identity and this spike does not change it.
- **Correlation middleware** (`middleware/correlation.py`): explicitly ignores/does not trust any
  caller-supplied header for the correlation ID it assigns — the one precedent in this codebase
  for "a caller-controlled header is not a trust boundary," consistent with this spike's finding
  on certificate-looking headers.
- **No existing TLS documentation** anywhere in `docs/` prior to this spike.
- **ASGI server**: Uvicorn, installed version `0.52.3` (`uvicorn[standard]>=0.29.0` in
  `pyproject.toml`). FastAPI `0.141.1`, Starlette `1.6.0` installed in the environment this spike
  ran in. `asgiref` is not a direct or transitive dependency of this project.
- **Existing cert/X.509 tooling**: `cryptography>=42.0.0` is already a `dev` dependency
  (`pyproject.toml`); `PyJWT[crypto]` is a runtime dependency. `httpx` is already a runtime
  dependency and is reused as this spike's TLS test client.

## Authoritative Sources Consulted

- Uvicorn `0.52.3` installed source: `uvicorn/config.py` (`Config.__init__`, `ssl_*` parameters),
  `uvicorn/protocols/http/{h11_impl,httptools_impl,zttp_impl}.py` (ASGI `scope` construction, all
  three HTTP protocol implementations Uvicorn ships), `uvicorn/protocols/utils.py` (`is_ssl()`).
- [ASGI Specification (main)](https://asgi.readthedocs.io/en/latest/specs/main.html) — the
  `extensions` mechanism.
- [ASGI TLS Extension spec, v0.2](https://asgi.readthedocs.io/en/latest/specs/tls.html) — the
  standardized `scope["extensions"]["tls"]` shape (`server_cert`, `client_cert_chain`,
  `client_cert_name`, `client_cert_error`, `tls_version`, `cipher_suite`).
- `encode/uvicorn` PR #1119, "Implement asgiref tls extension" — opened 2021-07-11, still **open**
  and unmerged as of this spike (most recent activity referenced May 2025). A maintainer
  (Kludex, Aug 2024) redirected further discussion to the still-open spec-level question in
  `django/asgiref#466`. A reviewer's own assessment: the ASGI TLS extension is not fully
  implementable as specified given Python `ssl` module limitations (e.g. `client_cert_chain` can
  only ever carry one certificate; `client_cert_error` cannot be populated). Two related PRs
  (#1842, #2586) also unmerged.
- `encode/uvicorn` discussion #2307 and issue #400 — users independently reporting the same gap
  this spike found: no supported way to reach transport/SSL information from ASGI application
  code.
- CPython `ssl`/`asyncio` documentation — `asyncio.BaseTransport.get_extra_info()` and its
  documented `"ssl_object"`/`"peercert"` extra-info keys (used only in this spike's
  transport-layer ground-truth proof, §"Raw asyncio/ssl" below — never as part of any proposed
  application-code change).

## Test Topology

Two independent harnesses, both driving real TCP/TLS handshakes on `127.0.0.1` — no mocked
certificate objects anywhere in this spike.

```
1. Raw asyncio/ssl ground-truth proof (bypasses Uvicorn/ASGI entirely)

   test client (asyncio + ssl.SSLContext, client cert loaded)
       → real TLS handshake, CERT_REQUIRED
       → asyncio.start_server handler
       → transport.get_extra_info("ssl_object").getpeercert()

2. Uvicorn/basis-gateway-shaped stack (the actual subject under test)

   test client (httpx.Client, explicit ssl.SSLContext, optional client cert)
       → real TLS handshake
       → Uvicorn subprocess, configured via ssl_certfile/ssl_keyfile/
         ssl_ca_certs/ssl_cert_reqs=CERT_REQUIRED — exactly the
         parameters basis-gateway would set in production
       → tests/integration/spike_app.py (raw ASGI callable; not
         basis_gateway.main:app, not FastAPI/Starlette — measures the
         Uvicorn/ASGI boundary unclouded by anything a framework might
         add or strip)
       → JSON response reporting exactly what the ASGI `scope` contained
```

Uvicorn was launched as an actual subprocess (`python -m uvicorn spike_app:app --ssl-certfile
... --ssl-keyfile ... --ssl-ca-certs ... --ssl-cert-reqs 2`), listening on a real ephemeral
`127.0.0.1` port — not Starlette's `TestClient` (which is in-process ASGI transport with no real
socket/TLS involved at all, and therefore cannot answer this question).

## Certificate Fixtures

All generated fresh, in-process, per test run by `tests/integration/mtls_certs.py`
(`cryptography` x509 API) — nothing is committed to the repository. RSA-2048, no passphrase,
`*.test`/`example.test` names (RFC 2606), valid only for driving local `127.0.0.1` handshakes for
the life of one test process.

| Fixture | Signed by | URI SAN(s) | Validity | Purpose |
| - | - | - | - | - |
| `ca` | self | — (CA) | now-1d .. now+30d | Gateway's configured trust anchor |
| `untrusted_ca` | self | — (CA) | now-1d .. now+30d | An independent, *not*-configured CA |
| `server` | `ca` | DNS:localhost, IP:127.0.0.1 | now-1d .. now+30d | Spike server's TLS identity |
| `client_one_uri_san` | `ca` | 1 (`spiffe://example.test/basis/reference-producer-01`) | now-1d .. now+30d | ADR-0008's admitted shape |
| `client_zero_uri_san` | `ca` | 0 (no SAN extension) | now-1d .. now+30d | Otherwise-valid, zero eligible URI SANs |
| `client_multi_uri_san` | `ca` | 2 | now-1d .. now+30d | Otherwise-valid, multiple URI SANs |
| `client_expired` | `ca` | 1 | now-10d .. now-1d (expired) | Deterministic expiry rejection |
| `client_untrusted_ca` | `untrusted_ca` | 1 | now-1d .. now+30d | Proves the trust store is enforced, not just "any cert" |

## Observed Results

All 14 tests in `tests/integration/test_producer_mtls_transport.py` pass; every row below is a
real, executed test, not a projection.

| Scenario | TLS result | HTTP handler reached? | Peer certificate visible to app? | URI SAN visible to app? |
| - | - | - | - | - |
| Trusted client, 1 URI SAN, raw asyncio/ssl (no Uvicorn) | Succeeds | n/a (no ASGI layer) | **Yes** — `getpeercert()` at the transport layer | **Yes** — `('URI', 'spiffe://.../reference-producer-01')` |
| Trusted client, 0 URI SAN, raw asyncio/ssl | Succeeds | n/a | Yes, at transport layer | Yes — `subjectAltName` present but empty of URI entries |
| Trusted client, 2 URI SAN, raw asyncio/ssl | Succeeds | n/a | Yes, at transport layer | Yes — both URIs listed |
| Trusted client, 1 URI SAN, via Uvicorn/ASGI | Succeeds, handler runs, `200 OK` | **Yes** | **No** | **No** |
| Untrusted-CA client, via Uvicorn/ASGI | Handshake fails | **No** | n/a | n/a |
| Missing client certificate, via Uvicorn/ASGI (CERT_REQUIRED) | Handshake fails | **No** | n/a | n/a |
| Expired client certificate, via Uvicorn/ASGI | Handshake fails | **No** | n/a | n/a |
| Zero/one/multi URI SAN clients, via Uvicorn/ASGI | All succeed | Yes, for all three | No, for all three | No — **all three produce an identical response body** |
| Ordinary caller sets `X-Client-Cert`/`X-SSL-Client-Cert`/`X-Client-DN`/`X-Forwarded-Client-Cert` | Succeeds (already-trusted mTLS client) | Yes | n/a | Header value echoed back **verbatim, unmodified** |

## Application Exposure Mechanism

```
TLS stack (OpenSSL via CPython ssl module)
    → asyncio Transport (transport.get_extra_info("ssl_object")/("peercert")
      — documented, stable, part of the Python standard library)
    → Uvicorn's asyncio.Protocol subclass (H11Protocol / HttpToolsProtocol /
      ZttpProtocol — all three shipped HTTP implementations were inspected)
    → ⨯ STOPS HERE. None of the three protocol classes read
      transport.get_extra_info("ssl_object")/("peercert") when constructing
      the ASGI `scope` dict. `self.transport` is held privately by the
      protocol object and is never passed into `scope`, and `scope` carries
      no `"extensions"` key at all — confirmed both by direct source
      inspection and, empirically, by this spike's own running server:
      `scope.keys()` for a real, successfully-validated trusted mTLS
      connection is exactly
      {asgi, client, headers, http_version, method, path, query_string,
      raw_path, root_path, scheme, server, state, type} — no more, no less.
    → gateway application code (FastAPI routes, middleware, or any other
      ASGI application)
```

The only scope field influenced by TLS at all is `scheme` (`"https"` vs. `"http"`, derived from
`is_ssl(transport)`). An application cannot distinguish "connected over a successfully validated
mTLS client certificate" from "connected over plain HTTPS with no client certificate presented"
by any means available through the ASGI interface.

The ASGI specification defines exactly the mechanism this would need —
[the TLS extension](https://asgi.readthedocs.io/en/latest/specs/tls.html),
`scope["extensions"]["tls"]` — but it is **not implemented by the installed Uvicorn version**, and
has not been implemented by any released Uvicorn version as of this spike: the four-year-old PR
adding it remains open and unmerged, blocked on unresolved questions in the ASGI spec repository
itself, not merely on gateway-side effort. This is not a private/unsupported implementation
detail that basis-gateway could route around by upgrading a dependency — it is an acknowledged,
long-standing gap in the entire Uvicorn/ASGI ecosystem.

## Security Analysis

**Can a request body spoof producer identity?** Irrelevant to this boundary — this spike's
finding is that *no* application-visible boundary carries certificate identity at all, from any
source. A request body was never a candidate.

**Can an arbitrary HTTP header spoof producer identity?** This spike does not propose trusting
any header for producer identity, and the reason is demonstrated directly: `X-Client-Cert`,
`X-SSL-Client-Cert`, `X-Client-DN`, and `X-Forwarded-Client-Cert` were each sent by an ordinary,
already-mTLS-authenticated test client with an attacker-chosen value, and each arrived at the ASGI
application **byte-for-byte unmodified**. Nothing in this Uvicorn/FastAPI/Starlette stack strips,
validates, or protects any of these header names. A reverse-proxy fallback (Outcome B's
implication, below) would still need to independently guarantee such headers cannot originate
from outside the trusted proxy hop — this spike does not evaluate that, since no reverse proxy is
in scope here.

**Does possession of a trusted certificate automatically imply admission?** No — not evaluated by
this spike at all; Phase 1B performs that separate check, once an exposure boundary exists to
build it on top of.

**Does TLS producer identity become authorization subject identity?** No — this spike populates
no subject, alters no authentication path, and the existing bearer-token subject flow
(`auth/oidc.py`, `auth/basis_local_token.py`, `auth/subject_mapper.py`) is untouched and
unexercised by any spike code.

**Does a valid certificate prove evidence correctness or authorization?** No — out of scope for
this spike; not evaluated.

## Decision

**Outcome B — direct application termination is not viable.**

Per the brief's own Outcome A checklist, every load-bearing property up to and including "URI SANs
are obtainable from that validated certificate data" was proven — client certificates can be
required (`ssl_cert_reqs=CERT_REQUIRED`), validated against a configured CA
(`ssl_ca_certs`), and TLS-layer validation happens before ordinary request processing (confirmed:
untrusted-CA, missing-certificate, and expired-certificate scenarios all fail the handshake with
the ASGI handler never invoked). But the next required property — "application code receives peer
certificate information through a documented/supportable boundary" — **fails**: stock Uvicorn
provides no such boundary under any of its three shipped HTTP protocol implementations, the one
standardized mechanism that would provide it (the ASGI TLS extension) is unimplemented anywhere in
the current Uvicorn release line, and the years-old effort to add it is stalled on unresolved
questions in the ASGI specification itself — not a small, uvicorn-side gap this project could
close with a documented, stable, minimal adjustment.

This spike explicitly evaluated Step 9's "minimal server adjustment" possibility and rejects it
for this PR: the only way to make Uvicorn expose peer-certificate data today is to subclass one of
its internal `asyncio.Protocol` implementations and manually inject
`transport.get_extra_info("ssl_object")`/`getpeercert()` output into the `scope` dict before
invoking the ASGI application — reaching into `H11Protocol`/`HttpToolsProtocol`/`ZttpProtocol`
internals that are not part of Uvicorn's public, documented, or stable API surface (there is no
supported extension point for scope construction; `Config(http=...)` accepts a full replacement
protocol class, not a scope-augmentation hook). That is precisely the "private/unsupported
implementation detail" Outcome B's own criteria name as disqualifying, and precisely the kind of
change the brief instructs this spike not to make casually. It remains a candidate worth
evaluating deliberately in a dedicated `basis-architecture` planning PR — alongside the
already-architecture-approved reverse-proxy fallback — rather than being adopted unreviewed inside
a spike.

## Implication for Phase 1B

**Phase 1B is blocked pending a reviewed proxy-to-gateway trust-boundary plan.** No producer
admission, exact URI SAN allowlisting, `OperationProducerTrust` mTLS semantics, or
`OPERATION_PRODUCER_SUBJECT_IDS` migration may proceed until a `basis-architecture` planning
update defines how a trust boundary in front of `basis-gateway` (most plausibly a reverse proxy
terminating mTLS and forwarding validated identity through a mechanism the gateway can trust — not
an arbitrary, caller-writable header) is established. This spike's raw-asyncio/ssl proof (§Test
Topology, item 1) confirms the certificate data itself is fully obtainable at the TLS layer by
*something* — the unresolved question for that follow-up planning work is exclusively how it
crosses the proxy-to-gateway hop in a way the gateway can trust, not whether it exists.

This spike's test harness (`tests/integration/mtls_certs.py`, `tests/integration/spike_app.py`,
`tests/integration/test_producer_mtls_transport.py`) is retained and reusable: the PKI generator
and the raw-asyncio/ssl proof both remain directly applicable to validating whichever
proxy-to-gateway trust mechanism the follow-up architecture work selects.

## Non-Claims

This spike does not implement, and this PR contains no code that implements:

- producer admission;
- producer trust classification (`OperationProducerTrust` mTLS semantics);
- `OPERATION_PRODUCER_SUBJECT_IDS` migration or any change to its existing behavior;
- subject/authentication changes (OIDC, `basis_local_token`, or otherwise);
- evidence handling of any kind (`AdapterEvidenceReference`, `IdentityEvidenceReference`, or
  otherwise);
- protocol execution;
- any reverse proxy, `nginx`/Envoy/HAProxy/stunnel configuration, or forwarding-header trust logic.
