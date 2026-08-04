# Operation-Aware Gateway Demonstration

A bounded, reproducible, offline demonstration of the real operation-aware
gateway path — the same code, the same HTTP route, and the same public
`basis-core` kernel this repository ships, exercised end to end with no
external infrastructure.

---

## Purpose

This demonstration proves that a signed identity, submitted through the real
gateway HTTP boundary, produces a real, auditable authorization decision —
and that the gateway's architectural invariants hold under six concrete
scenarios: allow, explicit deny, default deny, `not_applicable`, untrusted
producer rejection, and a semantically invalid policy bundle at startup.

It proves:

- authentication is real (a signed BASIS-local token, verified by the real
  gateway verifier);
- producer trust is derived only from configuration, never from a caller's
  claim about itself;
- the kernel decision (`basis-core`'s public `OperationAwareEnforcementPoint`)
  is never bypassed, mocked, or recomputed by the gateway;
- `not_applicable` and `deny` are distinct kernel outcomes, even though both
  collapse to HTTP `403`;
- explicit deny and default deny are distinguishable through matched-rule
  evidence, not fabricated;
- a pre-kernel rejection (untrusted producer context) carries no kernel
  evidence, ever;
- a semantically broken policy bundle leaves the process alive
  (`/health` 200) but not ready (`/ready` 503), with the route still
  registered (`503`, never `404`).

It does **not** prove:

- that a physical device executed anything (no adapter, no protocol, no
  device is involved in this repository at all);
- production availability, durable audit storage, or hosted-service
  behavior;
- `basis-console` integration (Training mode / Operator mode) — that is
  future work in a different repository;
- multi-tenancy or policy hot reload.

See [Limitations](#limitations) below for the complete list.

---

## Requirements

Use this repository's existing development installation — nothing beyond
it:

```bash
cd basis-gateway
pip install -e ../basis-core
pip install -e ".[dev]"
```

No Docker, no live OIDC provider, no database, no network access, no OT
device, no BACnet/Modbus/MQTT/OPC UA, and no sibling service running
separately. `[dev]` is required because this script generates an ephemeral
RSA key pair (`cryptography`, already a `[dev]` dependency of this
repository) and issues locally-signed tokens (`PyJWT`, already a runtime
dependency).

---

## Run it

```bash
python demo/operation-aware/run_demo.py
```

Run a single scenario:

```bash
python demo/operation-aware/run_demo.py --scenario allow
```

Machine-readable output:

```bash
python demo/operation-aware/run_demo.py --json
```

Exit code is `0` only when every scenario matches its expected result
(`demo/operation-aware/expected/scenario-summary.json`); any mismatch is
printed and the process exits non-zero.

---

## Scenarios

| Scenario | What it shows |
|---|---|
| `allow` | An authenticated, authorized read reaches an explicit `allow` rule. HTTP `200`. |
| `explicit-deny` | A request matches both an `allow` rule and a more specific `deny` rule for one protected resource. The explicit deny wins, and matched-rule evidence names both rules — distinguishing this from a default deny. HTTP `403`. |
| `default-deny` | A request is within the policy bundle's governed scope but matches no rule at all. This is the kernel's default-deny result, not a fabricated deny rule — matched-rule evidence is empty. HTTP `403`. |
| `not-applicable` | A request falls entirely outside the bundle's governed scope. The kernel outcome is `not_applicable`, never rewritten to `deny` — only the gateway's separately-derived HTTP status (`403`) collapses the two. |
| `untrusted-producer` | An authenticated caller not in the configured operation-producer allowlist submits one producer-only field (`operation_intent`). Rejected `400` before the kernel is ever invoked — no `AuditEvidence`, no `GatewayAuditEvent`, only a gateway system audit event. |
| `semantic-startup-failure` | A second, separate application instance is started against a structurally valid but semantically invalid bundle (two rules sharing the same `rule_id`). The process stays alive (`/health` 200), never becomes ready (`/ready` 503), and the operation-aware route stays registered — returning a governed `503`, never `404`. |

---

## Architecture

```text
signed local identity token
    |
    v
basis-gateway   (AUTH_MODE=basis_local_token; runtime authentication,
                 operation-producer trust classification, request
                 validation and composition, field-level provenance)
    |
    v
basis-core      (public OperationAwareEnforcementPoint — the sole
                 authority on allow / deny / not_applicable)
    |
    v
HTTP enforcement + audit evidence
    (exact evaluation_status/outcome/failure_reason -> HTTP classification;
     GatewayAuditEvent + AuditEvidence; readiness diagnostics)
```

Every primary scenario traverses the real path:

```text
HTTP request -> middleware -> auth -> route -> composition -> evaluator
-> basis-core -> classification -> audit
```

`demo/operation-aware/run_demo.py` calls `basis_gateway.main.create_app()`
directly and drives it with `fastapi.testclient.TestClient` (already part
of this repository's development dependencies) — the real ASGI lifespan
runs, the real middleware runs, the real route handler runs. Route
functions are never called directly, authentication is never bypassed, and
`basis-core` is never called directly for the demo's primary output.

### Authentication

The demo uses `AUTH_MODE=basis_local_token` — the same runtime
authentication path this repository's own test suite exercises for that
mode (see `tests/test_auth_mode_evaluate.py`). It:

1. Generates an ephemeral RSA key pair in process memory (never written to
   disk).
2. Configures the gateway's real BASIS-local token trust via the real
   environment variables (`BASIS_LOCAL_TOKEN_ISSUER`,
   `BASIS_LOCAL_TOKEN_AUDIENCE`, `BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON`).
3. Issues a properly signed demonstration JWT for a synthetic subject
   (`operator-demo-1`).
4. Submits it through the real `Authorization: Bearer ...` header.
5. Lets the real gateway authentication dispatch
   (`basis_gateway.auth.runtime.authenticate`) verify it.

Subject identity is derived from the verified token only — never from the
request body.

Synthetic values used throughout (all `.invalid` per RFC 2606 — guaranteed
never to resolve):

```text
issuer:                   https://identity.demo.basis.invalid
audience:                 basis-gateway-demo
trusted producer subject: adapter-demo-1
ordinary user subject:    operator-demo-1
```

`OPERATION_PRODUCER_SUBJECT_IDS=adapter-demo-1` is configured so the
demonstration can show a caller who is *not* a trusted producer
(`operator-demo-1`) being rejected when it asserts producer-only context
— see the `untrusted-producer` scenario.

### Policy bundle

`demo/operation-aware/policy-bundles/operation-aware-demo-bundle.json` is a
small, valid `PolicyBundle` (the real public schema the merged gateway
accepts) with three rules:

- `allow-read-ahu` — any authenticated caller may read an AHU.
- `allow-write-ahu` — a caller holding the `operator` role may write an AHU
  setpoint.
- `deny-write-protected-ahu` — writes to one specific protected AHU
  (`ahu:protected-1`) are explicitly denied, regardless of role.

Its `scope.actions` governs `read:ahu`, `write:ahu`, and `execute:ahu` —
`execute:ahu` is in scope but matches no rule (default deny), and anything
outside those three actions (e.g. `read:lighting`) is outside scope
entirely (`not_applicable`). No new condition operators, action grammar,
policy fields, or gateway-specific policy semantics are introduced — only
semantics already implemented and tested by this repository.

`demo/operation-aware/policy-bundles/operation-aware-invalid-bundle.json`
is structurally valid (`PolicyBundle` accepts it) but semantically invalid
— two rules share the same `rule_id`. It is never loaded into a serving
application in this demonstration; it is used only to start a second,
isolated application instance for the `semantic-startup-failure` scenario.

### Audit capture

The demo uses the real `GatewayAuditWriter` boundary. After the real
lifespan startup completes, a narrow, demonstration-only capturing sink is
injected underneath the writer's innermost delegate — the exact pattern
this repository's own tests already use (see
`tests/test_operation_aware_endpoint_audit.py`'s `_CapturingWriter`). The
`GatewayAuditWriter` itself (failure counting, readiness
degradation/recovery) is untouched; only its log destination is swapped so
the demo can print the real audit record instead of only writing it to the
process log. Gateway audit assembly and the HTTP classifier are never
patched.

The sink is attached via `GatewayAuditWriter._inner`, an internal
attribute, not a public API. It is an implementation detail used only by
this bounded demo and by the repository's own test harness, mirroring an
existing test pattern rather than introducing a new one. `_inner` is not a
supported production plugin interface, extension point, or configuration
option — there is no supported way to swap `GatewayAuditWriter`'s
destination outside of tests and this demo, and this PR does not add one.

---

## Evidence model

Every completed operation-aware evaluation produces one outer, durable
`AuditEvent` containing two sibling artifacts — never one nested inside the
other:

```text
outer AuditEvent
    |-- gateway_audit_event   (small, contract-shaped: evaluation_status,
    |                          outcome, failure_reason, enforcement_action,
    |                          audit_evidence_id)
    `-- audit_evidence        (the complete, unmodified kernel-produced
                                AuditEvidence: matched_rule_ids, bundle
                                identity, trace reference, ...)
```

with the linkage invariant:

```text
gateway_audit_event.audit_evidence_id  ==  audit_evidence.evidence_id
```

The demo's `allow`/`explicit-deny`/`default-deny`/`not-applicable`
scenarios each check this equality explicitly. See
[`docs/audit-model.md`](../../docs/audit-model.md) §10 for the full model.

---

## Safety

- No external network call is ever made — the `.invalid` issuer/audience
  values exist only as claims inside locally-signed, locally-verified
  tokens.
- No live identity provider — `AUTH_MODE=basis_local_token` requires none.
- No device command, no southbound adapter, no physical-state change of any
  kind — nothing in this repository or this demo can reach a device.
- No secrets are retained: the RSA key pair exists only in this process's
  memory for the duration of the run and is discarded on exit. No private
  key, public key body, token, or bearer header is ever printed.
- No temporary files persist beyond the run except a short-lived directory
  under the OS temp path holding the unrelated, unused v0.1 role-table
  policy file `AUTH_MODE=basis_local_token` requires at startup (see
  `_write_v01_policy` in `run_demo.py`) — removed when the script exits.

---

## Limitations

This demonstration does not prove:

- physical execution of any operation;
- device-state confirmation;
- production availability or hosted-service behavior;
- durable audit retention (the real `GatewayAuditWriter`/`LogAuditWriter`
  pipeline is exercised, but this demo's own capturing sink is in-memory
  and discarded on exit);
- multi-tenancy;
- console UI integration;
- protocol adapter integration.

---

## Console relationship

This demonstration provides the scenarios and evidence model that a future
`basis-console` Training mode can visualize:

- Training mode should explain the same real gateway path this
  demonstration exercises — the same authentication, producer trust,
  composition, kernel outcome, gateway disposition, evidence, and
  readiness facts.
- Training mode must not bypass authentication or authorization.
- Operator mode should consume the same governed outcomes this
  demonstration produces, never reinterpreting `allow`/`deny`/
  `not_applicable`.

Neither console mode is implemented by this repository or this
demonstration.
