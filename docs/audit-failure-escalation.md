# Audit Failure Escalation

This document is the canonical architectural reference for how `basis-gateway` should
behave when audit evidence can no longer be reliably produced.

It covers failure analysis, escalation model evaluation, the recommended strategy,
and implementation guidance. It does not specify metrics pipelines, alerting systems,
or persistent storage backends — those are deployment concerns addressed elsewhere.

---

## 1. Background and Framing

The current gateway wraps `basis-core`'s `LogAuditWriter` in a `GatewayAuditWriter`
that catches all write exceptions, logs them as `ERROR`, and increments a
`failed_write_count` counter. Authorization decisions are never affected by write
failures. The counter is exposed as a property but has no threshold behavior.

This is a deliberate v0.1 deferral. The open question recorded in `docs/audit-model.md`
§9 is:

> When should persistent audit failure affect operational behavior?

This document resolves that question.

---

## 2. Governing Principles

The following principles from `basis-architecture` and `basis-core` directly constrain
this decision.

**Kernel evaluates. Gateway enforces. Audit records evidence.**
Audit is downstream of the decision. The decision path and the audit path are
intentionally separate. This is not a deficiency — it is the designed model.
The kernel's `failure-modes.md` states this explicitly:
> *"Audit is evidence, not enforcement. The decision has already been made by the
> PolicyEngine before `write()` is called."*

**Fail closed.**
When the system encounters ambiguity or error, the safe default is denial.
This applies to authorization decisions. It also applies to gateway readiness:
a gateway that cannot reliably record evidence is operationally degraded, even if
it is technically capable of evaluating requests.

**Authorization decisions must remain deterministic.**
A decision produced by the policy engine is correct at the moment it is made,
regardless of whether the audit write succeeds. Reversing an `ALLOW` decision
because the log sink is unavailable would introduce a new, non-deterministic failure
mode into the authorization path itself — one where infrastructure failure grants
or denies access based on coincidental timing rather than policy.

**Audit must not become an authorization bypass.**
Any escalation model that links audit failure to authorization behavior creates a new
attack surface: an adversary who can suppress or break the audit pipeline gains
influence over whether requests are served. The escalation model must close that
surface while still providing operational signal.

**Operational resilience first (Architecture Principle 6).**
In OT environments — hospitals, schools, commercial buildings, industrial facilities —
availability is a safety requirement, not just a business preference. A building access
control system or HVAC authorization gateway that stops serving requests because a log
sink is full does not fail safely; it creates a physical safety incident. The escalation
model must account for environments where continued operation under degraded conditions
is the correct behavior.

**Fail-safe and operationally predictable behavior (Architecture Principle 7).**
Every failure mode that affects authorization decisions or readiness must be documented
and tested. Operators and integrators must be able to determine, from documented behavior,
what the gateway will do under specific failure conditions before those conditions occur.

---

## 3. Failure Scenarios

### 3.1 Transient failure — single write

**Examples:** momentary filesystem latency, brief log sink timeout, single serialization
exception from a malformed event.

**Characteristics:** isolated, self-resolving, no pattern of recurrence, failure counter
increments by one.

**Risk:** low. A single missing audit record in a high-volume system is operationally
significant but not an emergency. The decision was correct; evidence for that one request
was not recorded.

**Question:** Should anything happen beyond logging?

The answer for a single transient failure is no — beyond the existing `ERROR` log entry
and counter increment, no operational response is warranted. Requiring operator attention
for every isolated write failure would create noise that obscures real degradation.

---

### 3.2 Sustained degradation — repeated failures over time

**Examples:** audit destination intermittently unavailable, log forwarding agent
crashed, disk nearly full (writes fail unpredictably), permissions recently changed,
sink misconfiguration introduced by a config push.

**Characteristics:** failures recur over seconds or minutes, failure counter continues
growing, individual requests still get authorized correctly, but an increasing fraction
produce no audit record.

**Risk:** high. A sustained gap in the audit record is qualitatively different from a
single missed event. If the gap is not detected and the gateway continues serving
requests, the operator may not know that a large window of authorization decisions
left no evidence. This is the scenario most likely to become a compliance or forensic
failure.

**Question:** Should readiness degrade? Should operators be alerted?

Yes — this is the critical threshold. Once failures are not transient, the gateway's
ability to fulfill its evidence-recording obligation is materially impaired. The
readiness probe is the appropriate signal: it is the standard mechanism by which
deployment infrastructure learns that a component is degraded.

Readiness degradation at a defined threshold is the correct response to sustained
degradation. It does not stop authorization (decisions already made are correct); it
signals to orchestrators and operators that the audit pipeline requires attention.

---

### 3.3 Total audit failure — no evidence can be produced

**Examples:** `LogAuditWriter` permanently broken due to a code defect, log destination
permanently unavailable (mount unmounted, service gone), writer constructor raised at
startup but was not caught, all writes fail for the lifetime of the process.

**Characteristics:** no audit records produced from a given point in time, failure
counter grows monotonically, zero recoverable writes between failures.

**Risk:** critical. The gateway is operating entirely without evidence. In this state,
every authorization decision it produces is undocumented. This is operationally
indistinguishable from an audit path that has been silently suppressed.

**Question:** Should the gateway continue evaluating? Should it become not-ready?
Should it stop serving requests?

The gateway should mark itself not-ready when failure reaches the total-failure
threshold. It should continue responding to `/health` (the process is alive) but
`/ready` should return 503. Orchestrators that use readiness probes will stop routing
new requests to this instance; operators who check readiness will see the degraded
state immediately.

Whether the gateway should stop serving `/v1/evaluate` entirely (returning 503 to
callers) at this point is a configurable choice (see Section 5.4). The default
recommendation is readiness degradation, not request termination, because of the OT
operational resilience requirement.

---

### 3.4 Startup failure — audit path unavailable at initialization

**Examples:** `build_audit_writer()` raises during lifespan, `LogAuditWriter`
constructor raises, configured audit destination unreachable at boot.

**Characteristics:** the audit writer was never successfully constructed; the gateway
cannot record any evidence from the start.

**Risk:** critical. If the gateway starts and begins serving requests without a
functioning audit writer, every decision it produces is unrecorded from the first
request.

**Question:** Should startup fail? Should startup continue degraded?

For the current `LogAuditWriter`-backed implementation, `build_audit_writer()`
constructs a `GatewayAuditWriter` around `LogAuditWriter()`. The `LogAuditWriter`
constructor does not contact any external system — it allocates a logger. It cannot
meaningfully fail. Startup failure at the audit writer level is therefore a code defect,
not an infrastructure condition.

However, as the `AuditWriter` backend evolves toward durable storage, external sinks,
or network-accessible destinations, the startup audit path may become fallible. The
architecture must be prepared for this. The recommended approach:

- If `build_audit_writer()` raises, treat it as a startup failure for the
  `evaluator_initialized` component. The gateway starts (so `/health` responds)
  but `/ready` returns 503.
- The gateway does not serve `/v1/evaluate` until the audit writer is confirmed
  functional.
- This is consistent with how policy load failures and OIDC configuration failures
  are handled today.

---

## 4. Escalation Model Evaluation

### Model A — Best effort forever

**Behavior:** log failures, increment the counter, continue serving requests
regardless of failure count or duration. No readiness change, no threshold behavior.

**Pros:**
- Maximum availability. No risk of denying authorized operators because a log sink
  is having a bad day.
- Simple to implement and reason about.
- Correct for single transient failures (see §3.1).
- Appropriate for deployments that accept audit gaps in exchange for availability.

**Cons:**
- Provides no operational signal for sustained or total audit failure. Operators
  discover the gap after the fact, often during an incident investigation.
- A sustained audit gap is indistinguishable from a normally functioning gateway
  in readiness probe terms. Orchestrators cannot route accordingly.
- Creates an implicit audit bypass: any condition that breaks the audit pipeline
  silently enables unrecorded authorization decisions.
- Does not satisfy the "operationally predictable" principle. Operators cannot
  distinguish "audit is working" from "audit has been silently broken for hours."
- Architecturally inconsistent with how the gateway handles other degraded states
  (policy load failure, OIDC initialization failure) — those mark readiness not-ready.

**Assessment:** Correct for transient failures. Insufficient as the only behavior.
The gateway already implements this for the transient case; it should not be the
only behavior for sustained or total failure.

---

### Model B — Readiness degradation at threshold

**Behavior:** below a failure threshold, continue serving with logged failures (Model A
behavior). Once a threshold is crossed, mark one or more readiness components not-ready,
causing `/ready` to return 503. Authorization continues to be served (`/v1/evaluate`
still responds) but the deployment infrastructure is informed that the instance is
degraded.

**Pros:**
- Provides a clear, machine-readable operational signal for sustained failure.
- Compatible with orchestrator readiness probes (Kubernetes, load balancers, service
  mesh health checks) — degraded instances are removed from rotation without requiring
  a manual operator action.
- Does not terminate access for currently connected callers or in-flight requests.
- Recoverable: when audit writes resume, the component can be marked ready again.
- Consistent with how the gateway handles other degraded states.
- Does not create an authorization bypass: decisions are still made by the kernel;
  the escalation only affects readiness signaling.
- Operationally appropriate for OT environments where continued access is a safety
  requirement but operators need to know the audit pipeline is degraded.

**Cons:**
- Does not stop unrecorded requests if the orchestrator is slow to remove the instance
  or if no orchestrator is present (bare-metal OT deployment). The audit gap continues
  until the instance is removed or recovered.
- Choosing the right threshold requires judgment. Too low → false positives. Too high →
  real degradation goes unreported for too long.
- Adds state tracking to `GatewayAuditWriter` beyond the current counter.

**Assessment:** The right primary model. It provides operational signal, supports
orchestration, does not break authorization, and is consistent with the gateway's
existing degraded-state philosophy.

---

### Model C — Strict fail closed

**Behavior:** once audit failures cross a threshold, the gateway stops evaluating
authorization requests entirely. `/v1/evaluate` returns 503. No decisions are made
and no evidence is required until the audit path is restored.

**Pros:**
- Strongest evidence integrity guarantee. If no decisions are made, no decisions
  go unrecorded.
- Clear audit policy: evidence is produced for every decision, or no decisions are
  made.
- Appropriate for deployments with strict compliance requirements where audit gaps
  are a regulatory violation.

**Cons:**
- In OT environments, this model can cause physical safety incidents. A hospital
  access control system or industrial control gateway that stops authorizing access
  because a log sink is full has failed in a way that is worse than an audit gap.
- Violates Architecture Principle 6 (Operational Resilience First) as applied to
  OT deployments.
- Creates a strong incentive for operators to permanently lower the threshold or
  disable escalation, defeating the purpose.
- Opens an availability-as-attack-surface problem: an adversary who can fill the
  audit destination or trigger persistent write failures can force a denial-of-service
  condition on the authorization gateway.
- In single-instance OT deployments without orchestration, a 503 on `/v1/evaluate`
  means all downstream callers lose authorization service immediately.

**Assessment:** Appropriate as an opt-in mode for strict-compliance deployments.
Not appropriate as the default for an OT-first system. The gateway should support
this mode but not require it.

---

### Model D — Configurable escalation tiers (synthesis)

A model not in the original framing but worth naming explicitly: the gateway implements
Model B as its default, with Model C available as a configuration option for deployments
that require strict evidence integrity guarantees.

This is the approach recommended in this document. See Section 5.

---

## 5. Recommended Strategy

### 5.1 Summary

**Model B — Readiness degradation at threshold — is the recommended default.**

This is justified by:

1. The OT operational context. Hospitals, schools, commercial buildings, and industrial
   facilities depend on authorization infrastructure availability. Stopping authorization
   service because a log sink is degraded is not a safe failure in this context.

2. Consistency with existing gateway degraded-state handling. Policy load failure,
   OIDC initialization failure, and JWKS unavailability all produce readiness degradation
   rather than request termination. Audit failure should follow the same pattern.

3. Machine-readable operational signal. The readiness probe is the correct mechanism for
   communicating degraded state to orchestrators and operators.

4. Audit bypass prevention. Readiness degradation does not allow an attacker to gain
   authorization by suppressing the audit pipeline. The gateway still evaluates and
   enforces decisions; it just signals that evidence recording is impaired.

5. Recoverability. Readiness can be restored when the audit pipeline recovers, without
   a process restart.

Model C (strict fail closed) should be available as a configuration option via
`AUDIT_FAIL_CLOSED=true` or equivalent, for deployments with strict compliance
requirements. The gateway's current design supports adding this without breaking the
default behavior.

---

### 5.2 Threshold definition

**Recommendation: consecutive failure count, not rolling window.**

A rolling time window requires a timer or background loop, which adds concurrency
complexity. A consecutive failure count is simpler, stateless between write calls,
and directly reflects the condition that matters: is the audit path currently broken,
or did it recently fail?

The threshold should be a configurable integer with a safe default. The default must
balance:

- Avoiding false positives from transient failures (too low is noisy)
- Catching sustained degradation promptly (too high delays the signal)

**Recommended default: 10 consecutive failures.**

Rationale: in a functioning system, a burst of 10 consecutive write failures to a
`LogAuditWriter` indicates a real and sustained infrastructure problem, not a transient
blip. A single outlier write failure would need to be followed by 9 more before
readiness degrades. This provides tolerance for brief instability without masking
real failure.

Configurable via environment variable: `AUDIT_FAILURE_THRESHOLD` (integer, default 10).

**Consecutive vs. cumulative:** the threshold tracks consecutive failures, not
lifetime `failed_write_count`. A successful write resets the consecutive counter to
zero. This ensures that a gateway that recovered from a prior degraded period and
is now writing successfully is not held in a degraded readiness state indefinitely
because of historical failures.

---

### 5.3 Readiness behavior

When the consecutive failure threshold is crossed:

- `GatewayAuditWriter` calls `readiness_state.mark_not_ready(reason=..., component="audit_writer")`.
- The `reason` string must be operator-readable and must not contain raw exception text.
  Suggested: `"Audit write failures exceeded threshold ({n} consecutive failures)"`.
- `/ready` returns 503 with `"audit_writer": false` in the `components` map.
- The gateway continues serving `/v1/evaluate` (Model B default).

When audit writes resume successfully after a degraded period:

- `GatewayAuditWriter` calls `readiness_state.mark_ready(component="audit_writer")`.
- Specifically: a successful write while in the degraded state (consecutive count ≥
  threshold) resets the counter and marks the component ready.
- `/ready` returns 200 once all other components are also ready.

The readiness state is thread-safe (the existing `ReadinessState` uses a lock).
`GatewayAuditWriter` must hold a reference to the `ReadinessState` instance
(or a callable that returns it) to call `mark_ready`/`mark_not_ready`.

---

### 5.4 Strict fail-closed mode (optional)

When `AUDIT_FAIL_CLOSED=true` (or equivalent configuration):

- Reaching the threshold additionally causes `/v1/evaluate` to return 503 to callers.
- The evaluator is not destroyed; if the audit path recovers, the gateway resumes
  serving requests without a restart.
- This mode is appropriate for compliance-heavy environments where an unrecorded
  authorization decision is a regulatory violation, and where the cost of temporary
  unavailability is lower than the cost of an audit gap.

This mode should be documented clearly so operators can make an informed choice.
The default must remain Model B.

**Strict-mode recovery mechanism (implementation note)**

A naive implementation of strict fail-closed creates a recovery deadlock: if the
check blocks all requests before any audit write fires, no successful write can ever
occur and the gateway remains degraded indefinitely without a restart.

To prevent this, the fail-closed check emits a lightweight probe event
(`gateway.audit_recovery_probe`) before returning 503. The probe contains only the
correlation ID and request path — no authentication material. If the probe write
succeeds, the writer self-heals and the request continues to normal evaluation. If
it fails, the writer remains degraded and 503 is returned.

This means recovery is automatic: when the audit backend heals, the next incoming
request will probe it, the writer will recover, and evaluation will resume — with no
operator intervention and no process restart required.

---

### 5.5 Logging behavior

On each failed write:

- Log `ERROR` with the exception, the total `failed_write_count`, and the current
  consecutive count. This is already done for `failed_write_count`; the consecutive
  count should be added.

On threshold crossing (readiness degradation):

- Log `CRITICAL` (or `ERROR` at minimum) at the moment the threshold is crossed.
  Message must clearly state the audit pipeline is impaired and readiness is degraded.
  Example: `"Audit write failures reached threshold (%d consecutive); marking audit_writer not-ready"`.

On recovery (first successful write after degraded state):

- Log `INFO` indicating recovery: `"Audit write recovered after %d consecutive failures; marking audit_writer ready"`.

These log entries serve as the basis for operator alerting. The gateway does not emit
metrics or wire external alerting — those are deployment concerns — but the log entries
must be structured consistently so that log-based alerting pipelines can match them.

---

### 5.6 Recovery behavior

Recovery is automatic and requires no operator intervention or process restart.

The recovery path (Model B — readiness degradation only):

1. `GatewayAuditWriter.write()` is called and the write succeeds.
2. If the previous state was degraded (consecutive count ≥ threshold), log recovery.
3. Reset the consecutive failure counter to zero.
4. Call `readiness_state.mark_ready(component="audit_writer")`.
5. `/ready` returns 200 once all other components are also ready.

The recovery path (Model C — `AUDIT_FAIL_CLOSED=true`):

Recovery uses the same `GatewayAuditWriter.write()` success path, but the triggering
mechanism is the fail-closed probe rather than a normal request write:

1. A request arrives at `/v1/evaluate` while the writer is degraded.
2. The fail-closed check emits a `gateway.audit_recovery_probe` event — no request
   content, no auth material.
3. If the probe write succeeds, `GatewayAuditWriter.write()` detects the degraded
   state, logs recovery, resets the counter, and calls `mark_ready("audit_writer")`.
4. The fail-closed check sees `degraded=False` and allows the request to continue
   to normal evaluation.
5. Steps 2–4 happen in the same synchronous request cycle — the caller that triggers
   recovery receives a normal response, not a 503.

This means readiness automatically restores as soon as one successful write occurs.
This is intentional: the condition being tracked is "is the audit path currently broken?"
not "was there ever a failure?" A gateway that recovers should immediately return to
full operational status.

If the audit destination recovers but then fails again, the counter re-accumulates
from zero. Operators who observe repeated readiness oscillation (ready → degraded →
ready → degraded) should interpret this as evidence of an unstable audit backend
requiring investigation.

---

## 6. Security Analysis

### 6.1 Audit suppression as attack vector

An adversary who can intentionally trigger audit write failures in Model B gains the
ability to cause readiness degradation, which may cause the orchestrator to route
traffic away from the affected instance. This is a denial-of-service vector against
the gateway instance, not an authorization bypass — decisions are still DENY by
default if the gateway is removed from rotation.

In Model C (fail closed), an adversary who triggers failures beyond the threshold
can force a complete authorization outage. This is a stronger DoS vector and should
be weighed against the compliance benefits in environments where Model C is considered.

Neither model allows audit failure to produce an ALLOW decision that the kernel would
not have produced. This invariant must not be broken by any future implementation
of this architecture.

### 6.2 Audit gaps vs. audit falsification

An audit gap (a decision that occurred but was not recorded) is operationally serious
but forensically bounded: the gap is identifiable by the absence of expected records in
a time window. An audit falsification (a record that does not correspond to a real
decision) is worse. The escalation model must not, under any conditions, cause audit
records to be written that misrepresent the actual decisions made.

No model described here creates that risk. The audit path writes records after decisions
are made; the escalation model only adds threshold-based readiness signaling to the
existing failure path.

### 6.3 OT environment considerations

In hospital, school, commercial building, and industrial OT deployments:

- A fail-closed authorization gateway during a fire alarm, power event, or safety
  incident can prevent evacuation, emergency response, or physical plant control.
- The default Model B (readiness degradation without stopping authorization) is the
  appropriate conservative default.
- Model C (strict fail closed) should be reserved for deployments where audit gap risk
  has been explicitly assessed and deemed higher than availability risk — for example,
  a financial or government access control deployment where compliance is primary.
- Operators in OT environments should be educated that audit pipeline health is an
  independent operational concern from authorization availability.

---

## 7. Implementation Guidance

This section describes the implementation approach. Code is not provided here — this
is the architectural specification that implementation should follow.

### 7.1 Components affected

**`basis_gateway/audit/writer.py` — `GatewayAuditWriter`**

New fields:
- `_consecutive_failure_count: int` — reset to zero on successful write
- `_failure_threshold: int` — configurable, default 10
- `_degraded: bool` — true when consecutive count ≥ threshold
- `_readiness_state: ReadinessState` — injected at construction; used to call
  `mark_ready` / `mark_not_ready`

Updated `write()` logic:
```
try:
    inner.write(event)
    if _degraded:
        log INFO: "Audit write recovered..."
        _consecutive_failure_count = 0
        _degraded = False
        readiness_state.mark_ready("audit_writer")
    else:
        _consecutive_failure_count = 0  # reset on success even below threshold
except Exception as exc:
    _failed_write_count += 1
    _consecutive_failure_count += 1
    log ERROR: "Audit write failed (consecutive: N, total: M): exc"
    if _consecutive_failure_count >= _failure_threshold and not _degraded:
        log CRITICAL: "Audit write failures reached threshold..."
        _degraded = True
        readiness_state.mark_not_ready("audit_writer", reason="...")
```

**`basis_gateway/main.py` — `lifespan()`**

- Register `"audit_writer"` as a readiness component during startup. This ensures
  that the readiness probe correctly reflects audit writer state even at startup.
- Pass the `ReadinessState` instance into `build_audit_writer()`.
- Startup audit path failure (if `build_audit_writer()` raises) marks
  `"evaluator_initialized"` not-ready, consistent with current pattern.

**`basis_gateway/config.py` — configuration**

New config fields:
- `audit_failure_threshold: int` (default 10) — consecutive failures before readiness
  degrades. Source: `AUDIT_FAILURE_THRESHOLD` env var.
- `audit_fail_closed: bool` (default False) — if true, gateway stops serving
  `/v1/evaluate` when audit is degraded. Source: `AUDIT_FAIL_CLOSED` env var.

**`basis_gateway/api/routes.py` — `evaluate()` route**

When `audit_fail_closed=True` and audit writer is degraded, return 503 before
processing the request. This check must occur before authentication to prevent
leaking request processing in a state where no evidence can be produced.

### 7.2 State tracking

The state to track is:

| Field | Type | Description |
|---|---|---|
| `failed_write_count` | `int` | Monotonic; never resets. Total lifetime failures. |
| `consecutive_failure_count` | `int` | Resets to zero on successful write. Drives threshold. |
| `degraded` | `bool` | True when consecutive count ≥ threshold. Drives readiness. |
| `failure_threshold` | `int` | Configured at construction. Compared against consecutive count. |

All state lives in `GatewayAuditWriter`. No background timers or threads. State
transitions happen synchronously inside `write()`.

### 7.3 Readiness component name

Register as `"audit_writer"` in `ReadinessState`. This name will appear in the `/ready`
response `components` map, making the degraded state machine-readable:

```json
{
  "status": "not_ready",
  "service": "basis-gateway",
  "components": {
    "configuration_loaded": true,
    "oidc_configured": true,
    "jwks_available": true,
    "policy_loaded": true,
    "evaluator_initialized": true,
    "audit_writer": false
  },
  "reason": "Audit write failures exceeded threshold (10 consecutive failures)"
}
```

### 7.4 Tests required

**Unit tests for `GatewayAuditWriter` (in `tests/test_audit_writer.py` or equivalent):**

- Single failure does not degrade readiness
- Consecutive failures below threshold do not degrade readiness
- Consecutive failures at threshold degrade readiness and mark component not-ready
- A single successful write after degradation resets the counter and marks ready
- `failed_write_count` is monotonic (never decremented)
- `consecutive_failure_count` resets on success but `failed_write_count` does not
- Inner writer exceptions are caught and never propagated
- Recovery log message is emitted when recovering from degraded state
- Threshold crossing log message is emitted when degrading

**Integration tests (in `tests/test_readiness_integration.py` or equivalent):**

- `/ready` returns 503 with `audit_writer: false` when threshold is crossed
- `/ready` returns 200 when audit writer recovers
- `audit_fail_closed=True`: `/v1/evaluate` returns 503 when audit is degraded
- `audit_fail_closed=True`: `/v1/evaluate` resumes after recovery

**Configuration tests:**

- `AUDIT_FAILURE_THRESHOLD` is parsed correctly
- `AUDIT_FAIL_CLOSED` is parsed correctly
- Default values are applied when env vars are absent

### 7.5 Documentation updates required

- `docs/audit-model.md` §6: replace the ambiguity note in the current implementation
  with a reference to this document
- `docs/audit-model.md` §9: close the "Audit failure escalation threshold" open
  question with a pointer to this document
- `basis_gateway/audit/writer.py` module docstring: update to document threshold
  behavior
- `README.md` or equivalent operator reference: document `AUDIT_FAILURE_THRESHOLD`
  and `AUDIT_FAIL_CLOSED` environment variables

---

## 8. Tradeoffs Summary

| Concern | Decision | Rationale |
|---|---|---|
| Default behavior | Readiness degradation (Model B) | OT availability requirement; consistent with existing gateway failure handling |
| Strict compliance option | `AUDIT_FAIL_CLOSED=true` | Available as opt-in; not default for OT context |
| Threshold type | Consecutive failures | Simpler than rolling window; reflects current state not history |
| Default threshold | 10 consecutive failures | Tolerates transients; catches sustained degradation promptly |
| Recovery | Automatic on successful write | No operator action required; readiness immediately reflects restored state |
| Decision path | Unaffected by audit failure | Determinism principle; audit is evidence, not enforcement |
| Startup failure | Marks not-ready; gateway still starts | Consistent with policy and OIDC failure handling |
| Readiness component name | `"audit_writer"` | Machine-readable; consistent with existing component naming |

---

## 9. Unresolved Questions

**9.1 Multi-instance deployments**

In a horizontally scaled deployment where multiple gateway instances share a common
audit sink, a sink failure will cause all instances to degrade simultaneously.
Orchestrators will remove all of them from rotation at the same time, producing a
complete authorization outage. Whether this is acceptable depends on the deployment
topology and the availability requirements of the environment. This document does not
resolve the multi-instance topology question; it recommends that the single-instance
behavior be defined first and multi-instance behavior be addressed when horizontal
scaling is designed.

**9.2 Threshold tuning guidance**

The default of 10 consecutive failures is a judgment call. It may need adjustment
for deployments where writes are slow (high-latency sinks), writes are batched, or
request volume is very high. Operational experience will inform whether the default
needs to change. The threshold being configurable allows per-deployment tuning without
code changes.

**9.3 Audit writer health at startup**

The current `LogAuditWriter` cannot fail during construction. Future backends (durable
storage, network sinks) may fail at construction or during an initial health check. The
startup path should be extended to include an optional `check()` method on `AuditWriter`
implementations that is called during lifespan initialization. This is deferred until
a fallible backend is introduced.

**9.4 Relationship to future metrics**

Once metrics are added to the gateway (out of scope per the non-goals), the
`failed_write_count` and `consecutive_failure_count` fields are natural candidates
for counter and gauge metrics respectively. The field names chosen here should be
treated as the canonical names for those future metrics.

---

## 10. Non-Goals

This document does not specify:

- Metrics, Prometheus, OpenTelemetry, or SIEM integration
- External alerting or dashboard configuration
- Audit persistence backend redesign
- Distributed audit systems or audit aggregation
- Log forwarding pipeline configuration
- Audit immutability mechanisms
- Multi-instance coordination for audit health

---

## Related Documents

- `docs/audit-model.md` — current audit behavior, open questions this document resolves
- `basis-architecture/docs/architecture-principles.md` — governing principles referenced
  in §2
- `basis-core/docs/failure-modes.md` — kernel failure semantics, audit write failure
  rationale
- `basis-core/docs/enforcement-boundary.md` — EnforcementPoint guarantees
- `basis-architecture/docs/architecture/basis-gateway.md` — gateway responsibilities,
  open questions (§3 "Audit sink failure behavior") this document resolves
