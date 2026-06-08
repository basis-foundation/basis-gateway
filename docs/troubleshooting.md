# basis-gateway Troubleshooting

This document covers common operator and developer failure scenarios, how to diagnose them, and what to do next.

---

## How to inspect `/ready`

The `/ready` endpoint is the primary diagnostic surface. Query it to see which components are healthy and why the gateway is not ready:

```bash
curl -s http://localhost:8000/ready | python3 -m json.tool
```

A not-ready response includes:

- `status` — always `"not_ready"` when the gateway is unhealthy
- `service` — service name (`"basis-gateway"`)
- `components` — per-component readiness map (which components have been reached and whether each is ready)
- `reason` — the first failing component's reason
- `reasons` — all failing components and their reasons (useful when multiple components are degraded simultaneously)

Example not-ready response:

```json
{
  "status": "not_ready",
  "service": "basis-gateway",
  "components": {
    "configuration_loaded": true,
    "oidc_configured": false,
    "policy_loaded": false
  },
  "reason": "OIDC discovery request failed for issuer 'https://idp.example.com': ...",
  "reasons": {
    "oidc_configured": "OIDC discovery request failed for issuer 'https://idp.example.com': ...",
    "policy_loaded": "Policy file not found: '/etc/basis/policy.json'. Set POLICY_PATH to the path of your JSON policy file."
  }
}
```

Check the startup logs alongside `/ready` — each component logs a diagnostic milestone at `INFO` level, and failures log at `ERROR` with the component name and actionable context.

---

## Gateway not ready after startup

**Symptom:** `/ready` returns 503 immediately after startup.

**Diagnosis:** Inspect the `components` map in the `/ready` response. The first `false` entry is the failing component. The `reasons` dict shows what went wrong in each.

Check startup logs for `ERROR` lines — each failure includes the component name in brackets, e.g.:

```
ERROR ... Policy loading failed [policy_loaded]: Policy file not found: '/path/to/policy.json' ...
```

The components are initialized in order:

1. `configuration_loaded` — environment variables parsed successfully
2. `oidc_configured` — OIDC discovery succeeded (only when `OIDC_ISSUER` is set)
3. `jwks_available` — initial JWKS fetch succeeded (only when `OIDC_ISSUER` is set)
4. `policy_loaded` — policy file loaded and parsed (only when `POLICY_PATH` is set)
5. `audit_writer` — audit writer initialized (only when `POLICY_PATH` is set)
6. `evaluator_initialized` — evaluator constructed (only when `POLICY_PATH` is set)

---

## Missing or invalid OIDC configuration

**Symptom:** `oidc_configured` is `false` in the `/ready` response; startup log shows `OIDC discovery failed [oidc_configured]`.

**Cause:** `OIDC_ISSUER` is set but the discovery document at `{OIDC_ISSUER}/.well-known/openid-configuration` is unreachable, returns an HTTP error, or does not match the configured issuer.

**What to check:**

- Confirm `OIDC_ISSUER` is set to the correct issuer URL (e.g., `https://idp.example.com/realms/my-realm`).
- Verify the discovery endpoint is reachable from the gateway host:
  ```bash
  curl -s https://idp.example.com/realms/my-realm/.well-known/openid-configuration | python3 -m json.tool
  ```
- Check that the `issuer` field in the discovery document matches `OIDC_ISSUER` exactly (trailing slashes matter).
- If the JWKS endpoint differs from what discovery returns, set `OIDC_JWKS_URI` to override it.

**Symptom:** `jwks_available` is `false`; log shows `JWKS fetch failed [jwks_available]`.

**Cause:** The JWKS endpoint is unreachable after successful discovery.

**What to check:**

- Verify the JWKS URI (logged in startup debug output) is reachable from the gateway host.
- Check firewall rules, DNS resolution, and TLS certificate validity for the JWKS endpoint.
- Set `OIDC_JWKS_URI` to point to a reachable endpoint and skip auto-discovery.

---

## Policy file missing or invalid

**Symptom:** `policy_loaded` is `false`; startup log shows `Policy loading failed [policy_loaded]`.

**What to check:**

- Confirm `POLICY_PATH` is set and points to a file that exists:
  ```bash
  ls -l "$POLICY_PATH"
  ```
- The file must be valid JSON. Validate it:
  ```bash
  python3 -m json.tool "$POLICY_PATH"
  ```
- The file must be a JSON object with a `rules` array containing at least one rule. Each rule must have `rule_name` (string) and `role_table` (object mapping action strings to lists of role strings).
- The gateway does not perform dynamic policy reload. After fixing the file, restart the service.

**Example valid policy file:**

```json
{
  "rules": [
    {
      "rule_name": "rbac",
      "role_table": {
        "read:sensor:telemetry": ["viewer", "operator", "admin"],
        "write:hvac:setpoint": ["operator", "admin"]
      }
    }
  ]
}
```

See `policies/default.json` for a complete example.

---

## Audit writer degraded

**Symptom:** `audit_writer` is `false` in the `/ready` response; `/ready` returns 503. The startup log shows `CRITICAL` level messages about consecutive write failures crossing a threshold.

**Cause:** The `GatewayAuditWriter` has accumulated `AUDIT_FAILURE_THRESHOLD` consecutive write failures (default: 10). This means the audit pipeline (by default, the Python logger) is failing repeatedly.

**What `AUDIT_FAILURE_THRESHOLD` controls:**

`AUDIT_FAILURE_THRESHOLD` is the number of consecutive audit write failures before the `audit_writer` readiness component is marked not-ready. Default is 10. Set it lower (e.g., `AUDIT_FAILURE_THRESHOLD=3`) for faster degradation detection in production, or higher for more tolerance.

**What `AUDIT_FAIL_CLOSED` controls:**

When `AUDIT_FAIL_CLOSED=false` (default), a degraded audit writer degrades readiness (503 on `/ready`) but does not block `/v1/evaluate`. Evaluation continues. This is appropriate for OT environments where authorization availability is a safety requirement.

When `AUDIT_FAIL_CLOSED=true`, a degraded audit writer additionally blocks `/v1/evaluate` with 503. No evaluation proceeds until the audit pipeline recovers. This is appropriate for strict-compliance deployments where an unrecorded authorization decision is a regulatory violation.

**Recovery:**

Recovery is automatic — no restart required. The first successful audit write after degradation resets the consecutive failure counter and marks `audit_writer` ready again. If `AUDIT_FAIL_CLOSED=true`, the gateway attempts a lightweight recovery probe on each incoming request to detect whether the audit pipeline has recovered.

**What to check:**

- Inspect the process logs for `ERROR` lines from `basis_gateway.audit.writer` describing the write failure and its cause.
- If using the default `LogAuditWriter`, check whether the Python logging pipeline itself is failing (e.g., a log handler writing to a file on a full disk).

---

## Strict audit fail-closed returns 503 on `/v1/evaluate`

**Symptom:** `/v1/evaluate` returns 503 with `"Audit pipeline degraded; evaluation suspended (fail-closed mode)"`. `/ready` also returns 503 with `audit_writer` false.

**Cause:** `AUDIT_FAIL_CLOSED=true` is set and the audit writer has crossed the failure threshold. The gateway is refusing to evaluate authorization requests because it cannot record the decision.

**How recovery works:**

The gateway automatically attempts a lightweight recovery probe on each incoming `/v1/evaluate` request. The probe contains no authentication material and makes no authorization decision. If the probe write succeeds, the writer exits the degraded state and the original request proceeds normally. If the probe fails, the request returns 503.

**In practice:**

1. Fix the underlying cause of the audit write failures (check logs for the specific error).
2. Once the audit pipeline is healthy, the next incoming request will trigger a successful probe write, which restores readiness automatically.
3. No restart is required.

---

## `pip install -e ".[dev]"` tries to download `basis-core` from PyPI

**Symptom:** `pip` fetches an unrelated `basis-core` package from PyPI. You may see unexpected compile errors for `numpy`, `pandas`, or `pyarrow`.

**Fix:** Install the local `basis-core` sibling before running `pip install -e ".[dev]"`:

```bash
deactivate
rm -rf .venv

python3.10 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
pip install -e ../basis-core
pip install -e ".[dev]"
```

Verify the correct package is installed:

```bash
python -c "import basis_core; print(basis_core.__file__)"
```

The path must reference `../basis-core/src/basis_core/__init__.py`, not `.venv/site-packages`.

---

## API error response format

Every error response from basis-gateway uses a consistent JSON shape:

```json
{
  "error": "string_code",
  "message": "Human-readable explanation",
  "correlation_id": "uuid4"
}
```

- `error` — stable machine-readable code; see table below.
- `message` — safe to surface to operators; never contains tokens, stack traces, or raw exception text.
- `correlation_id` — matches the `X-Correlation-ID` response header and any gateway audit events emitted for this request.

### Stable error codes

| Code | HTTP | Meaning |
|---|---|---|
| `authentication_required` | 401 | No Bearer token was presented, or the `Authorization` header is malformed. |
| `authentication_failed` | 401 | A token was present but failed verification, or subject identity could not be derived. |
| `validation_failed` | 400 | Request body failed schema validation. |
| `evaluator_unavailable` | 503 | The evaluator is not initialized; the service is not ready to evaluate requests. |
| `evaluation_failed_closed` | 500 | An unexpected error occurred during evaluation; the request was denied (fail-closed). |
| `audit_fail_closed` | 503 | The audit pipeline is degraded and `AUDIT_FAIL_CLOSED=true`; evaluation is suspended. |
| `internal_error` | 500 | Unexpected internal error not otherwise classified. |

Authorization denials (`DENY`, `NOT_APPLICABLE`) return HTTP 403 with the `EvaluateResponse` body (including `outcome`, `reason`, `policy_version`, and `correlation_id`) rather than an `ErrorResponse`.

### Correlating errors with audit events

Use the `correlation_id` from the response body (or `X-Correlation-ID` header) to find the corresponding gateway audit event in your audit log. The audit event captures the failure category (`reason`), subject identity, and policy version even for pre-evaluation failures such as authentication errors.

---

## mypy cache errors

**Symptom:** `mypy src` fails with stale cache errors or unexpected `[attr-defined]` / `[import]` errors that disappear when the cache is cleared.

**Workaround:**

```bash
mypy src --cache-dir=/tmp/mypy-gw-cache
```

This uses a temporary cache directory and avoids conflicts with other projects sharing `~/.mypy_cache`.
