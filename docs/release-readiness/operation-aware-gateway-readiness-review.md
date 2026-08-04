# Operation-Aware Gateway Readiness Review

**Reviewed at**: PR 10 (documentation and release hardening), branch
`docs/operation-aware-release-hardening`, starting commit `70bd322` (merged PR 9).
**Scope**: the feature-gated `POST /v1/evaluate/operation-aware` path implemented across PRs 1–9.
**This review is evidence-based** — every claim below is backed by a specific test, source
file, or command run against this repository during this review.

> **Current status**: `v0.2.0` has since been tagged and published (see
> [`docs/releases/v0.2.0.md`](../releases/v0.2.0.md)). §12 below and its "Release recommendation"
> describe this repository's state at the point the release-preparation PR was reviewed, before
> the tag and GitHub Release existed; that language is retained as a historical record of the
> review rather than rewritten to describe the now-published release.

---

## 1. Scope reviewed

Endpoint, configuration, authentication boundary, producer trust, composition, kernel
integration, HTTP classification, audit, readiness, conformance, compatibility, documentation,
packaging metadata, and CI.

---

## 2. Implementation state

The following is **implemented and merged to `main`** as of this review. Nothing in this section
is a roadmap item.

- Feature-gated route `POST /v1/evaluate/operation-aware`, registered only when
  `OPERATION_AWARE_ENABLED=true` (`src/basis_gateway/api/routes.py`, `main.py`).
- Normalized request model `OperationAwareEvaluateRequest` (`api/operation_aware_schemas.py`),
  shape-validated, `extra="forbid"`, empty-only `context`.
- Operation-producer trust classification (`auth/operation_producer.py`) — exact, case-sensitive
  subject-ID allowlist (`OPERATION_PRODUCER_SUBJECT_IDS`), empty by default (safe default: no
  caller is ever a producer without explicit configuration).
- Provenance-gated composition (`core/operation_aware_composition.py`) reusing the existing
  action/resource composition boundary (`core/actions.py`, `core/resources.py`) unchanged.
- Public `basis-core` kernel integration only
  (`core/operation_aware_evaluator.py`, `OperationAwareEnforcementPoint.for_bundle()`) — no
  import of `basis_core.evaluation.*` or any other internal symbol (verified in
  §5 Security boundaries and §7 below).
- Startup semantic preflight (`preflight_operation_aware_evaluator`) against a synthetic,
  reserved request through the same real public enforcement path.
- Exact HTTP status classification (`api/operation_aware_classification.py`) — a single,
  exhaustively-tested function, no permissive default.
- Gateway and kernel audit evidence (`audit/operation_aware_gateway_events.py`) — sibling
  `gateway_audit_event`/`audit_evidence` artifacts in one durable record, linked by
  `audit_evidence_id`.
- Shared `GatewayAuditWriter` and its existing failure-escalation/fail-closed behavior, reused
  unchanged across both evaluation endpoints.
- Four operation-aware readiness components (`readiness.py` usage in `main.py`'s lifespan).
- Canonical conformance (`tests/test_operation_aware_endpoint_canonical_scenarios.py`) and a
  broader adversarial/mutation-based conformance suite
  (`tests/test_operation_aware_gateway_conformance.py`,
  `tests/test_operation_aware_gateway_conformance_mutations.py`).
- Public-import boundary enforcement
  (`tests/test_operation_aware_public_api_contract.py`, and route-level import assertions in
  `tests/test_operation_aware_endpoint.py`).

**Implemented since this review's original PR 10 scope, folded in below:**

- PR 11's bounded, reproducible, offline end-to-end demonstration (`demo/operation-aware/`) —
  see §11.

**Not implemented — explicitly out of scope for this review, tracked separately:**

- Any capability listed in this repository's [README — Current limitations](../../README.md#current-limitations)
  (policy hot reload, durable audit storage, audit query API, cryptographic audit signing,
  tamper-evident audit chain, adapter execution confirmation, device-state verification,
  background policy revalidation, built-in multi-tenancy, hosted-service control plane).

---

## 3. Compatibility

| Claim | Evidence |
|---|---|
| `/v1/evaluate` retained, unchanged | `tests/test_evaluate.py`, `test_action_composition.py`, `test_resource_composition.py` all pass unmodified; `routes.py`'s `evaluate()` handler is untouched by the operation-aware addition (separate `operation_aware_router` `APIRouter` instance). |
| Operation-aware feature disabled by default | `GatewayConfig.operation_aware_enabled: bool = Field(default=False, ...)` (`config.py`); `tests/test_operation_aware_readiness.py::test_disabled_mode_registers_none_of_the_four_components` and `::test_disabled_mode_route_absent` (404). |
| Both paths coexist | `tests/test_operation_aware_readiness.py::test_both_modes_enabled_all_components_present_one_shared_writer` — both `/v1/evaluate` and `/v1/evaluate/operation-aware` ready simultaneously, one shared audit writer. |
| Public `basis-core` imports only | `core/operation_aware_evaluator.py` module docstring ("Import boundary (§8)"); `tests/test_operation_aware_public_api_contract.py`; `tests/test_operation_aware_endpoint.py::test_routes_module_does_not_import_kernel_internals` and `::test_enforcement_point_constructed_only_via_for_bundle_in_evaluator_module`. |
| Dependency floor and upper bound | `pyproject.toml`: `basis-core>=0.2.1,<0.3.0`. Confirmed installed version in this review's environment: `basis-core==0.2.1` (satisfies the floor; the operation-aware public factory `OperationAwareEnforcementPoint.for_bundle()` was introduced at `0.2.1`, per `core/operation_aware_evaluator.py`'s own docstring). |
| No `basis-schemas` runtime dependency | `pyproject.toml` dependencies: `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `PyJWT[crypto]`, `httpx`, `basis-core` — no `basis-schemas` entry. |

---

## 4. Security boundaries

| Boundary | Status | Evidence |
|---|---|---|
| Authentication | Reused unchanged from `/v1/evaluate`; same auth-mode dispatch, no fallback between modes. | `auth/runtime.py` unchanged; `tests/test_operation_aware_endpoint.py` authentication-failure tests. |
| Explicit producer trust | Configuration-driven, exact-match, case-sensitive; empty allowlist by default. | `auth/operation_producer.py`; `tests/test_operation_producer_trust.py`; `test_operation_aware_endpoint.py::test_untrusted_producer_by_default_with_no_configuration`. |
| Fail-closed enforcement | Every non-`ALLOW` kernel result blocks; no permissive default in HTTP classification. | `api/operation_aware_classification.py` (`_UNRECOGNIZED_STATE_HTTP_STATUS = 500`, no fallthrough to 200/403). |
| Audit degradation | Shared writer; strict mode (`AUDIT_FAIL_CLOSED`) and default mode identical to v0.1, applied to both endpoints. | `tests/test_audit_escalation_integration.py`, `test_operation_aware_endpoint_audit.py`. |
| Sensitive-data handling | No tokens/claims/secrets/policy bodies/stack traces in audit or readiness output. | `tests/test_operation_aware_readiness.py::_assert_operation_aware_reasons_are_safe`; `docs/audit-model.md` §10.6. |
| Startup failure containment | A later-stage failure (auth, v0.1 policy) leaves operation-aware components honestly pending, never fabricated as a bundle/semantic failure. | `tests/test_operation_aware_readiness.py::test_earlier_authentication_failure_leaves_honest_pending_diagnostics`, `::test_v01_policy_failure_before_operation_aware_processing`. |
| Route registration behavior | Enabled-but-broken leaves the route registered (503), never silently 404. | `tests/test_operation_aware_readiness.py::test_missing_bundle_path_stage_attribution` (route registered, `/ready` 503). |
| Readiness truthfulness | Four independent components; semantic preflight is a distinct, required stage. | `tests/test_operation_aware_readiness.py::test_semantic_preflight_failure_duplicate_rule_ids`, `::test_semantic_preflight_failure_unsupported_operator`. |

---

## 5. Test evidence

Commands run against this repository during this review
(`PYTHONPATH=src:<basis-core>/src <venv>/bin/python -m pytest ...`):

| Suite | Result |
|---|---|
| Full suite (`pytest -q`) | **1087 passed** (baseline confirmed against merged PR 9 before any change in this PR) |
| Operation-aware tests (`tests/test_operation_aware_*.py`) | **549 passed** |
| Conformance suite (`test_operation_aware_gateway_conformance.py`) | **83 passed** |
| Mutation-based conformance (`test_operation_aware_gateway_conformance_mutations.py`) | **24 passed** |
| Lint (`ruff check src tests`) | All checks passed |
| Formatting (`ruff format --check src tests`) | 80 files already formatted |
| Type checking (`mypy --cache-dir=/dev/null src`) | Success: no issues found in 32 source files |
| Import-boundary tests | Included in operation-aware test count above (`test_operation_aware_public_api_contract.py`, route-level assertions in `test_operation_aware_endpoint.py`) |
| Documentation tests (`tests/test_operation_aware_documentation.py`, added in this PR) | See final validation run in the PR 10 completion report |

This PR adds documentation and documentation-validation tests only; it does not add, remove, or
modify any production-code test, and the full-suite count above reflects PRs 1–9's own work, not
this PR's.

---

## 6. Packaging and dependency state

Inspected: `pyproject.toml`.

- **Version**: `0.1.0` (`[project].version`) — unchanged. Per this PR's scope rules, version
  metadata is not authorized to change here even though the shipped feature set has grown since
  `0.1.0`'s release notes (`docs/releases/v0.1.0.md`); see Finding F1 below.
- **Dependency bounds**: `basis-core>=0.2.1,<0.3.0` — floor matches the version that introduced
  the public `OperationAwareEnforcementPoint.for_bundle()` factory this integration depends on;
  upper bound excludes the next breaking increment. Consistent with the integration plan's own
  dependency-pinning recommendation (§8).
- **Python version support**: `requires-python = ">=3.10"`; CI matrix tests 3.10/3.11/3.12
  (`.github/workflows/ci.yml`).
- **Entry points**: none declared. Not applicable — this is a library/service package, not a CLI
  tool.
- **Included files**: `[tool.hatch.build.targets.wheel] packages = ["src/basis_gateway"]` — no
  change needed or made.
- **License metadata**: a `LICENSE` file (Apache 2.0) exists at the repository root, but
  `pyproject.toml`'s `[project]` table declares no `license` field, `classifiers` entry, or
  `authors`/`urls` metadata. This predates PR 10 and is not caused by, or a blocker for, the
  operation-aware rollout — see Finding F2 below. Not corrected in this PR (packaging changes are
  out of scope unless a concrete inconsistency requires a narrowly justified correction, and this
  is a pre-existing gap, not a rollout-introduced inconsistency).

No packaging changes were made in this PR.

---

## 7. Documentation completeness

| Area | Document |
|---|---|
| Setup | [`README.md`](../../README.md) (Local setup, unchanged) |
| Configuration | [`docs/configuration.md`](../configuration.md) (new) |
| Endpoint | [`docs/operation-aware-endpoint.md`](../operation-aware-endpoint.md) (new) |
| Audit | [`docs/audit-model.md`](../audit-model.md) §10 (new section), [`docs/audit-failure-escalation.md`](../audit-failure-escalation.md) (updated) |
| Readiness | [`docs/readiness.md`](../readiness.md) (new) |
| Limitations | [`README.md` — Current limitations](../../README.md#current-limitations) (new section) |
| Troubleshooting / operator failure interpretation | [`docs/readiness.md`](../readiness.md) (failure matrix + troubleshooting table), cross-linked from [`docs/troubleshooting.md`](../troubleshooting.md) |
| Compatibility | [`README.md` — Endpoints](../../README.md#endpoints), [`CHANGELOG.md`](../../CHANGELOG.md) Compatibility subsection |
| Architecture / design rationale | [`docs/implementation/operation-aware-gateway-integration-plan.md`](../implementation/operation-aware-gateway-integration-plan.md) (status updated) |

---

## 8. Known limitations

Restated from [README — Current limitations](../../README.md#current-limitations), not buried:

no policy hot reload; no remote policy distribution; no durable database-backed audit store; no
audit query API; no cryptographic audit signing; no tamper-evident audit chain; no adapter
execution confirmation; no device-state verification; no background policy revalidation; no
built-in multi-tenancy; no hosted-service control plane; no PR 11 demonstration yet.

Additionally, from this review specifically:

- `invalid_request`, `unsupported_schema_version`, and `internal_evaluation_error` are governed,
  documented failure reasons not reachable through the real gateway-to-kernel path with a
  structurally valid bundle in this repository's own test suite (only reachable by injecting a
  stub engine through a non-public constructor path, which this repository correctly does not
  do). Their HTTP classification is still exhaustively covered at the pure-function level.
- Operation-aware UI support for `basis-console` is intentionally outside this repository. The
  gateway now exposes the governed decision, disposition, provenance, evidence, and readiness
  information that Training and Operator modes will consume in a future `basis-console` phase.
  This is **future ecosystem work, not a PR 10 blocker** — see §9 below. Training mode must
  remain explanatory or simulation-oriented and must not bypass the gateway or kernel. Operator
  mode must consume the same gateway contract and must not reinterpret `allow`, `deny`,
  `not_applicable`, failed evaluation, or enforcement disposition.
- Packaging metadata gaps predating this PR (Finding F2).

---

## 9. Release blockers

| Item | Classification |
|---|---|
| PR 11 bounded demonstration | **resolved** — implemented in `demo/operation-aware/`; see §11 |
| `pyproject.toml` version left at `0.1.0` despite the operation-aware feature set | **non-blocking** — see Finding F1; a version bump is a separate, authorized release-preparation action, not a PR 10 documentation task |
| Missing `license`/`classifiers`/`authors` metadata in `pyproject.toml` | **non-blocking** — pre-existing gap, not introduced by or specific to this rollout |
| Three governed failure reasons not reachable through the real kernel path in this test suite | **non-blocking** — a structural property of the current bundle/request surface, not a test gap; already covered at the pure-function classification level |
| Operation-aware `basis-console` UI integration (Training mode, Operator mode) | **future** — ecosystem work scoped to the `basis-console` repository, not this repository; not required for PR 10 or PR 11 |

No **blocking** items were found for PR 10's own scope (documentation and release hardening), and
none were found for PR 11's demonstration work either (see §11).

---

## 10. Recommendation

**Operation-aware gateway rollout complete and ready for a separate versioning/release-preparation
decision.**

PRs 1–11 are implemented, tested, and documented. Lint, formatting, and type checking are clean.
Compatibility with the existing `/v1/evaluate` path is verified. The bounded, offline
demonstration (PR 11) reproduces all six governed scenarios against the real gateway-to-kernel
path with a deterministic, non-zero-on-mismatch exit contract. No release-blocking issues were
found. The two non-blocking packaging findings (F1, F2) remain tracked as separate follow-up work
— see §6 and the Findings below.

---

## 11. PR 11 — Bounded demonstration validation

**Reviewed at**: PR 11 (`demo/operation-aware/`), branch `demo/operation-aware-gateway`, starting
commit `f6d48c8` (merged PR 10).

- **Scope**: `demo/operation-aware/run_demo.py`, `demo/operation-aware/policy-bundles/*.json`,
  `demo/operation-aware/expected/scenario-summary.json`, `demo/operation-aware/README.md`,
  `tests/test_operation_aware_demo.py`.
- **Real-path claim, verified**: every primary scenario is driven through
  `basis_gateway.main.create_app()`'s real ASGI lifespan and the real
  `POST /v1/evaluate/operation-aware` route via `fastapi.testclient.TestClient` — no route
  function is called directly, no middleware or authentication step is bypassed, and
  `basis-core` is never called directly for the demo's primary output.
- **Authentication**: real `AUTH_MODE=basis_local_token` path; an ephemeral, in-memory RSA key
  pair signs demonstration-only BASIS-local identity tokens submitted through the real
  `Authorization: Bearer ...` header and verified by the real
  `basis_gateway.auth.runtime.authenticate` dispatch. No live OIDC provider, no JWKS fetch, no
  network call.
- **Audit capture**: a narrow, demonstration-only capturing sink is injected under the real
  `GatewayAuditWriter`'s innermost delegate after startup — the same pattern this repository's
  own tests already use (`tests/test_operation_aware_endpoint_audit.py`'s `_CapturingWriter`).
  `GatewayAuditWriter`'s own failure-tracking/readiness behavior is untouched; gateway audit
  assembly and HTTP classification are never patched.
- **Scenario coverage**: `allow`, `explicit-deny`, `default-deny`, `not-applicable`,
  `untrusted-producer`, `semantic-startup-failure` — one more than this document's original PR
  11 scope (which named four kernel outcomes plus the producer-trust rejection); the sixth,
  `semantic-startup-failure`, demonstrates the startup semantic preflight failure mode documented
  in §13/`docs/readiness.md` using a structurally valid, semantically invalid bundle (duplicate
  `rule_id`).
- **Determinism and exit contract**: `demo/operation-aware/expected/scenario-summary.json` holds
  only stable semantic fields (HTTP status, evaluation status, outcome, disposition) — never
  dynamic IDs. `run_demo.py` exits `0` only when every scenario matches; a deliberately mutated
  expectation is asserted (both manually during this review and by
  `tests/test_operation_aware_demo.py::test_runner_returns_nonzero_when_expectation_mutated`) to
  produce a non-zero exit with the mismatch printed, never a silently-passing false positive.
- **Hermeticity**: no `requests`/`boto3`/`docker`/`kubernetes`/`subprocess`/`socket`/
  `urllib.request` usage; `httpx` is used only via `TestClient`'s in-process ASGI transport, never
  against an external URL — confirmed by a repository-wide grep during this review's validation
  run and by `tests/test_operation_aware_demo.py::test_no_disallowed_network_or_process_imports_in_source`.
- **Sensitive-data guard**: no committed private key, no committed bearer token, no raw JWT or key
  material in any demo output (text or `--json`) — confirmed by grep and by
  `tests/test_operation_aware_demo.py`'s dedicated tests.
- **Import boundary**: no import of `basis_core.evaluation.*` anywhere in `demo/` — only the same
  public `basis-core`/`basis-gateway` surfaces already approved for production use.
- **Production impact**: none. No file under `src/` was modified by this PR; no defect in
  already-promised behavior was found or needed correcting.
- **Test evidence**: `tests/test_operation_aware_demo.py` — 33 passed. Operation-aware suite
  (`tests/test_operation_aware_*.py`) — 673 passed. Full suite — 1211 passed (baseline 1178 + 33).
  See this PR's completion report for full command output.

---

## Findings

**F1 — Version metadata.** `pyproject.toml`'s `version = "0.1.0"` and
`src/basis_gateway/__init__.py`'s version string were not changed in this PR, per this PR's
explicit scope rule (version changes are a separate release-preparation action requiring
repository-policy authorization this PR does not have). The operation-aware feature set has grown
materially since the `0.1.0` release notes were written. **Recommendation**: a future,
narrowly-scoped release-preparation PR should decide the correct next version number and update
both locations together with `docs/releases/`.

**F2 — Packaging metadata gaps.** `pyproject.toml` declares no `license`, `classifiers`,
`authors`, or `urls` (`Homepage`/`Repository`) metadata, despite a `LICENSE` file (Apache 2.0)
being present at the repository root. This predates the operation-aware rollout and is not
specific to it. **Recommendation**: address in a dedicated packaging-metadata PR, not folded into
documentation work.

**F3 — Resolved in PR 11.** The bounded, reproducible end-to-end demonstration scenario and its
demo policy bundles (beyond the tiny structural examples in PR 10's own documentation) were
explicitly out of scope for PR 10, per that PR's own "Explicit Non-Goals," and are now delivered
in PR 11 (`demo/operation-aware/`) — see §11. Sample deployment tooling (Docker, Kubernetes,
hosted control plane) remains explicitly out of scope for both PRs and is not part of this
repository's roadmap.

---

## 12. Release preparation (v0.2.0)

**Reviewed at**: release-preparation PR, branch `release/v0.2.0-preparation`, starting commit
`791d89d` (merged PR 11, `demo/operation-aware-gateway`).

This section closes Finding F1 and records this repository's final release-preparation state.
Finding F2 (packaging metadata) is explicitly **not** addressed here — see below.

### Selected version and rationale

**`0.2.0`.** Evidence: this document's own Finding F1 explicitly recommended that "a future,
narrowly-scoped release-preparation PR should decide the correct next version number" once the
operation-aware feature set — a substantial, additive authorization surface — was complete. The
`CHANGELOG.md` `[Unreleased]` section this PR promotes documents a new endpoint, a new trust
model, new composition and audit behavior, and new readiness diagnostics, all additive and
backward-compatible: `POST /v1/evaluate` is untouched. Per SemVer, an additive, non-breaking
feature set is a MINOR version increment (`0.1.0` → `0.2.0`), not a PATCH (`0.1.1`, which would
misrepresent this as a bug fix) and not a MAJOR increment (no breaking change occurred). No
repository evidence contradicts `0.2.0`.

### Synchronized version declarations

`pyproject.toml` (`[project].version`) and `src/basis_gateway/__init__.py`
(`__version__`) both updated to `"0.2.0"`. A new guard, `tests/test_version.py`, asserts both
locations parse, agree, are valid SemVer, equal the repository-selected release version, and that
no current-state document (README, `docs/release-readiness.md`) still claims the package is
currently `0.1.0` — while confirming the historical `docs/releases/v0.1.0.md` is untouched.

### Release notes

[`docs/releases/v0.2.0.md`](../releases/v0.2.0.md) — written following the `v0.1.0` release notes'
structure and precedent. States `/v1/evaluate` compatibility, the disabled-by-default operation-
aware flag, the exact configuration variable names, the security model, the demonstration, known
limitations, and upgrade guidance for existing v0.1 users. Makes no production-certification,
device-execution, durable-audit-persistence, hosted-service, `basis-console`-integration,
protocol-adapter-execution, tamper-evident-audit, multi-tenancy, or high-availability claim.

### Changelog

`CHANGELOG.md`'s prior `[Unreleased]` content is now under a dated `## [0.2.0] - 2026-08-03`
section, organized under `Added`/`Changed`/`Security`/`Compatibility`/`Documentation`/`Notes`
headings consistent with this changelog's existing style. An empty `[Unreleased]` heading is
retained above it. The `[0.1.0]` entry is unchanged.

### Build artifacts

Built with `python -m build` (hatchling backend) from a clean `dist/`/`build/`:

- `basis_gateway-0.2.0-py3-none-any.whl`
- `basis_gateway-0.2.0.tar.gz`

Exactly one wheel and one sdist produced. Wheel contents inspected via
`python -m zipfile -l`: only `basis_gateway/` package modules plus
`basis_gateway-0.2.0.dist-info/` (`METADATA`, `WHEEL`, `RECORD`, and `licenses/LICENSE` — the
license file is auto-included by hatchling from the repository root even though `pyproject.toml`
declares no explicit `license` table entry). No `.env`, key, token, `.git`, virtual environment,
test cache, build cache, sibling-repository content, demo-generated credential, or local absolute
path found in the wheel. Sdist contents inspected via `tar -tzf`: repository source, docs, demo,
tests, policies, `LICENSE`, and `pyproject.toml` — no `.venv`, no build cache, no absolute
developer paths.

Wheel `METADATA` verified: `Name: basis-gateway`, `Version: 0.2.0`, `Requires-Python: >=3.10`,
and a `Requires-Dist` list identical to `pyproject.toml`'s dependency list, including
`basis-core<0.3.0,>=0.2.1`. No accidental dependency, no local-filesystem/Git-branch/editable-path
dependency, and no malformed-name collision with the unrelated PyPI package.

Not committed: `dist/` and `build/` remain outside version control (repository policy — this
project does not commit built release artifacts).

### Clean-install tests

**Wheel**, fresh venv outside this repository's checkout: installed the local BASIS `basis-core`
(non-editable, from the sibling checkout) first, then the built wheel with `--no-deps`, then the
runtime dependency set. `import basis_core` and `import basis_gateway` both resolved to that
venv's `site-packages/`, not the repository checkout. `basis_gateway.__version__ == "0.2.0"`.
Smoke tests passed: import, `create_app()`, `GatewayConfig()` load, `GET /health` (200), a request
to the disabled operation-aware route (`404`, confirming the route is not registered when
`OPERATION_AWARE_ENABLED` is unset), and the version check.

**Sdist**, a second fresh venv: same `basis-core` install order, then the sdist (built and
installed via hatchling with `--no-deps`), then the runtime dependency set. `import basis_core`
and `import basis_gateway` both resolved to that venv's `site-packages/`; no repository checkout
path required for the gateway package itself. `create_app()` and `GET /health` (200) verified.

The demo (`demo/operation-aware/run_demo.py`) is **repository-distributed**, not wheel-packaged —
`demo/` is not included in the wheel's file list (by design; the wheel is the production service
package). It was run directly against the repository checkout (§11) rather than against either
clean-installed artifact.

### Dependency verification

For every clean-install environment, `import basis_core; print(basis_core.__file__)` resolved
into that environment's own `site-packages/`, never the unrelated public PyPI package named
`basis-core` (that package is not installed anywhere in this review's environments; installation
was performed exclusively from the local BASIS `basis-core` sibling checkout). Installed
`basis-core==0.2.1` in every environment; installed `basis-gateway==0.2.0` in every environment
this PR built.

### Demonstration result

`python demo/operation-aware/run_demo.py` — all six scenarios (allow, explicit deny, default
deny, `not_applicable`, untrusted producer, semantic startup failure) passed; exit code `0`.

### Test and static-analysis result

Full suite, lint, formatting, and type-checking results are recorded in this PR's completion
report (exact counts depend on the environment `pytest` run at review time; see that report for
authoritative figures. As a baseline reference, PR 11 recorded 1211 passed).

### CI review

`.github/workflows/ci.yml` already covers the Python matrix declared in `pyproject.toml`
(`3.10`, `3.11`, `3.12`) with format, lint, type-check, and test steps, installing the `basis-core`
sibling by checkout. It does not build or inspect packaging artifacts. This PR performed that
verification locally (build, metadata inspection, clean wheel install, clean sdist install) rather
than adding a new CI job — the existing test matrix plus this PR's local release validation is
judged sufficient for this release; no CI workflow change was made.

### Remaining non-blocking findings

| Item | Classification |
|---|---|
| F1 — version metadata | **resolved by this PR** — `pyproject.toml` and `__init__.py` now `0.2.0`, guarded by `tests/test_version.py` |
| F2 — missing `license`/`classifiers`/`authors`/`urls` metadata in `pyproject.toml` | **still non-blocking** — the package builds and installs correctly without them (verified: exactly one wheel, one sdist, both install cleanly); not addressed in this PR per its explicit scope boundary; recommend a dedicated packaging-metadata PR (tracked as a possible **PR 13**) |
| Three governed failure reasons not reachable through the real kernel path in this test suite | **non-blocking**, unchanged from §9 |
| Operation-aware `basis-console` UI integration | **future**, unchanged from §9 |
| Final published-artifact checksums | **post-merge** — this PR's checksums are validation-only (computed against the locally built, not-yet-published artifacts); final checksums must be generated from the exact artifacts attached to the GitHub Release after tagging |

### Release recommendation

**Repository ready for v0.2.0 tag and GitHub release after this PR merges and CI passes.**

Nothing in this PR was committed, pushed, tagged, or published. See this PR's completion report
for the full adversarial review and validation command output.
