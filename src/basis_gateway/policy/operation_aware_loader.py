"""Operation-aware policy-bundle loader for basis-gateway.

Reads a single JSON document at startup and constructs the public
``basis-core`` ``PolicyBundle`` model (``basis_core.policy.PolicyBundle`` —
the documented public import path confirmed by
``tests/test_operation_aware_public_api_contract.py``). Parallel to, but
structurally unrelated to and never sharing a code path with, the existing
``basis_gateway.policy.loader.load_policy_engine()`` — the v0.1 role-table
format and the operation-aware ``PolicyBundle`` format are two different
shapes loaded by two different loaders, per
``docs/implementation/operation-aware-gateway-integration-plan.md`` §12
("Existing policy loading — ``policy/loader.py`` and ``POLICY_PATH`` are
untouched").

Structural vs. semantic validation
-----------------------------------
This module performs *structural* loading only: reading the file, parsing
JSON, and constructing ``PolicyBundle`` (a plain Pydantic model — field
presence/type/shape validation). It does not implement, call, or duplicate
*semantic* policy-bundle validation (duplicate rule IDs, invalid scope
declarations, unsupported condition operators, etc.) — per §8 of the
integration plan, that validation runs automatically, deterministically,
and unavoidably inside ``OperationAwareEvaluationEngine.evaluate()`` (via
``basis_core.policy.operation_aware.validation.validate_policy_bundle``,
which this module never imports or calls directly) every time the loaded
bundle is evaluated. The startup semantic preflight
(``basis_gateway.core.operation_aware_evaluator.preflight_operation_aware_evaluator``)
is what actually exercises that semantic check, once, at startup, through
the real public kernel entry point — not this module.

Constraints
-----------
- No network access.
- No dynamic reload, no directory scanning, no multi-bundle selection.
- The file is read exactly once per call to
  ``load_operation_aware_policy_bundle``.
- Raises ``OperationAwarePolicyLoadError`` on any structural failure
  (missing file, unreadable path, malformed JSON, wrong top-level shape,
  or a ``PolicyBundle`` construction ``ValidationError``). The failed
  stage is recorded on the exception's ``stage`` attribute
  (``OperationAwarePolicyLoadFailureStage``) so callers can distinguish
  categories without string-matching the message.
- Error messages never include the full policy document or arbitrary raw
  JSON values — only the configured path and a bounded error count/
  description. This mirrors, but does not share code with,
  ``basis_gateway.policy.loader``'s existing error-message discipline.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path

from basis_core.policy import PolicyBundle
from pydantic import ValidationError

log = logging.getLogger(__name__)

__all__ = [
    "OperationAwarePolicyLoadError",
    "OperationAwarePolicyLoadFailureStage",
    "load_operation_aware_policy_bundle",
]


class OperationAwarePolicyLoadFailureStage(str, Enum):
    """Closed vocabulary of structural policy-bundle load failure stages.

    Distinguishes *where* structural loading failed without exposing
    document content. Never used for semantic (kernel-side) validation
    failures — those are reported separately, by
    ``basis_gateway.core.operation_aware_evaluator.OperationAwarePreflightError``.
    """

    FILE_UNREADABLE = "file_unreadable"
    INVALID_JSON = "invalid_json"
    INVALID_STRUCTURE = "invalid_structure"


class OperationAwarePolicyLoadError(Exception):
    """Raised when the operation-aware policy bundle file cannot be
    structurally loaded.

    Callers (``main.py``'s lifespan) should treat this as a fatal startup
    error when operation-aware integration is enabled. ``stage`` identifies
    which structural step failed (see ``OperationAwarePolicyLoadFailureStage``);
    the exception message never includes the raw policy document or any
    arbitrary JSON value it contained.
    """

    def __init__(self, message: str, *, stage: OperationAwarePolicyLoadFailureStage) -> None:
        self.stage = stage
        super().__init__(message)


def load_operation_aware_policy_bundle(path: str | Path) -> PolicyBundle:
    """Load a public ``basis-core`` ``PolicyBundle`` from a JSON file.

    Args:
        path: Filesystem path to the JSON operation-aware policy bundle
            file (``OPERATION_AWARE_POLICY_BUNDLE_PATH``).

    Returns:
        A real, structurally validated ``basis_core.policy.PolicyBundle``
        instance — never a gateway-owned copy, wrapper, or subclass.

    Raises:
        OperationAwarePolicyLoadError: the file is missing, is not a file,
            cannot be read, is not valid JSON, is not a JSON object at the
            top level, or does not match ``PolicyBundle``'s structural
            shape. This function performs no semantic (kernel-side)
            validation of any kind — see this module's docstring.
    """
    display_path = str(path)
    file_path = Path(path)

    if not file_path.exists():
        raise OperationAwarePolicyLoadError(
            f"Operation-aware policy bundle file not found: {display_path!r}. "
            "Set OPERATION_AWARE_POLICY_BUNDLE_PATH to the path of your operation-aware "
            "JSON policy bundle file.",
            stage=OperationAwarePolicyLoadFailureStage.FILE_UNREADABLE,
        )

    if not file_path.is_file():
        raise OperationAwarePolicyLoadError(
            f"Operation-aware policy bundle path is not a file: {display_path!r}",
            stage=OperationAwarePolicyLoadFailureStage.FILE_UNREADABLE,
        )

    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OperationAwarePolicyLoadError(
            f"Could not read operation-aware policy bundle file {display_path!r}: {exc}",
            stage=OperationAwarePolicyLoadFailureStage.FILE_UNREADABLE,
        ) from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise OperationAwarePolicyLoadError(
            f"Operation-aware policy bundle file {display_path!r} is not valid JSON: {exc}",
            stage=OperationAwarePolicyLoadFailureStage.INVALID_JSON,
        ) from exc

    if not isinstance(data, dict):
        raise OperationAwarePolicyLoadError(
            f"Operation-aware policy bundle file {display_path!r} must be a JSON object "
            f"at the top level, got {type(data).__name__}",
            stage=OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE,
        )

    try:
        bundle = PolicyBundle.model_validate(data)
    except ValidationError as exc:
        raise OperationAwarePolicyLoadError(
            f"Operation-aware policy bundle file {display_path!r} does not match the "
            f"required PolicyBundle structure ({exc.error_count()} validation error(s)).",
            stage=OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE,
        ) from exc

    log.info(
        "Operation-aware policy bundle loaded path=%r bundle_id=%r bundle_version=%r rules=%d",
        display_path,
        bundle.bundle_id,
        bundle.bundle_version,
        len(bundle.rules),
    )

    return bundle
