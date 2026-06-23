"""Unit tests for the gateway resource-identifier-composition helper.

These test the pure helpers in ``basis_gateway.core.resources`` — no HTTP, no
auth, no kernel.
"""

from __future__ import annotations

import pytest

from basis_gateway.core.actions import EVIDENCE_RESOURCE_TYPE, RESERVED_CONTEXT_PREFIX
from basis_gateway.core.resources import (
    EVIDENCE_COMPOSED_RESOURCE_ID,
    EVIDENCE_ORIGINAL_RESOURCE_ID,
    EVIDENCE_RESOURCE_COMPOSED,
    ResourceCompositionError,
    build_resource_composition_evidence,
    compose_resource_id,
    is_typed_resource_id,
)

# ---------------------------------------------------------------------------
# is_typed_resource_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rid", ["ahu:rooftop-1", "sensor:co2:lobby", "hvac:zone-a:setpoint", "a:b"]
)
def test_typed_resource_ids_detected(rid: str):
    assert is_typed_resource_id(rid)


@pytest.mark.parametrize("rid", ["rooftop-1", "co2-lobby", "zone-a-setpoint", "abc"])
def test_local_resource_ids_detected(rid: str):
    assert not is_typed_resource_id(rid)


# ---------------------------------------------------------------------------
# compose_resource_id — Case A: resource-independent (no resource_id)
# ---------------------------------------------------------------------------


def test_no_resource_id_and_no_resource_type_is_resource_independent():
    result = compose_resource_id(None, None)
    assert result.resource_id is None
    assert result.composed is False


def test_resource_type_without_resource_id_does_not_compose():
    # Domain-level / resource-independent request: resource_type drives action
    # composition only; no resource_id is composed and the request is NOT rejected.
    result = compose_resource_id("ahu", None)
    assert result.resource_id is None
    assert result.composed is False


# ---------------------------------------------------------------------------
# compose_resource_id — Case B: local resource_id + resource_type composes
# ---------------------------------------------------------------------------


def test_local_resource_id_with_resource_type_composes():
    result = compose_resource_id("ahu", "rooftop-1")
    assert result.resource_id == "ahu:rooftop-1"
    assert result.composed is True
    assert result.original_resource_id == "rooftop-1"
    assert result.resource_type == "ahu"


# ---------------------------------------------------------------------------
# compose_resource_id — Case C: typed resource_id, no resource_type passes through
# ---------------------------------------------------------------------------


def test_typed_resource_id_without_resource_type_passes_through():
    result = compose_resource_id(None, "ahu:rooftop-1")
    assert result.resource_id == "ahu:rooftop-1"
    assert result.composed is False


def test_multi_segment_typed_resource_id_passes_through():
    result = compose_resource_id(None, "sensor:co2:lobby")
    assert result.resource_id == "sensor:co2:lobby"
    assert result.composed is False


# ---------------------------------------------------------------------------
# compose_resource_id — Case D: typed resource_id + resource_type is rejected
# ---------------------------------------------------------------------------


def test_typed_resource_id_with_matching_resource_type_is_rejected():
    # Even when the prefix matches, dual sources of truth are rejected.
    with pytest.raises(ResourceCompositionError):
        compose_resource_id("ahu", "ahu:rooftop-1")


def test_typed_resource_id_with_conflicting_resource_type_is_rejected():
    with pytest.raises(ResourceCompositionError):
        compose_resource_id("sensor", "ahu:rooftop-1")


# ---------------------------------------------------------------------------
# compose_resource_id — Case E: local resource_id, no resource_type is rejected
# ---------------------------------------------------------------------------


def test_local_resource_id_without_resource_type_is_rejected():
    with pytest.raises(ResourceCompositionError):
        compose_resource_id(None, "rooftop-1")


# ---------------------------------------------------------------------------
# build_resource_composition_evidence
# ---------------------------------------------------------------------------


def test_build_resource_composition_evidence_shape():
    evidence = build_resource_composition_evidence(
        original_resource_id="rooftop-1",
        resource_type="ahu",
        composed_resource_id="ahu:rooftop-1",
    )
    assert evidence == {
        EVIDENCE_RESOURCE_COMPOSED: "true",
        EVIDENCE_ORIGINAL_RESOURCE_ID: "rooftop-1",
        EVIDENCE_RESOURCE_TYPE: "ahu",
        EVIDENCE_COMPOSED_RESOURCE_ID: "ahu:rooftop-1",
    }
    # All values are strings (the evaluation context is dict[str, str]).
    assert all(isinstance(v, str) for v in evidence.values())


def test_resource_evidence_keys_share_reserved_namespace():
    for key in (
        EVIDENCE_RESOURCE_COMPOSED,
        EVIDENCE_ORIGINAL_RESOURCE_ID,
        EVIDENCE_COMPOSED_RESOURCE_ID,
    ):
        assert key.startswith(RESERVED_CONTEXT_PREFIX)
