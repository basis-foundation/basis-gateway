"""Unit tests for the gateway action-composition helper.

These test the pure helpers in ``basis_gateway.core.actions`` — no HTTP, no
auth, no kernel.
"""

from __future__ import annotations

import pytest

from basis_gateway.core.actions import (
    EVIDENCE_ACTION_COMPOSED,
    EVIDENCE_COMPOSED_ACTION,
    EVIDENCE_ORIGINAL_ACTION,
    EVIDENCE_RESOURCE_TYPE,
    RESERVED_CONTEXT_PREFIX,
    ActionCompositionError,
    build_composition_evidence,
    compose_action,
    is_composite_action,
    reserved_key_collisions,
)

# ---------------------------------------------------------------------------
# compose_action — pass-through (already composite)
# ---------------------------------------------------------------------------


def test_composite_action_passes_through_unchanged():
    assert compose_action("read:ahu", None) == "read:ahu"


def test_three_segment_composite_passes_through_unchanged():
    assert compose_action("write:hvac:setpoint", None) == "write:hvac:setpoint"


def test_composite_action_with_resource_type_is_rejected():
    with pytest.raises(ActionCompositionError):
        compose_action("read:ahu", "ahu")


def test_composite_action_with_empty_resource_type_is_rejected():
    # An empty string still counts as "supplied" → ambiguous.
    with pytest.raises(ActionCompositionError):
        compose_action("read:ahu", "")


# ---------------------------------------------------------------------------
# compose_action — composition (bare verb + resource_type)
# ---------------------------------------------------------------------------


def test_bare_action_with_resource_type_composes():
    assert compose_action("read", "ahu") == "read:ahu"


def test_bare_action_allows_hyphen_and_underscore_segments():
    assert compose_action("read", "ahu-1_zone") == "read:ahu-1_zone"


def test_bare_action_without_resource_type_fails():
    with pytest.raises(ActionCompositionError):
        compose_action("read", None)


def test_bare_action_with_empty_resource_type_fails():
    with pytest.raises(ActionCompositionError):
        compose_action("read", "")


# ---------------------------------------------------------------------------
# compose_action — invalid segments
# ---------------------------------------------------------------------------


def test_empty_action_fails():
    with pytest.raises(ActionCompositionError):
        compose_action("", "ahu")


def test_whitespace_action_fails():
    with pytest.raises(ActionCompositionError):
        compose_action("   ", "ahu")


@pytest.mark.parametrize("bad_verb", ["Read", "read!", "1read", "re ad", "-read"])
def test_invalid_action_segment_fails(bad_verb: str):
    with pytest.raises(ActionCompositionError):
        compose_action(bad_verb, "ahu")


@pytest.mark.parametrize("bad_rt", ["AHU", "ahu!", "1ahu", "a hu", "-ahu", "ahu:zone"])
def test_invalid_resource_type_segment_fails(bad_rt: str):
    with pytest.raises(ActionCompositionError):
        compose_action("read", bad_rt)


# ---------------------------------------------------------------------------
# is_composite_action
# ---------------------------------------------------------------------------


def test_is_composite_action():
    assert is_composite_action("read:ahu")
    assert not is_composite_action("read")


# ---------------------------------------------------------------------------
# reserved_key_collisions
# ---------------------------------------------------------------------------


def test_no_collision_for_ordinary_context():
    assert reserved_key_collisions({"site": "bldg-a", "shift": "night"}) == []


def test_collision_detected_for_reserved_namespace():
    ctx = {"site": "bldg-a", f"{RESERVED_CONTEXT_PREFIX}original_action": "read"}
    assert reserved_key_collisions(ctx) == [f"{RESERVED_CONTEXT_PREFIX}original_action"]


def test_collisions_sorted():
    ctx = {
        EVIDENCE_RESOURCE_TYPE: "ahu",
        EVIDENCE_ACTION_COMPOSED: "true",
    }
    assert reserved_key_collisions(ctx) == sorted(
        [EVIDENCE_RESOURCE_TYPE, EVIDENCE_ACTION_COMPOSED]
    )


# ---------------------------------------------------------------------------
# build_composition_evidence
# ---------------------------------------------------------------------------


def test_build_composition_evidence_shape():
    evidence = build_composition_evidence(
        original_action="read", resource_type="ahu", composed_action="read:ahu"
    )
    assert evidence == {
        EVIDENCE_ACTION_COMPOSED: "true",
        EVIDENCE_ORIGINAL_ACTION: "read",
        EVIDENCE_RESOURCE_TYPE: "ahu",
        EVIDENCE_COMPOSED_ACTION: "read:ahu",
    }
    # All values are strings (the evaluation context is dict[str, str]).
    assert all(isinstance(v, str) for v in evidence.values())
