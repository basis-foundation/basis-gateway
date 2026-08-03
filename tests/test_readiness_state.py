"""Focused unit tests for the generic ``ReadinessState`` component tracker
(PR 8 follow-up).

``basis_gateway.readiness.ReadinessState`` itself was not behaviorally
changed by PR 8 (only its module docstring gained a description of the four
operation-aware components ``main.py`` now registers) — the existing
mark_ready/mark_not_ready/components/reason/all_reasons API is reused
unchanged by every component, existing or operation-aware. These tests pin
down the generic invariants PR 8's staged operation-aware registration in
``main.py`` (see ``tests/test_operation_aware_readiness.py``) relies on:
deterministic registration, no duplicate-component artifacts from repeated
updates, correct aggregate readiness, consistent reason tracking, and a
clean slate after ``reset_readiness_state()``. No operation-aware-specific
logic exists in ``readiness.py`` itself; these tests use plain, arbitrary
component names to prove that.
"""

from __future__ import annotations

from basis_gateway.readiness import ReadinessState, get_readiness_state, reset_readiness_state


def test_new_state_has_no_components_and_is_not_ready() -> None:
    state = ReadinessState()
    assert state.components == {}
    assert state.is_ready is False


def test_mark_ready_registers_component_as_true() -> None:
    state = ReadinessState()
    state.mark_ready("thing_a")
    assert state.components == {"thing_a": True}
    assert state.is_ready is True


def test_mark_not_ready_registers_component_as_false_with_reason() -> None:
    state = ReadinessState()
    state.mark_not_ready(reason="thing_a is broken", component="thing_a")
    assert state.components == {"thing_a": False}
    assert state.is_ready is False
    assert state.reason == "thing_a is broken"
    assert state.all_reasons == {"thing_a": "thing_a is broken"}


def test_repeated_mark_ready_does_not_create_duplicate_components() -> None:
    """Calling mark_ready on the same component name more than once must
    leave exactly one entry in the components dict — proves registration is
    deterministic and idempotent, not accumulating duplicate keys/entries."""
    state = ReadinessState()
    state.mark_ready("thing_a")
    state.mark_ready("thing_a")
    state.mark_ready("thing_a")
    assert state.components == {"thing_a": True}
    assert len(state.components) == 1


def test_repeated_mark_not_ready_does_not_create_duplicate_components() -> None:
    state = ReadinessState()
    state.mark_not_ready(reason="first failure", component="thing_a")
    state.mark_not_ready(reason="second failure", component="thing_a")
    assert len(state.components) == 1
    assert state.components == {"thing_a": False}
    # The reason is updated in place, not appended/accumulated.
    assert state.reason == "second failure"


def test_is_ready_false_when_any_registered_component_is_false() -> None:
    state = ReadinessState()
    state.mark_ready("thing_a")
    state.mark_ready("thing_b")
    state.mark_not_ready(reason="broken", component="thing_c")
    assert state.is_ready is False


def test_is_ready_true_only_when_all_registered_components_are_true() -> None:
    state = ReadinessState()
    state.mark_ready("thing_a")
    state.mark_ready("thing_b")
    state.mark_ready("thing_c")
    assert state.is_ready is True


def test_unregistered_component_never_registered_does_not_block_readiness() -> None:
    """A component that a caller never calls mark_ready/mark_not_ready for
    (the generic mechanism an entire disabled feature relies on to register
    nothing) is simply absent — it cannot block or contribute to
    is_ready/components/all_reasons."""
    state = ReadinessState()
    state.mark_ready("thing_a")
    assert "thing_never_registered" not in state.components
    assert "thing_never_registered" not in state.all_reasons
    assert state.is_ready is True


def test_mark_ready_after_mark_not_ready_clears_the_reason() -> None:
    state = ReadinessState()
    state.mark_not_ready(reason="broken", component="thing_a")
    assert state.all_reasons == {"thing_a": "broken"}
    state.mark_ready("thing_a")
    assert state.all_reasons == {}
    assert state.reason == ""


def test_reason_reports_first_not_ready_component_in_insertion_order() -> None:
    state = ReadinessState()
    state.mark_ready("thing_a")
    state.mark_not_ready(reason="b is broken", component="thing_b")
    state.mark_not_ready(reason="c is broken", component="thing_c")
    assert state.reason == "b is broken"


def test_all_reasons_covers_every_not_ready_component() -> None:
    state = ReadinessState()
    state.mark_not_ready(reason="b is broken", component="thing_b")
    state.mark_not_ready(reason="c is broken", component="thing_c")
    state.mark_ready("thing_a")
    assert state.all_reasons == {"thing_b": "b is broken", "thing_c": "c is broken"}


def test_components_snapshot_is_a_copy_not_a_live_view() -> None:
    state = ReadinessState()
    state.mark_ready("thing_a")
    snapshot = state.components
    snapshot["thing_a"] = False
    assert state.components == {"thing_a": True}


def test_reset_readiness_state_removes_all_prior_component_state() -> None:
    """The module-level singleton (what main.py and tests actually share)
    is fully cleared by reset_readiness_state() — no residue from a prior
    app/test leaks into the next one."""
    state = get_readiness_state()
    state.mark_ready("leftover_ready")
    state.mark_not_ready(reason="leftover failure", component="leftover_not_ready")
    assert state.components != {}

    reset_readiness_state()

    assert get_readiness_state().components == {}
    assert get_readiness_state().all_reasons == {}
    assert get_readiness_state().is_ready is False


def test_reset_readiness_state_is_idempotent() -> None:
    reset_readiness_state()
    reset_readiness_state()
    assert get_readiness_state().components == {}
