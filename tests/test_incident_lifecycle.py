
import pytest

from detection.incident_response import (
    create_incident,
    transition_incident,
    add_evidence,
    approve_response,
    record_response_action,
)


@pytest.fixture
def incident():
    alert = {
        "alert_id": "simulation-incident-001",
        "source_module": "scc_security_alerts",
        "principal_or_resource": "projects/demo/buckets/public-data",
        "risk_score": 100,
        "severity": "CRITICAL",
        "description": "Cloud storage bucket allows public access",
        "evidence": [
            {
                "event_id": "sim-event-001",
                "finding": "Public bucket access detected",
            }
        ],
    }

    return create_incident(alert)


def test_incident_starts_pending_approval(incident):
    assert incident["status"] == "PENDING_ANALYST_APPROVAL"


def test_incident_contains_evidence(incident):
    assert len(incident["evidence"]["evidence_items"]) == 1


def test_incident_contains_investigation_playbook(incident):
    assert len(incident["playbook"]["investigation_steps"]) > 0


def test_incident_contains_response_playbook(incident):
    assert len(incident["playbook"]["response_steps"]) > 0


def test_incident_timeline_records_creation(incident):
    assert incident["timeline"][0]["event"] == "INCIDENT_CREATED"


def test_incident_can_enter_investigation(incident):
    transition_incident(incident, "INVESTIGATING")

    assert incident["status"] == "INVESTIGATING"


def test_invalid_transition_is_rejected(incident):
    with pytest.raises(ValueError):
        transition_incident(incident, "CONTAINED")


def test_unknown_status_is_rejected(incident):
    with pytest.raises(ValueError):
        transition_incident(incident, "COMPROMISED")


def test_evidence_can_be_added(incident):
    transition_incident(incident, "INVESTIGATING")

    add_evidence(
        incident,
        {
            "event_id": "sim-event-002",
            "finding": "Additional simulated evidence",
        },
    )

    assert len(incident["evidence"]["evidence_items"]) == 2


def test_analyst_approval_is_required(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    with pytest.raises(PermissionError):
        record_response_action(
            incident,
            "Simulate public access restriction",
        )


def test_analyst_can_approve_response(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    approve_response(
        incident,
        approved_by="test-analyst",
        approved=True,
    )

    assert incident["approval"]["status"] == "APPROVED"


def test_rejected_response_cannot_be_executed(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    approve_response(
        incident,
        approved_by="test-analyst",
        approved=False,
    )

    with pytest.raises(PermissionError):
        record_response_action(
            incident,
            "Simulate public access restriction",
        )


def test_response_action_is_simulation_only(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    approve_response(
        incident,
        approved_by="test-analyst",
        approved=True,
    )

    record_response_action(
        incident,
        "Simulate public access restriction",
    )

    action = incident["response_actions"][0]

    assert action["result"] == "SIMULATED"
    assert action["execution_mode"] == "SIMULATION_ONLY"


def test_containment_requires_recorded_action(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    approve_response(
        incident,
        approved_by="test-analyst",
        approved=True,
    )

    with pytest.raises(ValueError):
        transition_incident(incident, "CONTAINED")


def test_incident_can_be_marked_contained(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    approve_response(
        incident,
        approved_by="test-analyst",
        approved=True,
    )

    record_response_action(
        incident,
        "Simulate public access restriction",
    )

    transition_incident(incident, "CONTAINED")

    assert incident["status"] == "CONTAINED"


def test_incident_can_be_resolved_and_closed(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "RESOLVED")
    transition_incident(incident, "CLOSED")

    assert incident["status"] == "CLOSED"
    assert incident["closed_at"] is not None


def test_closed_incident_cannot_be_reopened(incident):
    transition_incident(incident, "CLOSED")

    with pytest.raises(ValueError):
        transition_incident(incident, "INVESTIGATING")


def test_timeline_records_status_changes(incident):
    transition_incident(incident, "INVESTIGATING")

    assert len(incident["timeline"]) == 2
    assert incident["timeline"][1]["event"] == "STATUS_CHANGED"


def test_real_execution_mode_is_rejected(incident):
    transition_incident(incident, "INVESTIGATING")
    transition_incident(incident, "CONTAINMENT_PENDING")

    approve_response(
        incident,
        approved_by="test-analyst",
        approved=True,
    )

    with pytest.raises(ValueError):
        record_response_action(
            incident,
            "Attempt real cloud modification",
            result="EXECUTED",
        )
