
from datetime import datetime, timedelta, timezone

from detection.event_correlation import (
    detect_account_creation_then_key,
    detect_key_creation_then_iam_change,
    detect_repeated_sensitive_activity,
)


BASE_TIME = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)


def make_event(event_id, method_name, minutes, principal="analyst@example.com"):
    """Create an isolated synthetic GCP audit event."""

    timestamp = BASE_TIME + timedelta(minutes=minutes)

    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "method_name": method_name,
        "principal_email": principal,
        "service_name": "iam.googleapis.com",
        "resource_name": "projects/synthetic-security-lab",
        "severity": "NOTICE",
        "status": {},
        "source": "SIMULATED_TEST_EVENT",
    }


# --------------------------------------------------
# CORR-001: SERVICE ACCOUNT CREATION -> KEY CREATION
# --------------------------------------------------

def test_simulation_detects_account_creation_followed_by_key():
    events = [
        make_event(
            "sim-001",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
        ),
        make_event(
            "sim-002",
            "google.iam.admin.v1.CreateServiceAccountKey",
            20,
        ),
    ]

    results = detect_account_creation_then_key(events)

    assert len(results) == 1
    assert results[0]["rule_id"] == "CORR-001"
    assert results[0]["risk_score"] == 85


def test_simulation_corr001_rejects_different_principals():
    events = [
        make_event(
            "sim-003",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
            "analyst1@example.com",
        ),
        make_event(
            "sim-004",
            "google.iam.admin.v1.CreateServiceAccountKey",
            10,
            "analyst2@example.com",
        ),
    ]

    assert detect_account_creation_then_key(events) == []


def test_simulation_corr001_rejects_events_outside_60_minutes():
    events = [
        make_event(
            "sim-005",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
        ),
        make_event(
            "sim-006",
            "google.iam.admin.v1.CreateServiceAccountKey",
            61,
        ),
    ]

    assert detect_account_creation_then_key(events) == []


def test_simulation_corr001_rejects_wrong_event_order():
    events = [
        make_event(
            "sim-007",
            "google.iam.admin.v1.CreateServiceAccountKey",
            0,
        ),
        make_event(
            "sim-008",
            "google.iam.admin.v1.CreateServiceAccount",
            10,
        ),
    ]

    assert detect_account_creation_then_key(events) == []


# --------------------------------------------------
# CORR-002: KEY CREATION -> IAM POLICY MODIFICATION
# --------------------------------------------------

def test_simulation_detects_key_creation_followed_by_iam_change():
    events = [
        make_event(
            "sim-009",
            "google.iam.admin.v1.CreateServiceAccountKey",
            0,
        ),
        make_event(
            "sim-010",
            "google.iam.admin.v1.SetIamPolicy",
            15,
        ),
    ]

    results = detect_key_creation_then_iam_change(events)

    assert len(results) == 1
    assert results[0]["rule_id"] == "CORR-002"
    assert results[0]["risk_score"] == 95


def test_simulation_corr002_rejects_different_principals():
    events = [
        make_event(
            "sim-011",
            "google.iam.admin.v1.CreateServiceAccountKey",
            0,
            "analyst1@example.com",
        ),
        make_event(
            "sim-012",
            "google.iam.admin.v1.SetIamPolicy",
            10,
            "analyst2@example.com",
        ),
    ]

    assert detect_key_creation_then_iam_change(events) == []


def test_simulation_corr002_rejects_events_outside_60_minutes():
    events = [
        make_event(
            "sim-013",
            "google.iam.admin.v1.CreateServiceAccountKey",
            0,
        ),
        make_event(
            "sim-014",
            "google.iam.admin.v1.SetIamPolicy",
            61,
        ),
    ]

    assert detect_key_creation_then_iam_change(events) == []


def test_simulation_corr002_rejects_wrong_event_order():
    events = [
        make_event(
            "sim-015",
            "google.iam.admin.v1.SetIamPolicy",
            0,
        ),
        make_event(
            "sim-016",
            "google.iam.admin.v1.CreateServiceAccountKey",
            10,
        ),
    ]

    assert detect_key_creation_then_iam_change(events) == []


# --------------------------------------------------
# CORR-003: REPEATED SENSITIVE ADMINISTRATIVE ACTIVITY
# --------------------------------------------------

def test_simulation_detects_three_sensitive_actions_within_15_minutes():
    events = [
        make_event(
            "sim-017",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
        ),
        make_event(
            "sim-018",
            "google.iam.admin.v1.CreateServiceAccountKey",
            5,
        ),
        make_event(
            "sim-019",
            "google.iam.admin.v1.SetIamPolicy",
            10,
        ),
    ]

    results = detect_repeated_sensitive_activity(events)

    assert len(results) == 1
    assert results[0]["rule_id"] == "CORR-003"
    assert results[0]["risk_score"] == 75
    assert results[0]["event_count"] == 3


def test_simulation_corr003_rejects_different_principals():
    events = [
        make_event(
            "sim-020",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
            "analyst1@example.com",
        ),
        make_event(
            "sim-021",
            "google.iam.admin.v1.CreateServiceAccountKey",
            5,
            "analyst2@example.com",
        ),
        make_event(
            "sim-022",
            "google.iam.admin.v1.SetIamPolicy",
            10,
            "analyst3@example.com",
        ),
    ]

    assert detect_repeated_sensitive_activity(events) == []


def test_simulation_corr003_rejects_actions_spread_beyond_15_minutes():
    events = [
        make_event(
            "sim-023",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
        ),
        make_event(
            "sim-024",
            "google.iam.admin.v1.CreateServiceAccountKey",
            8,
        ),
        make_event(
            "sim-025",
            "google.iam.admin.v1.SetIamPolicy",
            16,
        ),
    ]

    assert detect_repeated_sensitive_activity(events) == []
