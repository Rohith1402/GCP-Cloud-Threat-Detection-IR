
from datetime import datetime, timedelta, timezone

from detection.behaviour_anomaly_detector import (
    detect_admin_activity_spike,
    detect_repeated_service_enablement,
    detect_unusual_service_account_activity,
)


BASE_TIME = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id,
    method_name,
    minutes,
    principal="analyst@example.com",
    service="serviceusage.googleapis.com",
    source="SIMULATED_TEST_EVENT",
):
    timestamp = BASE_TIME + timedelta(minutes=minutes)

    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "method_name": method_name,
        "principal_email": principal,
        "service_name": service,
        "resource_name": "projects/synthetic-security-lab",
        "severity": "NOTICE",
        "status": {},
        "source": source,
    }


def test_detects_administrative_activity_spike():
    methods = [
        "SetIamPolicy",
        "SetIamPolicy",
        "CreateServiceAccount",
        "CreateServiceAccountKey",
        "DeleteServiceAccountKey",
    ]

    events = [
        make_event(f"spike-{i}", method, i, service="iam.googleapis.com")
        for i, method in enumerate(methods)
    ]

    results = detect_admin_activity_spike(events)

    assert len(results) == 1
    assert results[0]["rule_id"] == "BEHAV-001"
    assert results[0]["risk_score"] == 70
    assert results[0]["event_count"] == 5


def test_admin_spike_rejects_activity_below_threshold():
    events = [
        make_event(
            f"normal-{i}",
            "SetIamPolicy",
            i,
            service="iam.googleapis.com",
        )
        for i in range(4)
    ]

    assert detect_admin_activity_spike(events) == []


def test_admin_spike_rejects_different_principals():
    events = [
        make_event(
            f"principal-{i}",
            "SetIamPolicy",
            i,
            principal=f"user{i}@example.com",
            service="iam.googleapis.com",
        )
        for i in range(5)
    ]

    assert detect_admin_activity_spike(events) == []


def test_admin_spike_ignores_normal_gcp_setup_operations():
    methods = [
        "CreateProject",
        "google.api.serviceusage.v1.ServiceUsage.EnableService",
        "google.api.serviceusage.v1.ServiceUsage.EnableService",
        "google.longrunning.Operations.GetOperation",
        "google.api.serviceusage.v1.ServiceUsage.EnableService",
        "google.api.serviceusage.v1.ServiceUsage.EnableService",
        "google.longrunning.Operations.GetOperation",
    ]

    events = [
        make_event(f"setup-{i}", method, 0)
        for i, method in enumerate(methods)
    ]

    assert detect_admin_activity_spike(events) == []


def test_admin_spike_counts_only_sensitive_operations():
    events = [
        make_event("iam-001", "SetIamPolicy", 0, service="iam.googleapis.com"),
        make_event("normal-001", "CreateProject", 1),
        make_event("normal-002", "GetOperation", 2),
        make_event("iam-002", "SetIamPolicy", 3, service="iam.googleapis.com"),
        make_event("normal-003", "EnableService", 4),
        make_event("iam-003", "CreateServiceAccount", 5, service="iam.googleapis.com"),
    ]

    assert detect_admin_activity_spike(events) == []


def test_detects_repeated_service_enablement():
    events = [
        make_event(
            f"enable-{i}",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            i,
        )
        for i in range(3)
    ]

    results = detect_repeated_service_enablement(events)

    assert len(results) == 1
    assert results[0]["rule_id"] == "BEHAV-002"
    assert results[0]["risk_score"] == 55
    assert results[0]["confidence"] == "LOW"
    assert results[0]["detection_status"] == "REQUIRES_INVESTIGATION"


def test_service_enablement_rejects_insufficient_events():
    events = [
        make_event(
            "enable-one",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            0,
        ),
        make_event(
            "enable-two",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            5,
        ),
    ]

    assert detect_repeated_service_enablement(events) == []


def test_service_enablement_rejects_different_principals():
    events = [
        make_event(
            f"enable-user-{i}",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            i,
            principal=f"user{i}@example.com",
        )
        for i in range(3)
    ]

    assert detect_repeated_service_enablement(events) == []


def test_detects_unusual_service_account_activity():
    events = [
        make_event(
            "sa-001",
            "google.iam.admin.v1.CreateServiceAccount",
            0,
            service="iam.googleapis.com",
        ),
        make_event(
            "sa-002",
            "google.iam.admin.v1.CreateServiceAccountKey",
            5,
            service="iam.googleapis.com",
        ),
    ]

    results = detect_unusual_service_account_activity(events)

    assert len(results) == 1
    assert results[0]["rule_id"] == "BEHAV-003"
    assert results[0]["risk_score"] == 65


def test_service_account_rule_ignores_unrelated_activity():
    events = [
        make_event(
            "unrelated-001",
            "google.longrunning.Operations.GetOperation",
            0,
        ),
        make_event(
            "unrelated-002",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            5,
        ),
    ]

    assert detect_unusual_service_account_activity(events) == []


def test_invalid_timestamps_are_ignored():
    events = [
        {
            "event_id": "invalid-001",
            "timestamp": "not-a-timestamp",
            "method_name": "SetIamPolicy",
            "principal_email": "analyst@example.com",
            "service_name": "iam.googleapis.com",
            "source": "SIMULATED_TEST_EVENT",
        }
    ]

    assert detect_admin_activity_spike(events) == []


def test_missing_timestamps_are_ignored():
    events = [
        {
            "event_id": "missing-001",
            "method_name": "SetIamPolicy",
            "principal_email": "analyst@example.com",
            "service_name": "iam.googleapis.com",
            "source": "SIMULATED_TEST_EVENT",
        }
    ]

    assert detect_admin_activity_spike(events) == []


def test_duplicate_event_ids_do_not_inflate_activity_count():
    events = [
        make_event("duplicate-001", "SetIamPolicy", 0, service="iam.googleapis.com"),
        make_event("duplicate-001", "SetIamPolicy", 1, service="iam.googleapis.com"),
        make_event("duplicate-002", "SetIamPolicy", 2, service="iam.googleapis.com"),
    ]

    assert detect_admin_activity_spike(events) == []


def test_simulated_events_are_labelled_in_detection_results():
    events = [
        make_event(
            f"simulated-{i}",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            i,
            source="SIMULATED_TEST_EVENT",
        )
        for i in range(3)
    ]

    results = detect_repeated_service_enablement(events)

    assert len(results) == 1
    assert results[0]["source"] == "SIMULATED"
