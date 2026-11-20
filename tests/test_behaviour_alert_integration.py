import json
import tempfile
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from detection import alert_classifier
from detection.alert_classifier import (
    classify_alerts,
    deduplicate_alerts,
    load_behaviour_records,
    normalise_behaviour_alert,
    normalise_correlation,
)
from detection.behaviour_alert_integration import (
    build_behaviour_report,
    load_audit_events,
    main as run_behaviour_integration,
    run_behaviour_detection,
)


BASE_TIME = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id,
    method_name,
    minutes,
    principal="analyst@example.com",
    service="iam.googleapis.com",
    source="SIMULATED_TEST_EVENT",
):
    return {
        "event_id": event_id,
        "timestamp": (BASE_TIME + timedelta(minutes=minutes)).isoformat(),
        "method_name": method_name,
        "principal_email": principal,
        "service_name": service,
        "resource_name": "projects/synthetic-security-lab",
        "severity": "NOTICE",
        "status": {},
        "source": source,
    }


def admin_spike_events():
    methods = [
        "SetIamPolicy",
        "SetIamPolicy",
        "SetIamPolicy",
        "DeleteServiceAccountKey",
        "SetIamPolicy",
    ]
    return [
        make_event(f"spike-{i}", method, i)
        for i, method in enumerate(methods)
    ]


def service_enablement_events():
    return [
        make_event(
            f"enable-{i}",
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            30 + i,
            service="serviceusage.googleapis.com",
        )
        for i in range(3)
    ]


def service_account_events():
    return [
        make_event(
            "sa-create",
            "google.iam.admin.v1.CreateServiceAccount",
            120,
        ),
        make_event(
            "sa-key",
            "google.iam.admin.v1.CreateServiceAccountKey",
            125,
        ),
    ]


def all_behaviour_events():
    return (
        admin_spike_events()
        + service_enablement_events()
        + service_account_events()
    )


def write_json(path, data):
    Path(path).write_text(json.dumps(data), encoding="utf-8")


class TestBehaviourDetectionRunner(unittest.TestCase):

    def test_all_three_behaviour_rules_are_run(self):
        results = run_behaviour_detection(all_behaviour_events())

        rule_ids = sorted(result["rule_id"] for result in results)

        self.assertEqual(
            rule_ids,
            ["BEHAV-001", "BEHAV-002", "BEHAV-003"]
        )

    def test_normal_setup_activity_creates_no_high_risk_alerts(self):
        events = [
            make_event("setup-1", "CreateProject", 0),
            make_event(
                "setup-2",
                "google.longrunning.Operations.GetOperation",
                1,
            ),
        ]

        self.assertEqual(run_behaviour_detection(events), [])

    def test_duplicate_detections_are_not_repeated(self):
        events = service_enablement_events()

        first = run_behaviour_detection(events)
        repeated = run_behaviour_detection(events + events)

        self.assertEqual(len(first), 1)
        self.assertEqual(len(repeated), 1)

    def test_failing_detector_does_not_stop_other_rules(self):
        def broken_detector(events):
            raise ValueError("synthetic failure")

        from detection import behaviour_alert_integration as module

        detectors = (broken_detector,) + module.BEHAVIOUR_DETECTORS

        with mock.patch.object(module, "BEHAVIOUR_DETECTORS", detectors):
            results = run_behaviour_detection(service_enablement_events())

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "BEHAV-002")

    def test_report_summarises_rules_and_sources(self):
        events = all_behaviour_events()
        results = run_behaviour_detection(events)

        report = build_behaviour_report(events, results)

        self.assertEqual(report["total_events_analyzed"], len(events))
        self.assertEqual(report["total_behaviour_alerts"], 3)
        self.assertEqual(report["rule_summary"]["BEHAV-002"], 1)
        self.assertEqual(report["source_summary"], {"SIMULATED": 3})


class TestAuditEventLoading(unittest.TestCase):

    def test_missing_audit_file_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            result = load_audit_events(Path(directory) / "missing.json")

        self.assertEqual(result, [])

    def test_malformed_audit_file_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_file = Path(directory) / "audit.json"
            audit_file.write_text("{invalid json", encoding="utf-8")

            result = load_audit_events(audit_file)

        self.assertEqual(result, [])

    def test_non_dict_records_are_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_file = Path(directory) / "audit.json"
            write_json(audit_file, [make_event("ok", "SetIamPolicy", 0), "bad", 7])

            result = load_audit_events(audit_file)

        self.assertEqual(len(result), 1)

    def test_integration_writes_behaviour_report(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_file = Path(directory) / "audit.json"
            output_file = Path(directory) / "behaviour.json"
            write_json(audit_file, all_behaviour_events())

            run_behaviour_integration(audit_file, output_file)

            report = json.loads(output_file.read_text(encoding="utf-8"))

        self.assertEqual(report["total_behaviour_alerts"], 3)
        self.assertEqual(len(report["alerts"]), 3)


class TestBehaviourAlertNormalisation(unittest.TestCase):

    def setUp(self):
        self.records = {
            result["rule_id"]: result
            for result in run_behaviour_detection(all_behaviour_events())
        }

    def test_behaviour_alert_uses_standard_soc_format(self):
        alert = normalise_behaviour_alert(self.records["BEHAV-001"])

        expected_keys = {
            "alert_id", "source_module", "principal_or_resource",
            "category", "risk_score", "severity", "description",
            "timestamp", "status", "rule_id", "rule_name",
            "confidence", "mitre_technique_id", "mitre_technique_name",
            "mitre_tactics",
            "evidence", "recommendation", "detection_status",
        }

        self.assertEqual(set(alert), expected_keys)
        self.assertEqual(alert["source_module"], "gcp_behaviour_alerts")
        self.assertEqual(alert["status"], "OPEN")
        self.assertEqual(
            alert["detection_status"],
            "REQUIRES_INVESTIGATION"
        )

    def test_severity_uses_classifier_thresholds(self):
        self.assertEqual(
            normalise_behaviour_alert(self.records["BEHAV-001"])["severity"],
            "HIGH"
        )
        self.assertEqual(
            normalise_behaviour_alert(self.records["BEHAV-002"])["severity"],
            "MEDIUM"
        )
        self.assertEqual(
            normalise_behaviour_alert(self.records["BEHAV-003"])["severity"],
            "MEDIUM"
        )

    def test_mitre_mapping_is_preserved(self):
        alert = normalise_behaviour_alert(self.records["BEHAV-003"])

        self.assertEqual(alert["mitre_technique_id"], "T1098.001")
        self.assertEqual(
            alert["mitre_technique_name"],
            "Additional Cloud Credentials"
        )

    def test_low_confidence_is_preserved(self):
        alert = normalise_behaviour_alert(self.records["BEHAV-002"])

        self.assertEqual(alert["confidence"], "LOW")

    def test_evidence_and_simulation_label_are_preserved(self):
        alert = normalise_behaviour_alert(self.records["BEHAV-003"])

        self.assertEqual(alert["evidence"]["data_source"], "SIMULATED")
        self.assertEqual(alert["evidence"]["event_count"], 2)
        self.assertEqual(
            [event["event_id"] for event in alert["evidence"]["events"]],
            ["sa-create", "sa-key"]
        )
        self.assertEqual(
            alert["timestamp"],
            self.records["BEHAV-003"]["first_seen"]
        )

    def test_real_events_are_labelled_real(self):
        events = [
            dict(event, source="gcp_cloud_audit_logs")
            for event in service_enablement_events()
        ]

        record = run_behaviour_detection(events)[0]
        alert = normalise_behaviour_alert(record)

        self.assertEqual(alert["evidence"]["data_source"], "REAL")

    def test_invalid_risk_score_is_clamped(self):
        record = dict(self.records["BEHAV-002"], risk_score="bad")
        self.assertEqual(normalise_behaviour_alert(record)["risk_score"], 0)

        record = dict(self.records["BEHAV-002"], risk_score=250)
        self.assertEqual(normalise_behaviour_alert(record)["risk_score"], 100)


class TestBehaviourReportLoading(unittest.TestCase):

    def test_missing_behaviour_report_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            result = load_behaviour_records(Path(directory) / "missing.json")

        self.assertEqual(result, [])

    def test_malformed_behaviour_report_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "behaviour.json"
            report_file.write_text("{invalid json", encoding="utf-8")

            result = load_behaviour_records(report_file)

        self.assertEqual(result, [])

    def test_non_behaviour_records_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "behaviour.json"
            write_json(report_file, {
                "alerts": [
                    {"alert_id": "x-1", "rule_id": "CORR-001"},
                    {"alert_id": "", "rule_id": "BEHAV-001"},
                    {"alert_id": "BEHAV-002-a", "rule_id": "BEHAV-002"},
                ]
            })

            result = load_behaviour_records(report_file)

        self.assertEqual([item["alert_id"] for item in result], ["BEHAV-002-a"])


class TestBehaviourAlertsInSocPipeline(unittest.TestCase):

    def test_duplicate_behaviour_alerts_are_deduplicated(self):
        record = run_behaviour_detection(service_enablement_events())[0]

        first = normalise_behaviour_alert(record)
        duplicate = normalise_behaviour_alert(dict(record, risk_score=60))

        result = deduplicate_alerts([first, duplicate])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk_score"], 60)

    def test_behaviour_alerts_are_prioritised_with_other_alerts(self):
        behaviour_alert = normalise_behaviour_alert(
            run_behaviour_detection(admin_spike_events())[0]
        )

        correlation_alert = normalise_correlation({
            "correlation_id": "CORR-TEST-001",
            "rule_id": "CORR-001",
            "risk_score": 85,
            "principal_email": "analyst@example.com",
            "evidence": [],
        })

        ordinary_alert = {
            "alert_id": "ordinary-001",
            "source_module": "iam_security_alerts",
            "severity": "MEDIUM",
            "risk_score": 40,
        }

        result, summary = classify_alerts([
            ordinary_alert,
            behaviour_alert,
            correlation_alert,
        ])

        self.assertEqual(
            [alert["alert_id"] for alert in result],
            ["CORR-TEST-001", behaviour_alert["alert_id"], "ordinary-001"]
        )
        self.assertEqual(summary["HIGH"], 2)

    def test_classifier_includes_behaviour_alerts_in_consolidated_report(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            audit_file = directory / "audit.json"
            behaviour_file = directory / "behaviour.json"
            output_file = directory / "consolidated.json"

            write_json(audit_file, all_behaviour_events())
            run_behaviour_integration(audit_file, behaviour_file)

            with mock.patch.object(alert_classifier, "REPORT_FILES", []), \
                    mock.patch.object(alert_classifier, "OUTPUT_FILE", output_file), \
                    mock.patch.object(alert_classifier, "BEHAVIOUR_REPORT_FILE", behaviour_file), \
                    mock.patch.object(
                        alert_classifier, "load_correlation_records",
                        return_value=[]
                    ):
                alert_classifier.main()

            report = json.loads(output_file.read_text(encoding="utf-8"))

        self.assertEqual(report["behaviour_alert_count"], 3)
        self.assertEqual(report["correlation_alert_count"], 0)
        self.assertEqual(report["source_summary"], {"gcp_behaviour_alerts": 3})
        self.assertEqual(
            sorted(report["rule_summary"]),
            ["BEHAV-001", "BEHAV-002", "BEHAV-003"]
        )


if __name__ == "__main__":
    unittest.main()
