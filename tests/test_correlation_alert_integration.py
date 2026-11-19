
import json
import tempfile
import unittest

from pathlib import Path

from detection.alert_classifier import (
    load_correlation_records,
    normalise_correlation,
    deduplicate_alerts,
    classify_alerts
)


class TestCorrelationAlertIntegration(unittest.TestCase):

    def setUp(self):
        self.correlation = {
            "correlation_id": "CORR-TEST-001",
            "rule_id": "CORR-001",
            "rule_name": "Service Account Creation Followed by Key Creation",
            "description": "A service account was created and a key was subsequently generated.",
            "risk_score": 85,
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "detection_status": "REQUIRES_INVESTIGATION",
            "event_count": 2,
            "first_seen": "2026-11-19T10:00:00+00:00",
            "last_seen": "2026-11-19T10:10:00+00:00",
            "principal_email": "test@example.com",
            "evidence": [
                {
                    "event_id": "event-001",
                    "method_name": "CreateServiceAccount",
                    "timestamp": "2026-11-19T10:00:00+00:00"
                },
                {
                    "event_id": "event-002",
                    "method_name": "CreateServiceAccountKey",
                    "timestamp": "2026-11-19T10:10:00+00:00"
                }
            ],
            "recommendation": "Review the actor and event sequence."
        }

    def test_correlation_is_normalised_into_soc_alert(self):
        result = normalise_correlation(self.correlation)

        self.assertEqual(
            result["alert_id"],
            "CORR-TEST-001"
        )
        self.assertEqual(
            result["source_module"],
            "gcp_event_correlations"
        )
        self.assertEqual(result["rule_id"], "CORR-001")
        self.assertEqual(result["risk_score"], 85)
        self.assertEqual(result["severity"], "HIGH")

    def test_correlation_metadata_is_preserved(self):
        result = normalise_correlation(self.correlation)

        self.assertEqual(result["confidence"], "MEDIUM")
        self.assertEqual(
            result["detection_status"],
            "REQUIRES_INVESTIGATION"
        )
        self.assertEqual(
            result["rule_name"],
            self.correlation["rule_name"]
        )

    def test_correlation_principal_and_timestamps_are_preserved(self):
        result = normalise_correlation(self.correlation)

        self.assertEqual(
            result["principal_or_resource"],
            "test@example.com"
        )
        self.assertEqual(
            result["timestamp"],
            self.correlation["first_seen"]
        )
        self.assertEqual(
            result["evidence"]["last_seen"],
            self.correlation["last_seen"]
        )

    def test_all_contributing_events_are_preserved(self):
        result = normalise_correlation(self.correlation)

        self.assertEqual(
            result["evidence"]["event_count"],
            2
        )
        self.assertEqual(
            len(result["evidence"]["events"]),
            2
        )
        self.assertEqual(
            result["evidence"]["events"][0]["event_id"],
            "event-001"
        )

    def test_recommendation_is_preserved(self):
        result = normalise_correlation(self.correlation)

        self.assertEqual(
            result["recommendation"],
            "Review the actor and event sequence."
        )

    def test_missing_correlation_report_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_file = Path(directory) / "missing.json"

            result = load_correlation_records(missing_file)

        self.assertEqual(result, [])

    def test_empty_correlation_report_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "correlations.json"

            report_file.write_text(
                json.dumps({
                    "total_correlations": 0,
                    "correlations": []
                }),
                encoding="utf-8"
            )

            result = load_correlation_records(report_file)

        self.assertEqual(result, [])

    def test_malformed_json_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "correlations.json"
            report_file.write_text("{invalid json", encoding="utf-8")

            result = load_correlation_records(report_file)

        self.assertEqual(result, [])

    def test_duplicate_correlation_alerts_are_deduplicated(self):
        first = normalise_correlation(self.correlation)

        duplicate_data = dict(self.correlation)
        duplicate_data["risk_score"] = 95
        duplicate = normalise_correlation(duplicate_data)

        result = deduplicate_alerts([first, duplicate])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk_score"], 95)

    def test_correlation_alerts_are_prioritised(self):
        correlation_alert = normalise_correlation(self.correlation)

        ordinary_alert = {
            "alert_id": "ordinary-001",
            "source_module": "iam_security_alerts",
            "severity": "MEDIUM",
            "risk_score": 40
        }

        result, summary = classify_alerts([
            ordinary_alert,
            correlation_alert
        ])

        self.assertEqual(
            result[0]["alert_id"],
            "CORR-TEST-001"
        )
        self.assertEqual(summary["HIGH"], 1)
        self.assertEqual(summary["MEDIUM"], 1)


if __name__ == "__main__":
    unittest.main()
