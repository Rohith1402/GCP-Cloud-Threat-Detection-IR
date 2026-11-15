
import unittest

from detection.alert_classifier import (
    normalise_alert,
    deduplicate_alerts,
    classify_alerts,
    classify_severity
)


class TestAlertClassifier(unittest.TestCase):

    def test_normalise_scc_alert(self):
        alert = {
            "finding_id": "scc-001",
            "category": "PUBLIC_BUCKET_ACCESS",
            "priority": "CRITICAL",
            "risk_score": 100,
            "resource_name": "test-bucket",
            "description": "Public bucket access"
        }

        result = normalise_alert(alert, "scc_security_alerts")

        self.assertEqual(result["alert_id"], "scc-001")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["risk_score"], 100)

    def test_normalise_service_account_alert(self):
        alert = {
            "event_id": "sa-001",
            "event_type": "SERVICE_ACCOUNT_KEY_CREATED",
            "severity": "MEDIUM",
            "risk_score": 50,
            "service_account": "test@example.com"
        }

        result = normalise_alert(alert, "service_account_alerts")

        self.assertEqual(result["alert_id"], "sa-001")
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(
            result["principal_or_resource"],
            "test@example.com"
        )

    def test_invalid_risk_score(self):
        alert = {
            "event_id": "test-001",
            "severity": "HIGH",
            "risk_score": "invalid"
        }

        result = normalise_alert(alert, "test_report")

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity"], "LOW")

    def test_risk_score_bounds(self):
        high_alert = normalise_alert(
            {"event_id": "test-002", "risk_score": 150},
            "test_report"
        )

        low_alert = normalise_alert(
            {"event_id": "test-003", "risk_score": -10},
            "test_report"
        )

        self.assertEqual(high_alert["risk_score"], 100)
        self.assertEqual(high_alert["severity"], "CRITICAL")

        self.assertEqual(low_alert["risk_score"], 0)
        self.assertEqual(low_alert["severity"], "LOW")

    def test_duplicate_alert_removal(self):
        alerts = [
            {
                "source_module": "iam",
                "alert_id": "alert-001",
                "risk_score": 40
            },
            {
                "source_module": "iam",
                "alert_id": "alert-001",
                "risk_score": 70
            }
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk_score"], 70)

    def test_alerts_sorted_by_priority(self):
        alerts = [
            {
                "source_module": "test",
                "alert_id": "low",
                "severity": "LOW",
                "risk_score": 20
            },
            {
                "source_module": "test",
                "alert_id": "critical",
                "severity": "CRITICAL",
                "risk_score": 90
            },
            {
                "source_module": "test",
                "alert_id": "medium",
                "severity": "MEDIUM",
                "risk_score": 50
            }
        ]

        result, summary = classify_alerts(alerts)

        self.assertEqual(result[0]["alert_id"], "critical")
        self.assertEqual(result[1]["alert_id"], "medium")
        self.assertEqual(result[2]["alert_id"], "low")

        self.assertEqual(summary["CRITICAL"], 1)
        self.assertEqual(summary["MEDIUM"], 1)
        self.assertEqual(summary["LOW"], 1)

    def test_duplicate_alerts_from_different_sources(self):
        alerts = [
            {
                "source_module": "iam",
                "alert_id": "alert-001",
                "severity": "HIGH",
                "risk_score": 80
            },
            {
                "source_module": "audit",
                "alert_id": "alert-001",
                "severity": "MEDIUM",
                "risk_score": 40
            }
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 2)

    def test_risk_based_severity_classification(self):
        self.assertEqual(classify_severity(100), "CRITICAL")
        self.assertEqual(classify_severity(90), "CRITICAL")
        self.assertEqual(classify_severity(89), "HIGH")
        self.assertEqual(classify_severity(70), "HIGH")
        self.assertEqual(classify_severity(69), "MEDIUM")
        self.assertEqual(classify_severity(30), "MEDIUM")
        self.assertEqual(classify_severity(29), "LOW")
        self.assertEqual(classify_severity(0), "LOW")


if __name__ == "__main__":
    unittest.main()
