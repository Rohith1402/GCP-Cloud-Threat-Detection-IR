
import unittest

from detection.service_account_monitor import (
    detect_suspicious_activity,
    classify_severity
)


class TestServiceAccountMonitor(unittest.TestCase):

    def test_service_account_key_creation(self):
        events = [
            {
                "event_id": "test-001",
                "timestamp": "2026-11-15T09:30:00Z",
                "event_type": "SERVICE_ACCOUNT_KEY_CREATED",
                "service_account": "backup-sa@example.com",
                "source_ip": "192.168.1.10",
                "status": "SUCCESS",
                "failed_attempts": 0
            }
        ]

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 50)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_authentication_outside_normal_hours(self):
        events = [
            {
                "event_id": "test-002",
                "timestamp": "2026-11-15T23:45:00Z",
                "event_type": "SERVICE_ACCOUNT_AUTHENTICATION",
                "service_account": "admin-sa@example.com",
                "source_ip": "203.0.113.50",
                "status": "SUCCESS",
                "failed_attempts": 0
            }
        ]

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 30)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_multiple_failed_authentication_attempts(self):
        events = [
            {
                "event_id": "test-003",
                "timestamp": "2026-11-15T14:20:00Z",
                "event_type": "SERVICE_ACCOUNT_AUTHENTICATION",
                "service_account": "app-sa@example.com",
                "source_ip": "10.0.0.15",
                "status": "FAILED",
                "failed_attempts": 5
            }
        ]

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 60)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(len(alerts[0]["findings"]), 2)

    def test_normal_authentication(self):
        events = [
            {
                "event_id": "test-004",
                "timestamp": "2026-11-15T11:00:00Z",
                "event_type": "SERVICE_ACCOUNT_AUTHENTICATION",
                "service_account": "reporting-sa@example.com",
                "source_ip": "10.0.0.20",
                "status": "SUCCESS",
                "failed_attempts": 0
            }
        ]

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 0)

    def test_severity_classification(self):
        self.assertEqual(classify_severity(20), "LOW")
        self.assertEqual(classify_severity(40), "MEDIUM")
        self.assertEqual(classify_severity(70), "HIGH")


if __name__ == "__main__":
    unittest.main()
