
import unittest

from detection.audit_log_monitor import (
    detect_suspicious_activity,
    classify_severity
)


class TestAuditLogMonitor(unittest.TestCase):

    def test_iam_policy_modification(self):
        logs = [
            {
                "insertId": "test-001",
                "protoPayload": {
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {
                        "principalEmail": "admin@example.com"
                    },
                    "status": {"code": 0}
                }
            }
        ]

        alerts = detect_suspicious_activity(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 40)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_service_account_key_creation(self):
        logs = [
            {
                "insertId": "test-002",
                "protoPayload": {
                    "methodName": (
                        "google.iam.admin.v1.CreateServiceAccountKey"
                    ),
                    "authenticationInfo": {
                        "principalEmail": "user@example.com"
                    },
                    "status": {"code": 0}
                }
            }
        ]

        alerts = detect_suspicious_activity(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 50)
        self.assertEqual(len(alerts[0]["findings"]), 1)

    def test_failed_service_account_creation(self):
        logs = [
            {
                "insertId": "test-003",
                "protoPayload": {
                    "methodName": (
                        "google.iam.admin.v1.CreateServiceAccount"
                    ),
                    "authenticationInfo": {
                        "principalEmail": "developer@example.com"
                    },
                    "status": {"code": 7}
                }
            }
        ]

        alerts = detect_suspicious_activity(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 50)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(len(alerts[0]["findings"]), 2)

    def test_normal_operation(self):
        logs = [
            {
                "insertId": "test-004",
                "protoPayload": {
                    "methodName": "GetIamPolicy",
                    "authenticationInfo": {
                        "principalEmail": "viewer@example.com"
                    },
                    "status": {"code": 0}
                }
            }
        ]

        alerts = detect_suspicious_activity(logs)

        self.assertEqual(len(alerts), 0)

    def test_severity_classification(self):
        self.assertEqual(classify_severity(20), "LOW")
        self.assertEqual(classify_severity(40), "MEDIUM")
        self.assertEqual(classify_severity(70), "HIGH")


if __name__ == "__main__":
    unittest.main()
