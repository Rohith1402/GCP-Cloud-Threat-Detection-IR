
import unittest

from detection.iam_misconfiguration import (
    analyze_iam_policy,
    classify_severity,
)


class TestIAMDetection(unittest.TestCase):

    def test_owner_role_detection(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:admin@example.com"],
                }
            ]
        }

        alerts = analyze_iam_policy(policy)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 50)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_public_principal_detection(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"],
                }
            ]
        }

        alerts = analyze_iam_policy(policy)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 70)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_service_account_privileged_role(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [
                        "serviceAccount:test@example.iam.gserviceaccount.com"
                    ],
                }
            ]
        }

        alerts = analyze_iam_policy(policy)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 70)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_normal_viewer_role(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:viewer@example.com"],
                }
            ]
        }

        alerts = analyze_iam_policy(policy)

        self.assertEqual(len(alerts), 0)

    def test_severity_classification(self):
        self.assertEqual(classify_severity(20), "LOW")
        self.assertEqual(classify_severity(50), "MEDIUM")
        self.assertEqual(classify_severity(80), "HIGH")


if __name__ == "__main__":
    unittest.main()
