
import unittest

from detection.iam_privilege_escalation import (
    analyze_permissions,
    classify_severity,
)


class TestIAMPrivilegeEscalation(unittest.TestCase):

    def setUp(self):
        self.roles = {
            "roles/owner": {
                "permissions": [
                    "iam.serviceAccounts.actAs",
                    "iam.serviceAccounts.getAccessToken",
                    "iam.serviceAccountKeys.create",
                    "resourcemanager.projects.setIamPolicy",
                    "iam.roles.create",
                    "iam.roles.update",
                ]
            },
            "roles/iam.serviceAccountTokenCreator": {
                "permissions": [
                    "iam.serviceAccounts.getAccessToken"
                ]
            },
            "roles/viewer": {
                "permissions": [
                    "resourcemanager.projects.get"
                ]
            },
        }

    def test_owner_sensitive_permissions(self):
        policy = {
            "bindings": [{
                "role": "roles/owner",
                "members": ["user:admin@example.com"]
            }]
        }

        alerts = analyze_permissions(policy, self.roles)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 100)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(len(alerts[0]["risky_permissions"]), 6)

    def test_service_account_token_creator(self):
        policy = {
            "bindings": [{
                "role": "roles/iam.serviceAccountTokenCreator",
                "members": ["user:operator@example.com"]
            }]
        }

        alerts = analyze_permissions(policy, self.roles)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 40)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_normal_viewer_role(self):
        policy = {
            "bindings": [{
                "role": "roles/viewer",
                "members": ["user:viewer@example.com"]
            }]
        }

        alerts = analyze_permissions(policy, self.roles)

        self.assertEqual(len(alerts), 0)

    def test_unknown_role(self):
        policy = {
            "bindings": [{
                "role": "roles/custom.unknown",
                "members": ["user:test@example.com"]
            }]
        }

        alerts = analyze_permissions(policy, self.roles)

        self.assertEqual(len(alerts), 0)

    def test_severity_classification(self):
        self.assertEqual(classify_severity(20), "LOW")
        self.assertEqual(classify_severity(50), "MEDIUM")
        self.assertEqual(classify_severity(100), "HIGH")


if __name__ == "__main__":
    unittest.main()
