
import unittest

from detection.scc_findings_analyzer import (
    analyze_scc_findings,
    classify_severity
)


class TestSCCFindingsAnalyzer(unittest.TestCase):

    def test_public_bucket_access(self):
        findings = [
            {
                "finding_id": "test-001",
                "category": "PUBLIC_BUCKET_ACCESS",
                "severity": "CRITICAL",
                "state": "ACTIVE",
                "resource_name": "test-bucket",
                "description": "Public bucket access"
            }
        ]

        alerts = analyze_scc_findings(findings)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 100)
        self.assertEqual(alerts[0]["priority"], "CRITICAL")

    def test_over_privileged_iam(self):
        findings = [
            {
                "finding_id": "test-002",
                "category": "OVER_PRIVILEGED_IAM",
                "severity": "HIGH",
                "state": "ACTIVE",
                "resource_name": "test-project",
                "description": "Excessive IAM permissions"
            }
        ]

        alerts = analyze_scc_findings(findings)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 90)
        self.assertEqual(alerts[0]["priority"], "CRITICAL")

    def test_inactive_finding_ignored(self):
        findings = [
            {
                "finding_id": "test-003",
                "category": "OUTDATED_SOFTWARE",
                "severity": "LOW",
                "state": "INACTIVE",
                "resource_name": "test-server",
                "description": "Outdated software"
            }
        ]

        alerts = analyze_scc_findings(findings)

        self.assertEqual(len(alerts), 0)

    def test_suspicious_network_activity(self):
        findings = [
            {
                "finding_id": "test-004",
                "category": "SUSPICIOUS_NETWORK_ACTIVITY",
                "severity": "MEDIUM",
                "state": "ACTIVE",
                "resource_name": "app-server",
                "description": "Unusual network activity"
            }
        ]

        alerts = analyze_scc_findings(findings)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 55)
        self.assertEqual(alerts[0]["priority"], "MEDIUM")

    def test_findings_sorted_by_risk(self):
        findings = [
            {
                "finding_id": "test-005",
                "category": "SUSPICIOUS_NETWORK_ACTIVITY",
                "severity": "MEDIUM",
                "state": "ACTIVE"
            },
            {
                "finding_id": "test-006",
                "category": "PUBLIC_BUCKET_ACCESS",
                "severity": "CRITICAL",
                "state": "ACTIVE"
            }
        ]

        alerts = analyze_scc_findings(findings)

        self.assertGreaterEqual(
            alerts[0]["risk_score"],
            alerts[1]["risk_score"]
        )

    def test_severity_classification(self):
        self.assertEqual(classify_severity(20), "LOW")
        self.assertEqual(classify_severity(55), "MEDIUM")
        self.assertEqual(classify_severity(70), "HIGH")
        self.assertEqual(classify_severity(90), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
