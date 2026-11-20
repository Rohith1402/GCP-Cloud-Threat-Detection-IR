import json
import tempfile
import unittest

from pathlib import Path

from detection.publish_website_data import (
    SanitisationError,
    Sanitiser,
    build_public_report,
    check_for_leaks,
    main as publish_website_data,
)


REAL_EMAIL = "real.person@gmail.com"
REAL_PROJECT = "my-security-lab-123456"
PROJECT_NUMBER = "456513016005"


def make_alerts():
    return [
        {
            "alert_id": f"iam_privilege_alerts:user:{REAL_EMAIL}",
            "source_module": "iam_privilege_alerts",
            "principal_or_resource": f"user:{REAL_EMAIL}",
            "risk_score": 100,
            "severity": "CRITICAL",
            "rule_id": "GCP-IAM-006",
            "rule_name": "Sensitive IAM Permission Combination",
            "description": "Sensitive IAM capabilities detected",
            "evidence": {"method": None},
        },
        {
            "alert_id": "scc-001",
            "source_module": "scc_security_alerts",
            "principal_or_resource": (
                f"projects/{REAL_PROJECT}/buckets/public-data"
            ),
            "risk_score": 100,
            "severity": "CRITICAL",
            "rule_id": "GCP-SCC-001",
            "description": "Cloud storage bucket allows public access",
        },
        {
            "alert_id": "audit-001",
            "source_module": "audit_log_alerts",
            "principal_or_resource": "admin@example.com",
            "risk_score": 80,
            "severity": "HIGH",
            "rule_id": "GCP-IAM-001",
            "description": "Sensitive operation detected: SetIamPolicy",
        },
        {
            "alert_id": "BEHAV-002-event-1",
            "source_module": "gcp_behaviour_alerts",
            "principal_or_resource": REAL_EMAIL,
            "risk_score": 55,
            "severity": "MEDIUM",
            "confidence": "LOW",
            "rule_id": "BEHAV-002",
            "rule_name": "Repeated Service Enablement",
            "description": "Repeated service enablement operations.",
            "evidence": {
                "event_count": 3,
                "first_seen": "2026-11-15T14:43:46+00:00",
                "last_seen": "2026-11-15T14:43:48+00:00",
                "data_source": "REAL",
                "events": [
                    {
                        "event_id": f"event-{i}",
                        "timestamp": "2026-11-15T14:43:46+00:00",
                        "method_name": "ServiceUsage.EnableService",
                        "service_name": "serviceusage.googleapis.com",
                        "principal_email": REAL_EMAIL,
                    }
                    for i in range(3)
                ],
            },
        },
        {
            "alert_id": "real-event-1",
            "source_module": "gcp_audit_logs",
            "principal_or_resource": REAL_EMAIL,
            "risk_score": 5,
            "severity": "LOW",
            "rule_id": "GENERAL-001",
            "description": (
                f"Operation projects/{PROJECT_NUMBER}/operations/"
                f"acat.p2-{PROJECT_NUMBER}-abc"
            ),
        },
    ]


class TestSanitisation(unittest.TestCase):

    def setUp(self):
        self.report = build_public_report(
            make_alerts(),
            generated_at="2026-11-20T00:00:00+00:00",
        )
        self.text = json.dumps(self.report)

    def test_real_emails_are_removed(self):
        self.assertNotIn(REAL_EMAIL, self.text)
        self.assertNotIn("gmail.com", self.text)

    def test_same_email_gets_same_alias_everywhere(self):
        principals = {
            alert["principal"]
            for alert in self.report["alerts"]
            if alert["source_module"] in (
                "gcp_behaviour_alerts",
                "gcp_audit_logs",
            )
        }
        self.assertEqual(principals, {"user-01"})

    def test_fictional_example_emails_are_kept(self):
        self.assertIn("admin@example.com", self.text)

    def test_project_ids_and_numbers_are_removed(self):
        self.assertNotIn(REAL_PROJECT, self.text)
        self.assertNotIn(PROJECT_NUMBER, self.text)

    def test_resource_names_are_replaced_with_resource_type(self):
        alert = next(
            item for item in self.report["alerts"]
            if item["alert_id"] == "scc-001"
        )
        self.assertEqual(alert["principal"], "Storage bucket")
        self.assertNotIn("public-data", self.text)
        self.assertNotIn("projects/", self.text)

    def test_leak_check_rejects_resource_names(self):
        sanitiser = Sanitiser({})
        with self.assertRaises(SanitisationError):
            check_for_leaks({"resource": "projects/[PROJECT]/x"}, sanitiser)

    def test_service_accounts_get_service_account_alias(self):
        sanitiser = Sanitiser({})
        result = sanitiser.clean_text(
            "backup@prod-project.iam.gserviceaccount.com"
        )
        self.assertEqual(result, "service-account-01")

    def test_leak_check_rejects_unmasked_email(self):
        sanitiser = Sanitiser({})
        with self.assertRaises(SanitisationError):
            check_for_leaks({"principal": REAL_EMAIL}, sanitiser)

    def test_leak_check_rejects_unmasked_project(self):
        data = {"resource": f"projects/{REAL_PROJECT}"}
        sanitiser = Sanitiser(data)
        with self.assertRaises(SanitisationError):
            check_for_leaks(data, sanitiser)


class TestPublicReport(unittest.TestCase):

    def setUp(self):
        self.report = build_public_report(make_alerts())
        self.alerts = {
            alert["alert_id"]: alert for alert in self.report["alerts"]
        }

    def test_alerts_are_sorted_by_risk(self):
        scores = [alert["risk_score"] for alert in self.report["alerts"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_data_labels_separate_real_and_synthetic(self):
        self.assertEqual(self.alerts["scc-001"]["data_label"], "SYNTHETIC")
        self.assertEqual(self.alerts["real-event-1"]["data_label"], "REAL")
        self.assertEqual(
            self.alerts["BEHAV-002-event-1"]["data_label"],
            "REAL",
        )

    def test_behaviour_evidence_is_kept_without_principals(self):
        evidence = self.alerts["BEHAV-002-event-1"]["evidence"]

        self.assertEqual(evidence["event_count"], 3)
        self.assertEqual(len(evidence["events"]), 3)
        self.assertNotIn("principal_email", evidence["events"][0])

    def test_plain_alerts_have_no_sequence_evidence(self):
        self.assertIsNone(self.alerts["audit-001"]["evidence"])

    def test_summary_counts(self):
        summary = self.report["summary"]

        self.assertEqual(summary["total_alerts"], 5)
        self.assertEqual(summary["behaviour_alerts"], 1)
        self.assertEqual(summary["severity"]["CRITICAL"], 2)
        self.assertEqual(summary["data_labels"], {"REAL": 3, "SYNTHETIC": 2})

    def test_mitre_coverage_is_included_and_marks_fired_rules(self):
        coverage = self.report["mitre_coverage"]
        tactics = {
            item["tactic_name"]: item for item in coverage["tactics"]
        }

        self.assertEqual(coverage["total_tactics"], 14)
        self.assertTrue(tactics["Collection"]["active"])
        self.assertTrue(tactics["Privilege Escalation"]["active"])
        self.assertFalse(tactics["Impact"]["active"])

    def test_tuned_alerts_are_published_without_match_conditions(self):
        alerts = make_alerts()
        alerts[3].update({
            "status": "SUPPRESSED",
            "disposition": "BENIGN_TRUE_POSITIVE",
            "tuning": {
                "tuning_id": "TUNE-001",
                "justification": "Authorised project setup.",
                "approved_by": "SOC analyst",
                "approved_on": "2026-11-20",
                "expires_on": "2027-02-20",
                "principal_sha256": "a" * 64,
            },
        })
        alerts[4].update({"status": "ROLLED_UP", "covered_by": "BEHAV-002-event-1"})

        report = build_public_report(alerts)
        published = {item["alert_id"]: item for item in report["alerts"]}
        summary = report["summary"]

        self.assertEqual(published["BEHAV-002-event-1"]["tuning"]["tuning_id"], "TUNE-001")
        self.assertNotIn("principal_sha256", published["BEHAV-002-event-1"]["tuning"])
        self.assertEqual(published["real-event-1"]["covered_by"], "BEHAV-002-event-1")
        self.assertEqual(summary["active_alerts"], 3)
        self.assertEqual(summary["suppressed_alerts"], 1)
        self.assertEqual(summary["rolled_up_alerts"], 1)
        self.assertNotIn("MEDIUM", summary["severity"])
        self.assertEqual(report["detection_quality"]["active_alerts"], 3)

    def test_behaviour_rule_catalogue_is_included(self):
        rule_ids = [
            rule["rule_id"] for rule in self.report["behaviour_rules"]
        ]
        self.assertEqual(rule_ids, ["BEHAV-001", "BEHAV-002", "BEHAV-003"])


class TestPublishFile(unittest.TestCase):

    def test_publish_writes_sanitised_website_file(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_file = directory / "consolidated.json"
            output_file = directory / "website" / "data" / "soc_alerts.json"

            input_file.write_text(
                json.dumps({"alerts": make_alerts()}),
                encoding="utf-8",
            )

            publish_website_data(input_file, output_file)

            text = output_file.read_text(encoding="utf-8")

        self.assertNotIn(REAL_EMAIL, text)
        self.assertEqual(json.loads(text)["summary"]["total_alerts"], 5)


if __name__ == "__main__":
    unittest.main()
