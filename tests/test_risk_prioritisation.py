import json
import tempfile
import unittest

from pathlib import Path
from unittest import mock

from detection import alert_classifier
from detection.risk_prioritisation import (
    principal_key,
    prioritise_alerts,
    priority_band,
)


def make_alert(
    alert_id,
    rule_id,
    risk_score,
    principal="analyst@example.com",
    confidence="MEDIUM",
    tactics=None,
):
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "risk_score": risk_score,
        "severity": "MEDIUM",
        "principal_or_resource": principal,
        "confidence": confidence,
        "mitre_tactics": tactics or [],
    }


def by_id(alerts):
    return {alert["alert_id"]: alert for alert in alerts}


def factor_names(alert):
    return [item["factor"] for item in alert["score_factors"][1:]]


class TestPriorityBands(unittest.TestCase):

    def test_band_thresholds(self):
        self.assertEqual(priority_band(100), "P1")
        self.assertEqual(priority_band(90), "P1")
        self.assertEqual(priority_band(89), "P2")
        self.assertEqual(priority_band(70), "P2")
        self.assertEqual(priority_band(69), "P3")
        self.assertEqual(priority_band(40), "P3")
        self.assertEqual(priority_band(39), "P4")
        self.assertEqual(priority_band(0), "P4")


class TestPrincipalMatching(unittest.TestCase):

    def test_identity_prefixes_and_case_are_normalised(self):
        self.assertEqual(
            principal_key({"principal_or_resource": "user:Analyst@Example.com"}),
            "analyst@example.com",
        )
        self.assertEqual(
            principal_key({"principal_or_resource": "serviceAccount:sa@p.iam.gserviceaccount.com"}),
            "sa@p.iam.gserviceaccount.com",
        )

    def test_unknown_principal_is_ignored(self):
        self.assertIsNone(principal_key({"principal_or_resource": "unknown"}))
        self.assertIsNone(principal_key({}))


class TestScoringFactors(unittest.TestCase):

    def test_risk_score_and_severity_are_unchanged(self):
        alert = make_alert("a", "BEHAV-002", 55, confidence="LOW")

        result = prioritise_alerts([alert])[0]

        self.assertEqual(result["risk_score"], 55)
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertNotIn("priority", alert)

    def test_confidence_adjustments(self):
        results = by_id(prioritise_alerts([
            make_alert("high", "R-1", 50, principal="a@example.com", confidence="HIGH"),
            make_alert("medium", "R-2", 50, principal="b@example.com", confidence="MEDIUM"),
            make_alert("low", "R-3", 50, principal="c@example.com", confidence="LOW"),
        ]))

        self.assertEqual(results["high"]["priority_score"], 55)
        self.assertEqual(results["medium"]["priority_score"], 50)
        self.assertEqual(results["low"]["priority_score"], 40)

    def test_privileged_principal_boost(self):
        results = by_id(prioritise_alerts([
            make_alert("owner", "GCP-IAM-005", 50, principal="user:admin@example.com"),
            make_alert("behaviour", "BEHAV-002", 55, principal="admin@example.com", confidence="LOW"),
        ]))

        behaviour = results["behaviour"]

        self.assertIn("Privileged principal", factor_names(behaviour))
        self.assertIn("Multiple signals", factor_names(behaviour))
        self.assertEqual(behaviour["priority_score"], 65)
        self.assertEqual(behaviour["priority"], "P3")

    def test_privilege_finding_does_not_boost_itself(self):
        result = prioritise_alerts([
            make_alert("owner", "GCP-IAM-005", 50, principal="user:admin@example.com"),
        ])[0]

        self.assertNotIn("Privileged principal", factor_names(result))
        self.assertEqual(result["priority_score"], 50)

    def test_multiple_signals_need_two_different_rules(self):
        same_rule = prioritise_alerts([
            make_alert("a1", "GCP-IAM-001", 80, principal="x@example.com"),
            make_alert("a2", "GCP-IAM-001", 80, principal="x@example.com"),
        ])

        for alert in same_rule:
            self.assertNotIn("Multiple signals", factor_names(alert))

    def test_general_events_are_not_signals_and_get_no_boosts(self):
        results = by_id(prioritise_alerts([
            make_alert("rule", "GCP-IAM-001", 80, principal="x@example.com"),
            make_alert("general", "GENERAL-001", 20, principal="x@example.com", confidence="LOW"),
        ]))

        self.assertNotIn("Multiple signals", factor_names(results["rule"]))
        self.assertEqual(factor_names(results["general"]), ["Confidence"])
        self.assertEqual(results["general"]["priority_score"], 10)

    def test_high_impact_tactic_boost(self):
        results = by_id(prioritise_alerts([
            make_alert("pe", "R-1", 80, principal="a@example.com", tactics=["Persistence", "Privilege Escalation"]),
            make_alert("col", "R-2", 80, principal="b@example.com", tactics=["Collection"]),
        ]))

        self.assertEqual(results["pe"]["priority_score"], 85)
        self.assertEqual(results["col"]["priority_score"], 80)

    def test_score_is_capped_at_100_and_0(self):
        results = by_id(prioritise_alerts([
            make_alert("top", "GCP-IAM-006", 100, principal="a@example.com", confidence="HIGH", tactics=["Impact"]),
            make_alert("other", "GCP-IAM-001", 80, principal="a@example.com"),
            make_alert("bottom", "GENERAL-001", 5, principal="b@example.com", confidence="LOW"),
        ]))

        self.assertEqual(results["top"]["priority_score"], 100)
        self.assertEqual(results["bottom"]["priority_score"], 0)

    def test_every_alert_explains_its_score(self):
        alert = prioritise_alerts([
            make_alert("a", "BEHAV-002", 55, confidence="LOW"),
        ])[0]

        self.assertEqual(alert["score_factors"][0]["factor"], "Rule risk score")
        self.assertEqual(
            sum(item["adjustment"] for item in alert["score_factors"]),
            alert["priority_score"],
        )

    def test_invalid_risk_score_is_treated_as_zero(self):
        alert = prioritise_alerts([make_alert("bad", "R-1", "not-a-number")])[0]

        self.assertEqual(alert["priority_score"], 0)
        self.assertEqual(alert["priority"], "P4")

    def test_alerts_sorted_by_priority_then_risk(self):
        results = prioritise_alerts([
            make_alert("low", "R-1", 60, principal="a@example.com", confidence="LOW"),
            make_alert("high", "R-2", 55, principal="b@example.com", confidence="HIGH"),
            make_alert("tie", "R-3", 50, principal="c@example.com", confidence="LOW"),
        ])

        self.assertEqual(
            [alert["alert_id"] for alert in results],
            ["high", "low", "tie"],
        )


class TestClassifierReport(unittest.TestCase):

    def test_consolidated_report_includes_priorities(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_file = directory / "iam_privilege_alerts.json"
            output_file = directory / "consolidated.json"

            report_file.write_text(json.dumps([{
                "principal": "user:admin@example.com",
                "risky_permissions": ["iam.serviceAccounts.getAccessToken"],
                "risk_score": 100,
            }]), encoding="utf-8")

            with mock.patch.object(alert_classifier, "REPORT_FILES", [report_file]), \
                    mock.patch.object(alert_classifier, "OUTPUT_FILE", output_file), \
                    mock.patch.object(alert_classifier, "BEHAVIOUR_REPORT_FILE", directory / "none.json"), \
                    mock.patch.object(alert_classifier, "load_correlation_records", return_value=[]):
                alert_classifier.main()

            report = json.loads(output_file.read_text(encoding="utf-8"))

        alert = report["alerts"][0]

        self.assertEqual(report["priority_summary"], {"P1": 1})
        self.assertEqual(alert["rule_id"], "GCP-IAM-006")
        self.assertEqual(alert["risk_score"], 100)
        self.assertEqual(alert["priority"], "P1")
        self.assertTrue(alert["score_factors"])


if __name__ == "__main__":
    unittest.main()
