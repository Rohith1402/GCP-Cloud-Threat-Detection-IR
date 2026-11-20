import json
import tempfile
import unittest

from datetime import date
from pathlib import Path

from detection.alert_tuning import (
    apply_tuning,
    build_quality_report,
    hash_principal,
    load_tuning_rules,
    rule_matches,
    validate_rule,
)
from detection.incident_response import generate_response_plan


TODAY = date(2026, 11, 20)
OWNER = "owner@example.com"


def make_rule(**overrides):
    rule = {
        "id": "TUNE-TEST",
        "rule_id": "BEHAV-002",
        "disposition": "BENIGN_TRUE_POSITIVE",
        "justification": "Project setup by the owner.",
        "approved_by": "SOC analyst",
        "approved_on": "2026-11-20",
        "expires_on": "2027-02-20",
        "match": {
            "principal_sha256": hash_principal(OWNER),
            "first_seen_after": "2026-11-15T14:00:00Z",
            "first_seen_before": "2026-11-15T15:00:00Z",
            "methods": ["EnableService"],
        },
    }
    rule.update(overrides)
    return rule


def behaviour_alert(principal=OWNER, first_seen="2026-11-15T14:43:46+00:00", methods=None):
    methods = methods or ["google.api.serviceusage.v1.ServiceUsage.EnableService"] * 2

    return {
        "alert_id": "BEHAV-002-evt-1",
        "rule_id": "BEHAV-002",
        "source_module": "gcp_behaviour_alerts",
        "principal_or_resource": principal,
        "severity": "MEDIUM",
        "risk_score": 55,
        "evidence": {
            "first_seen": first_seen,
            "events": [
                {"event_id": f"evt-{i + 1}", "method_name": method}
                for i, method in enumerate(methods)
            ],
        },
    }


def raw_event(event_id):
    return {
        "alert_id": event_id,
        "rule_id": "GENERAL-001",
        "source_module": "gcp_audit_logs",
        "principal_or_resource": OWNER,
        "severity": "LOW",
        "risk_score": 20,
        "evidence": {"method": "EnableService"},
    }


class TestHashing(unittest.TestCase):

    def test_hash_is_stable_across_prefix_and_case(self):
        self.assertEqual(
            hash_principal("user:Owner@Example.com"),
            hash_principal(OWNER),
        )
        self.assertEqual(len(hash_principal(OWNER)), 64)

    def test_unknown_principal_has_no_hash(self):
        self.assertIsNone(hash_principal("unknown"))


class TestRuleValidation(unittest.TestCase):

    def test_valid_rule(self):
        self.assertEqual(validate_rule(make_rule()), [])

    def test_missing_expiry_is_rejected(self):
        self.assertIn("missing expires_on", validate_rule(make_rule(expires_on="")))

    def test_unknown_disposition_is_rejected(self):
        self.assertIn("unknown disposition", validate_rule(make_rule(disposition="IGNORE")))

    def test_email_in_approver_is_rejected(self):
        problems = validate_rule(make_rule(approved_by="someone@gmail.com"))
        self.assertIn("approved_by must not contain an email address", problems)

    def test_plain_email_instead_of_hash_is_rejected(self):
        rule = make_rule()
        rule["match"]["principal_sha256"] = OWNER
        self.assertIn(
            "principal_sha256 must be a SHA-256 hex digest",
            validate_rule(rule),
        )

    def test_empty_match_is_rejected(self):
        self.assertIn(
            "missing match",
            validate_rule(make_rule(match={})),
        )

    def test_invalid_rules_are_skipped_when_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tuning.json"
            path.write_text(json.dumps({
                "rules": [make_rule(), make_rule(id="BAD", expires_on="")]
            }), encoding="utf-8")

            rules = load_tuning_rules(path)

        self.assertEqual([rule["id"] for rule in rules], ["TUNE-TEST"])

    def test_missing_or_malformed_file_gives_no_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = load_tuning_rules(Path(directory) / "none.json")

            broken = Path(directory) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            malformed = load_tuning_rules(broken)

        self.assertEqual(missing, [])
        self.assertEqual(malformed, [])

    def test_committed_tuning_file_is_valid_and_has_no_emails(self):
        path = Path(__file__).resolve().parent.parent / "config" / "alert_tuning.json"
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)

        self.assertNotIn("@", text)
        for rule in data["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertEqual(validate_rule(rule), [])


class TestMatching(unittest.TestCase):

    def test_matching_alert(self):
        self.assertTrue(rule_matches(behaviour_alert(), make_rule(), TODAY))

    def test_other_principal_does_not_match(self):
        self.assertFalse(rule_matches(behaviour_alert(principal="other@example.com"), make_rule(), TODAY))

    def test_outside_time_window_does_not_match(self):
        alert = behaviour_alert(first_seen="2026-11-16T14:43:46+00:00")
        self.assertFalse(rule_matches(alert, make_rule(), TODAY))

    def test_other_method_in_evidence_does_not_match(self):
        alert = behaviour_alert(methods=["EnableService", "SetIamPolicy"])
        self.assertFalse(rule_matches(alert, make_rule(), TODAY))

    def test_other_rule_does_not_match(self):
        alert = dict(behaviour_alert(), rule_id="BEHAV-001")
        self.assertFalse(rule_matches(alert, make_rule(), TODAY))

    def test_expired_rule_stops_matching(self):
        rule = make_rule(expires_on="2026-11-19")
        self.assertFalse(rule_matches(behaviour_alert(), rule, TODAY))


class TestApplyTuning(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            raw_event("evt-1"),
            behaviour_alert(),
            raw_event("evt-2"),
            raw_event("unrelated"),
        ]
        self.results = {
            alert["alert_id"]: alert
            for alert in apply_tuning(self.alerts, [make_rule()], TODAY)
        }

    def test_matched_alert_is_suppressed_with_justification(self):
        alert = self.results["BEHAV-002-evt-1"]

        self.assertEqual(alert["status"], "SUPPRESSED")
        self.assertEqual(alert["disposition"], "BENIGN_TRUE_POSITIVE")
        self.assertEqual(alert["tuning"]["tuning_id"], "TUNE-TEST")
        self.assertEqual(alert["tuning"]["expires_on"], "2027-02-20")

    def test_covered_raw_events_are_rolled_up(self):
        for event_id in ("evt-1", "evt-2"):
            with self.subTest(event=event_id):
                self.assertEqual(self.results[event_id]["status"], "ROLLED_UP")
                self.assertEqual(self.results[event_id]["covered_by"], "BEHAV-002-evt-1")

    def test_unrelated_alerts_stay_open_and_unreviewed(self):
        alert = self.results["unrelated"]

        self.assertEqual(alert["status"], "OPEN")
        self.assertEqual(alert["disposition"], "UNREVIEWED")
        self.assertIsNone(alert["tuning"])

    def test_nothing_is_deleted_and_active_alerts_come_first(self):
        ordered = apply_tuning(self.alerts, [make_rule()], TODAY)

        self.assertEqual(len(ordered), len(self.alerts))
        self.assertEqual(
            [alert["status"] for alert in ordered],
            ["OPEN", "SUPPRESSED", "ROLLED_UP", "ROLLED_UP"],
        )

    def test_input_alerts_are_not_modified(self):
        self.assertNotIn("status", self.alerts[1])

    def test_raw_events_with_their_own_rule_are_never_rolled_up(self):
        detected = dict(raw_event("evt-1"), rule_id="GCP-IAM-001", severity="HIGH")
        results = {
            alert["alert_id"]: alert
            for alert in apply_tuning([detected, behaviour_alert()], [], TODAY)
        }

        self.assertEqual(results["evt-1"]["status"], "OPEN")
        self.assertIsNone(results["evt-1"]["covered_by"])

    def test_roll_up_applies_without_tuning_rules(self):
        results = {
            alert["alert_id"]: alert
            for alert in apply_tuning(self.alerts, [], TODAY)
        }

        self.assertEqual(results["BEHAV-002-evt-1"]["status"], "OPEN")
        self.assertEqual(results["evt-1"]["status"], "ROLLED_UP")


class TestQualityReport(unittest.TestCase):

    def test_per_rule_counts_and_noise_rate(self):
        alerts = apply_tuning(
            [raw_event("evt-1"), behaviour_alert(), raw_event("unrelated")],
            [make_rule()],
            TODAY,
        )
        report = build_quality_report(alerts, [make_rule()], TODAY)
        rules = {item["rule_id"]: item for item in report["rules"]}

        self.assertEqual(report["active_alerts"], 1)
        self.assertEqual(report["suppressed_alerts"], 1)
        self.assertEqual(report["rolled_up_alerts"], 1)
        self.assertEqual(rules["BEHAV-002"]["benign_true_positive"], 1)
        self.assertEqual(rules["BEHAV-002"]["noise_rate"], 1.0)
        self.assertEqual(rules["GENERAL-001"]["noise_rate"], 0.5)

    def test_tuning_rule_expiry_states(self):
        rules = [
            make_rule(id="ACTIVE"),
            make_rule(id="SOON", expires_on="2026-11-30"),
            make_rule(id="OLD", expires_on="2026-11-01"),
        ]
        states = {
            item["tuning_id"]: item["state"]
            for item in build_quality_report([], rules, TODAY)["tuning_rules"]
        }

        self.assertEqual(states, {
            "ACTIVE": "ACTIVE",
            "SOON": "EXPIRING_SOON",
            "OLD": "EXPIRED",
        })


class TestIncidentResponseSkipsTunedAlerts(unittest.TestCase):

    def test_suppressed_and_rolled_up_alerts_open_no_incidents(self):
        alerts = [
            {"alert_id": "open-1", "severity": "CRITICAL", "status": "OPEN"},
            {"alert_id": "sup-1", "severity": "CRITICAL", "status": "SUPPRESSED"},
            {"alert_id": "roll-1", "severity": "HIGH", "status": "ROLLED_UP"},
            {"alert_id": "legacy-1", "severity": "HIGH"},
        ]

        incidents = generate_response_plan(alerts)

        self.assertEqual(
            sorted(item["alert_id"] for item in incidents),
            ["legacy-1", "open-1"],
        )


if __name__ == "__main__":
    unittest.main()
