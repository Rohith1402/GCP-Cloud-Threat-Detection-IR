"""
End-to-end pipeline test.

Runs every pipeline stage in a temporary folder on a simulated
scenario and checks the result at each hand-off:

audit events -> event correlation -> behaviour detection
-> SOC classifier (rules, MITRE, priority, tuning)
-> incident response -> sanitised website data

All identities are fictional example.com accounts and all events are
labelled SIMULATED.
"""

import json
import tempfile
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from detection import alert_classifier
from detection import event_correlation
from detection import publish_website_data
from detection.alert_tuning import hash_principal
from detection.behaviour_alert_integration import main as run_behaviour
from detection.incident_response import generate_response_plan


START = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
ATTACKER = "attacker@example.com"
OWNER = "owner@example.com"


def event(event_id, minutes, method, principal, service="iam.googleapis.com"):
    return {
        "event_id": event_id,
        "timestamp": (START + timedelta(minutes=minutes)).isoformat(),
        "severity": "NOTICE",
        "method_name": method,
        "service_name": service,
        "principal_email": principal,
        "resource_name": "projects/simulated-lab/serviceAccounts/sa",
        "status": {},
        "source": "SIMULATED_E2E_SCENARIO",
    }


def scenario_events():
    attack = [
        event("atk-1", 0, "google.iam.admin.v1.CreateServiceAccount", ATTACKER),
        event("atk-2", 5, "google.iam.admin.v1.CreateServiceAccountKey", ATTACKER),
        event("atk-3", 6, "SetIamPolicy", ATTACKER),
        event("atk-4", 8, "SetIamPolicy", ATTACKER),
        event("atk-5", 10, "SetIamPolicy", ATTACKER),
    ]
    setup = [
        event(
            f"setup-{i}",
            120 + i,
            "google.api.serviceusage.v1.ServiceUsage.EnableService",
            OWNER,
            service="serviceusage.googleapis.com",
        )
        for i in range(3)
    ]
    background = [
        event(
            "bg-1",
            200,
            "google.longrunning.Operations.GetOperation",
            OWNER,
            service="serviceusage.googleapis.com",
        )
    ]
    return attack + setup + background


def discovery_events():
    methods = [
        "google.iam.admin.v1.ListServiceAccounts",
        "google.iam.admin.v1.GetServiceAccount",
        "google.iam.admin.v1.ListServiceAccountKeys",
        "google.iam.admin.v1.GetServiceAccount",
        "google.iam.admin.v1.ListServiceAccountKeys",
        "google.iam.admin.v1.GetServiceAccountKey",
    ]
    return [
        event(f"disc-{i}", -5 + i * 0.5, method, ATTACKER)
        for i, method in enumerate(methods)
    ]


def tuning_rules():
    return {
        "rules": [{
            "id": "TUNE-E2E",
            "rule_id": "BEHAV-002",
            "disposition": "BENIGN_TRUE_POSITIVE",
            "justification": "Simulated authorised project setup.",
            "approved_by": "E2E test analyst",
            "approved_on": "2026-11-18",
            "expires_on": "2099-01-01",
            "match": {
                "principal_sha256": hash_principal(OWNER),
                "methods": ["EnableService"],
            },
        }]
    }


class TestEndToEndPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)

        audit_file = root / "gcp_audit_logs.json"
        data_access_file = root / "gcp_data_access_logs.json"
        correlation_file = root / "gcp_event_correlations.json"
        behaviour_file = root / "gcp_behaviour_alerts.json"
        tuning_file = root / "alert_tuning.json"
        consolidated_file = root / "consolidated_soc_alerts.json"
        website_file = root / "website" / "data" / "soc_alerts.json"

        audit_file.write_text(json.dumps(scenario_events()), encoding="utf-8")
        data_access_file.write_text(json.dumps(discovery_events()), encoding="utf-8")
        tuning_file.write_text(json.dumps(tuning_rules()), encoding="utf-8")

        # Stage 1: event correlation.
        with mock.patch.object(event_correlation, "INPUT_FILE", audit_file), \
                mock.patch.object(event_correlation, "OUTPUT_DIR", root), \
                mock.patch.object(event_correlation, "OUTPUT_FILE", correlation_file):
            event_correlation.main()

        # Stage 2: behaviour detection.
        run_behaviour(audit_file, behaviour_file, data_access_file)

        # Stage 3: SOC classifier (rules, MITRE, priority, tuning).
        original_loader = alert_classifier.load_correlation_records

        with mock.patch.object(alert_classifier, "REPORT_FILES", [audit_file]), \
                mock.patch.object(alert_classifier, "OUTPUT_FILE", consolidated_file), \
                mock.patch.object(alert_classifier, "BEHAVIOUR_REPORT_FILE", behaviour_file), \
                mock.patch.object(alert_classifier, "TUNING_FILE", tuning_file), \
                mock.patch.object(
                    alert_classifier,
                    "load_correlation_records",
                    side_effect=lambda *args: original_loader(correlation_file),
                ):
            alert_classifier.main()

        cls.correlations = json.loads(correlation_file.read_text(encoding="utf-8"))
        cls.behaviour = json.loads(behaviour_file.read_text(encoding="utf-8"))
        cls.report = json.loads(consolidated_file.read_text(encoding="utf-8"))
        cls.alerts = cls.report["alerts"]

        # Stage 4: incident response.
        cls.incidents = generate_response_plan(cls.alerts)

        # Stage 5: sanitised website data.
        tuning = json.loads(tuning_file.read_text(encoding="utf-8"))["rules"]

        with mock.patch.object(publish_website_data, "load_tuning_rules", return_value=tuning):
            publish_website_data.main(consolidated_file, website_file)

        cls.website_text = website_file.read_text(encoding="utf-8")
        cls.website = json.loads(cls.website_text)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def rules(self, status=None):
        return {
            alert["rule_id"]
            for alert in self.alerts
            if status is None or alert["status"] == status
        }

    # Stage 1 and 2: detection engines

    def test_correlation_engine_finds_attack_sequences(self):
        found = {item["rule_id"] for item in self.correlations["correlations"]}
        self.assertTrue({"CORR-001", "CORR-002", "CORR-003"} <= found)

    def test_behaviour_engine_finds_attack_and_discovery_patterns(self):
        self.assertEqual(
            set(self.behaviour["rule_summary"]),
            {"BEHAV-001", "BEHAV-002", "BEHAV-003", "BEHAV-004"},
        )

    def test_discovery_reads_do_not_become_individual_alerts(self):
        self.assertFalse(
            any(alert["alert_id"].startswith("disc-") for alert in self.alerts)
        )

    # Stage 3: classifier

    def test_all_detection_sources_reach_the_consolidated_report(self):
        self.assertEqual(
            set(self.report["source_summary"]),
            {"gcp_audit_logs", "gcp_event_correlations", "gcp_behaviour_alerts"},
        )
        self.assertEqual(self.report["total_alerts"], len(self.alerts))

    def test_every_alert_is_enriched(self):
        for alert in self.alerts:
            with self.subTest(alert=alert["alert_id"]):
                self.assertIn(alert["priority"], {"P1", "P2", "P3", "P4"})
                self.assertTrue(alert["score_factors"])
                self.assertIn("mitre_tactics", alert)
                self.assertIn(alert["status"], {"OPEN", "SUPPRESSED", "ROLLED_UP"})

    def test_attack_alerts_carry_mitre_techniques(self):
        techniques = {
            alert["rule_id"]: alert["mitre_technique_id"]
            for alert in self.alerts
        }
        self.assertEqual(techniques["CORR-002"], "T1098.003")
        self.assertEqual(techniques["BEHAV-001"], "T1098")
        self.assertEqual(techniques["GCP-IAM-002"], "T1098.001")

    def test_attacker_alerts_are_boosted_by_multiple_signals(self):
        attack = [
            alert for alert in self.alerts
            if alert["principal_or_resource"] == ATTACKER
            and alert["rule_id"] != "GENERAL-001"
        ]
        self.assertTrue(attack)
        for alert in attack:
            with self.subTest(alert=alert["alert_id"]):
                factors = [item["factor"] for item in alert["score_factors"]]
                self.assertIn("Multiple signals", factors)

    def test_authorised_setup_is_suppressed_not_deleted(self):
        setup = [a for a in self.alerts if a["rule_id"] == "BEHAV-002"]

        self.assertEqual(len(setup), 1)
        self.assertEqual(setup[0]["status"], "SUPPRESSED")
        self.assertEqual(setup[0]["disposition"], "BENIGN_TRUE_POSITIVE")
        self.assertEqual(setup[0]["tuning"]["tuning_id"], "TUNE-E2E")

    def test_generic_setup_events_are_rolled_up(self):
        rolled = [a for a in self.alerts if a["status"] == "ROLLED_UP"]

        self.assertEqual(len(rolled), 3)
        for alert in rolled:
            with self.subTest(alert=alert["alert_id"]):
                self.assertEqual(alert["rule_id"], "GENERAL-001")
                self.assertTrue(alert["covered_by"].startswith("BEHAV-002"))

    def test_detected_attack_events_stay_active(self):
        raw_attack = [
            alert for alert in self.alerts
            if alert["source_module"] == "gcp_audit_logs"
            and alert["alert_id"].startswith("atk-")
        ]
        self.assertEqual(len(raw_attack), 5)
        for alert in raw_attack:
            with self.subTest(alert=alert["alert_id"]):
                self.assertEqual(alert["status"], "OPEN")

    def test_unrelated_background_event_stays_active(self):
        background = next(a for a in self.alerts if a["alert_id"] == "bg-1")
        self.assertEqual(background["status"], "OPEN")

    def test_active_alerts_are_listed_first(self):
        statuses = [alert["status"] for alert in self.alerts]
        first_tuned = statuses.index("SUPPRESSED")
        self.assertTrue(all(s == "OPEN" for s in statuses[:first_tuned]))

    def test_report_counts_are_consistent(self):
        quality = self.report["detection_quality"]
        self.assertEqual(
            quality["active_alerts"] + quality["suppressed_alerts"] + quality["rolled_up_alerts"],
            self.report["total_alerts"],
        )
        self.assertEqual(self.report["active_alert_count"], quality["active_alerts"])

    # Stage 4: incident response

    def test_incidents_only_for_active_critical_and_high_alerts(self):
        expected = {
            alert["alert_id"]
            for alert in self.alerts
            if alert["status"] == "OPEN"
            and alert["severity"] in {"CRITICAL", "HIGH"}
        }
        self.assertTrue(expected)
        self.assertEqual({item["alert_id"] for item in self.incidents}, expected)

    def test_incident_response_stays_simulation_only(self):
        for incident in self.incidents:
            with self.subTest(incident=incident["incident_id"]):
                self.assertEqual(incident["execution_mode"], "SIMULATION_ONLY")
                self.assertEqual(incident["status"], "PENDING_ANALYST_APPROVAL")

    # Stage 5: website data

    def test_website_data_matches_pipeline(self):
        summary = self.website["summary"]
        self.assertEqual(summary["total_alerts"], self.report["total_alerts"])
        self.assertEqual(summary["active_alerts"], self.report["active_alert_count"])
        self.assertEqual(summary["suppressed_alerts"], 1)
        self.assertEqual(summary["rolled_up_alerts"], 3)

    def test_website_data_is_sanitised(self):
        self.assertNotIn("simulated-lab", self.website_text)
        self.assertNotIn("projects/", self.website_text)
        self.assertNotIn(hash_principal(OWNER), self.website_text)

    def test_website_data_labels_simulated_evidence(self):
        behaviour = [
            alert for alert in self.website["alerts"]
            if alert["source_module"] == "gcp_behaviour_alerts"
        ]
        self.assertTrue(behaviour)
        for alert in behaviour:
            with self.subTest(alert=alert["alert_id"]):
                self.assertEqual(alert["data_label"], "SIMULATED")

    def test_simulated_events_are_never_published_as_real(self):
        labels = {
            alert["source_module"]: set()
            for alert in self.website["alerts"]
        }
        for alert in self.website["alerts"]:
            labels[alert["source_module"]].add(alert["data_label"])

        for module, found in labels.items():
            with self.subTest(module=module):
                self.assertEqual(found, {"SIMULATED"})

    def test_website_coverage_marks_attack_tactics_active(self):
        tactics = {
            item["tactic_name"]: item
            for item in self.website["mitre_coverage"]["tactics"]
        }
        self.assertTrue(tactics["Persistence"]["active"])
        self.assertTrue(tactics["Privilege Escalation"]["active"])
        self.assertTrue(tactics["Discovery"]["active"])


if __name__ == "__main__":
    unittest.main()
