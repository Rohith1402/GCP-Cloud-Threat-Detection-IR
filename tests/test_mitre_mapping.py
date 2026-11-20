import re
import unittest

from detection.alert_classifier import (
    DETECTION_RULES,
    identify_gcp_rule,
    normalise_alert,
    normalise_behaviour_alert,
    normalise_correlation,
)
from detection.behaviour_anomaly_detector import RULES as BEHAVIOUR_RULES
from detection.mitre_mapping import (
    ENTERPRISE_TACTICS as TACTIC_ORDER,
    MITRE_MAPPINGS,
    UNMAPPED_RULES,
    build_coverage,
    coverage_markdown,
    get_mitre,
    mitre_fields,
)


TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

ENTERPRISE_TACTICS = {
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
}

CORRELATION_RULES = {"CORR-001", "CORR-002", "CORR-003"}


class TestMappingCatalogue(unittest.TestCase):

    def test_technique_ids_are_well_formed(self):
        for rule_id, mapping in MITRE_MAPPINGS.items():
            with self.subTest(rule=rule_id):
                self.assertRegex(mapping["technique_id"], TECHNIQUE_ID)
                self.assertTrue(mapping["technique_name"])

    def test_tactics_are_valid_enterprise_tactics(self):
        for rule_id, mapping in MITRE_MAPPINGS.items():
            with self.subTest(rule=rule_id):
                self.assertTrue(mapping["tactics"])
                self.assertTrue(set(mapping["tactics"]) <= ENTERPRISE_TACTICS)

    def test_every_rule_is_mapped_or_explicitly_unmapped(self):
        all_rules = (
            set(DETECTION_RULES)
            | CORRELATION_RULES
            | set(BEHAVIOUR_RULES)
            | {"GENERAL-001"}
        )
        decided = set(MITRE_MAPPINGS) | set(UNMAPPED_RULES)

        self.assertEqual(all_rules - decided, set())

    def test_no_rule_is_both_mapped_and_unmapped(self):
        self.assertEqual(set(MITRE_MAPPINGS) & set(UNMAPPED_RULES), set())

    def test_unmapped_rules_have_a_reason(self):
        for rule_id, reason in UNMAPPED_RULES.items():
            with self.subTest(rule=rule_id):
                self.assertTrue(reason.strip())

    def test_coverage_is_fourteen_of_eighteen_rules(self):
        self.assertEqual(len(MITRE_MAPPINGS), 14)
        self.assertEqual(len(UNMAPPED_RULES), 4)

    def test_behaviour_detector_agrees_with_mapping(self):
        for rule_id, rule in BEHAVIOUR_RULES.items():
            mapping = get_mitre(rule_id)
            expected = mapping["technique_id"] if mapping else None

            with self.subTest(rule=rule_id):
                self.assertEqual(rule["mitre_technique"], expected)

    def test_unknown_rule_returns_empty_fields(self):
        self.assertIsNone(get_mitre("NOT-A-RULE"))
        self.assertEqual(
            mitre_fields(None),
            {
                "mitre_technique_id": None,
                "mitre_technique_name": None,
                "mitre_tactics": [],
            },
        )

    def test_get_mitre_returns_a_copy(self):
        get_mitre("GCP-IAM-001")["tactics"].append("Impact")

        self.assertNotIn("Impact", MITRE_MAPPINGS["GCP-IAM-001"]["tactics"])


class TestClassifierUsesMapping(unittest.TestCase):

    def test_detection_rules_are_synced_with_mapping(self):
        for rule_id, rule in DETECTION_RULES.items():
            mapping = get_mitre(rule_id)

            with self.subTest(rule=rule_id):
                self.assertEqual(
                    rule["mitre_id"],
                    mapping["technique_id"] if mapping else None,
                )

    def test_new_rule_mappings(self):
        expected = {
            "SetIamPolicy": "T1098.003",
            "DeleteServiceAccountKey": "T1531",
            "CreateServiceAccount": "T1136.003",
        }

        for method, technique in expected.items():
            _, rule = identify_gcp_rule(method_name=method)

            with self.subTest(method=method):
                self.assertEqual(rule["mitre_id"], technique)

    def test_sensitive_permission_alert_maps_to_temporary_elevated_access(self):
        alert = {
            "principal": "user:test@example.com",
            "risky_permissions": ["iam.serviceAccounts.getAccessToken"],
            "risk_score": 100,
        }

        result = normalise_alert(alert, "iam_privilege_alerts")

        self.assertEqual(result["rule_id"], "GCP-IAM-006")
        self.assertEqual(result["mitre_technique_id"], "T1548.005")
        self.assertIn("Privilege Escalation", result["mitre_tactics"])

    def test_unmatched_alert_has_no_technique(self):
        result = normalise_alert(
            {"method_name": "google.longrunning.Operations.GetOperation"},
            "gcp_audit_logs",
        )

        self.assertEqual(result["rule_id"], "GENERAL-001")
        self.assertIsNone(result["mitre_technique_id"])
        self.assertEqual(result["mitre_tactics"], [])

    def test_correlation_alerts_now_carry_mitre(self):
        for rule_id in sorted(CORRELATION_RULES):
            result = normalise_correlation({
                "correlation_id": f"{rule_id}-test",
                "rule_id": rule_id,
                "risk_score": 85,
            })

            with self.subTest(rule=rule_id):
                self.assertEqual(
                    result["mitre_technique_id"],
                    MITRE_MAPPINGS[rule_id]["technique_id"],
                )
                self.assertTrue(result["mitre_tactics"])

    def test_behaviour_alerts_use_mapping(self):
        mapped = normalise_behaviour_alert({
            "alert_id": "BEHAV-001-x",
            "rule_id": "BEHAV-001",
            "risk_score": 70,
        })
        unmapped = normalise_behaviour_alert({
            "alert_id": "BEHAV-002-x",
            "rule_id": "BEHAV-002",
            "risk_score": 55,
        })

        self.assertEqual(mapped["mitre_technique_id"], "T1098")
        self.assertIsNone(unmapped["mitre_technique_id"])


class TestCoverageMatrix(unittest.TestCase):

    def setUp(self):
        self.coverage = build_coverage()
        self.tactics = {
            item["tactic_name"]: item for item in self.coverage["tactics"]
        }

    def test_all_fourteen_tactics_in_order(self):
        names = [item["tactic_name"] for item in self.coverage["tactics"]]

        self.assertEqual(len(names), 14)
        self.assertEqual(names, [name for _, name in TACTIC_ORDER])
        self.assertEqual(set(names), ENTERPRISE_TACTICS)

    def test_coverage_totals(self):
        self.assertEqual(self.coverage["covered_tactics"], 7)
        self.assertEqual(self.coverage["mapped_rules"], 14)
        self.assertEqual(self.coverage["total_rules"], 18)
        self.assertEqual(self.coverage["unique_techniques"], 9)

    def test_gaps_are_reported_as_uncovered(self):
        for tactic in ("Reconnaissance", "Discovery", "Exfiltration"):
            with self.subTest(tactic=tactic):
                self.assertFalse(self.tactics[tactic]["covered"])
                self.assertEqual(self.tactics[tactic]["techniques"], [])

    def test_every_mapped_rule_appears_under_each_of_its_tactics(self):
        for rule_id, mapping in MITRE_MAPPINGS.items():
            for tactic in mapping["tactics"]:
                rules = [
                    rule
                    for item in self.tactics[tactic]["techniques"]
                    for rule in item["rules"]
                ]
                with self.subTest(rule=rule_id, tactic=tactic):
                    self.assertIn(rule_id, rules)

    def test_techniques_are_not_duplicated_within_a_tactic(self):
        for tactic in self.coverage["tactics"]:
            ids = [item["technique_id"] for item in tactic["techniques"]]
            with self.subTest(tactic=tactic["tactic_name"]):
                self.assertEqual(len(ids), len(set(ids)))

    def test_fired_rules_mark_techniques_active(self):
        coverage = build_coverage({"GCP-SCC-001": 1})
        tactics = {item["tactic_name"]: item for item in coverage["tactics"]}

        self.assertTrue(tactics["Collection"]["active"])
        self.assertFalse(tactics["Impact"]["active"])
        self.assertEqual(coverage["active_tactics"], 1)

    def test_no_fired_rules_means_nothing_active(self):
        self.assertEqual(self.coverage["active_tactics"], 0)

    def test_unmapped_rules_listed_with_reasons(self):
        listed = {item["rule_id"] for item in self.coverage["unmapped_rules"]}
        self.assertEqual(listed, set(UNMAPPED_RULES))

    def test_markdown_has_one_row_per_tactic(self):
        rows = coverage_markdown(self.coverage).splitlines()

        self.assertEqual(len(rows), 2 + 14)
        self.assertIn("No coverage", coverage_markdown(self.coverage))


if __name__ == "__main__":
    unittest.main()
