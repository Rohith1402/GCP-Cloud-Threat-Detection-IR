
import unittest

from detection.alert_classifier import (
    normalise_alert,
    deduplicate_alerts,
    classify_alerts,
    classify_severity,
    identify_gcp_rule,
    load_report_records
)


class TestAlertClassifier(unittest.TestCase):

    def test_normalise_scc_alert(self):
        alert = {
            "finding_id": "scc-001",
            "category": "PUBLIC_BUCKET_ACCESS",
            "priority": "CRITICAL",
            "risk_score": 100,
            "resource_name": "test-bucket",
            "description": "Public bucket access"
        }

        result = normalise_alert(alert, "scc_security_alerts")

        self.assertEqual(result["alert_id"], "scc-001")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["risk_score"], 100)

    def test_normalise_service_account_alert(self):
        alert = {
            "event_id": "sa-001",
            "event_type": "SERVICE_ACCOUNT_KEY_CREATED",
            "severity": "MEDIUM",
            "risk_score": 50,
            "service_account": "test@example.com"
        }

        result = normalise_alert(alert, "service_account_alerts")

        self.assertEqual(result["alert_id"], "sa-001")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(
            result["principal_or_resource"],
            "test@example.com"
        )
        self.assertEqual(result["rule_id"], "GCP-IAM-002")

    def test_invalid_risk_score(self):
        alert = {
            "event_id": "test-001",
            "severity": "HIGH",
            "risk_score": "invalid"
        }

        result = normalise_alert(alert, "test_report")

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity"], "LOW")

    def test_risk_score_bounds(self):
        high_alert = normalise_alert(
            {"event_id": "test-002", "risk_score": 150},
            "test_report"
        )

        low_alert = normalise_alert(
            {"event_id": "test-003", "risk_score": -10},
            "test_report"
        )

        self.assertEqual(high_alert["risk_score"], 100)
        self.assertEqual(high_alert["severity"], "CRITICAL")

        self.assertEqual(low_alert["risk_score"], 0)
        self.assertEqual(low_alert["severity"], "LOW")

    def test_duplicate_alert_removal(self):
        alerts = [
            {
                "source_module": "iam",
                "alert_id": "alert-001",
                "risk_score": 40
            },
            {
                "source_module": "iam",
                "alert_id": "alert-001",
                "risk_score": 70
            }
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk_score"], 70)

    def test_alerts_sorted_by_priority(self):
        alerts = [
            {
                "source_module": "test",
                "alert_id": "low",
                "severity": "LOW",
                "risk_score": 20
            },
            {
                "source_module": "test",
                "alert_id": "critical",
                "severity": "CRITICAL",
                "risk_score": 90
            },
            {
                "source_module": "test",
                "alert_id": "medium",
                "severity": "MEDIUM",
                "risk_score": 50
            }
        ]

        result, summary = classify_alerts(alerts)

        self.assertEqual(result[0]["alert_id"], "critical")
        self.assertEqual(result[1]["alert_id"], "medium")
        self.assertEqual(result[2]["alert_id"], "low")

        self.assertEqual(summary["CRITICAL"], 1)
        self.assertEqual(summary["MEDIUM"], 1)
        self.assertEqual(summary["LOW"], 1)

    def test_duplicate_alerts_from_different_sources(self):
        alerts = [
            {
                "source_module": "iam",
                "alert_id": "alert-001",
                "severity": "HIGH",
                "risk_score": 80
            },
            {
                "source_module": "audit",
                "alert_id": "alert-001",
                "severity": "MEDIUM",
                "risk_score": 40
            }
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 2)

    def test_risk_based_severity_classification(self):
        self.assertEqual(classify_severity(100), "CRITICAL")
        self.assertEqual(classify_severity(90), "CRITICAL")
        self.assertEqual(classify_severity(89), "HIGH")
        self.assertEqual(classify_severity(70), "HIGH")
        self.assertEqual(classify_severity(69), "MEDIUM")
        self.assertEqual(classify_severity(30), "MEDIUM")
        self.assertEqual(classify_severity(29), "LOW")
        self.assertEqual(classify_severity(0), "LOW")


class TestPhase2DetectionRules(unittest.TestCase):

    def test_iam_policy_modification_rule(self):
        rule_id, rule = identify_gcp_rule(
            method_name="SetIamPolicy"
        )

        self.assertEqual(rule_id, "GCP-IAM-001")
        self.assertEqual(rule["risk_score"], 80)
        self.assertEqual(rule["mitre_id"], "T1098.003")

    def test_service_account_key_creation_rule(self):
        rule_id, rule = identify_gcp_rule(
            method_name="CreateServiceAccountKey"
        )

        self.assertEqual(rule_id, "GCP-IAM-002")
        self.assertEqual(rule["risk_score"], 90)
        self.assertEqual(rule["mitre_id"], "T1098.001")

    def test_service_account_key_deletion_rule(self):
        rule_id, rule = identify_gcp_rule(
            method_name="DeleteServiceAccountKey"
        )

        self.assertEqual(rule_id, "GCP-IAM-003")
        self.assertEqual(rule["risk_score"], 70)
        self.assertEqual(rule["mitre_id"], "T1531")

    def test_service_account_creation_rule(self):
        rule_id, rule = identify_gcp_rule(
            method_name="CreateServiceAccount"
        )

        self.assertEqual(rule_id, "GCP-IAM-004")
        self.assertEqual(rule["risk_score"], 40)

    def test_privileged_role_assignment_rule(self):
        alert = {
            "role": "roles/owner",
            "findings": ["Privileged role assigned: roles/owner"]
        }

        result = normalise_alert(
            alert,
            "iam_security_alerts"
        )

        self.assertEqual(result["rule_id"], "GCP-IAM-005")
        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["mitre_technique_id"], "T1098.003")

    def test_sensitive_iam_permissions_rule(self):
        alert = {
            "role": "roles/owner",
            "risk_score": 100,
            "risky_permissions": [
                "iam.serviceAccounts.actAs",
                "iam.serviceAccounts.getAccessToken",
                "iam.serviceAccountKeys.create",
                "resourcemanager.projects.setIamPolicy"
            ]
        }

        result = normalise_alert(
            alert,
            "iam_privilege_alerts"
        )

        self.assertEqual(result["rule_id"], "GCP-IAM-006")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["confidence"], "MEDIUM")

    def test_public_bucket_rule(self):
        rule_id, rule = identify_gcp_rule(
            category="PUBLIC_BUCKET_ACCESS"
        )

        self.assertEqual(rule_id, "GCP-SCC-001")
        self.assertEqual(rule["risk_score"], 100)

    def test_over_privileged_iam_rule(self):
        rule_id, rule = identify_gcp_rule(
            category="OVER_PRIVILEGED_IAM"
        )

        self.assertEqual(rule_id, "GCP-SCC-002")
        self.assertEqual(rule["risk_score"], 90)

    def test_critical_vulnerability_rule(self):
        rule_id, rule = identify_gcp_rule(
            category="CRITICAL_VULNERABILITY"
        )

        self.assertEqual(rule_id, "GCP-SCC-003")
        self.assertEqual(rule["risk_score"], 85)

    def test_suspicious_network_activity_rule(self):
        rule_id, rule = identify_gcp_rule(
            category="SUSPICIOUS_NETWORK_ACTIVITY"
        )

        self.assertEqual(rule_id, "GCP-SCC-004")
        self.assertEqual(rule["risk_score"], 55)

    def test_unusual_network_activity_alias(self):
        rule_id, rule = identify_gcp_rule(
            category="UNUSUAL_NETWORK_ACTIVITY"
        )

        self.assertEqual(rule_id, "GCP-SCC-004")
        self.assertEqual(rule["risk_score"], 55)

    def test_service_account_multiple_authentication_failures(self):
        alert = {
            "event_type": "SERVICE_ACCOUNT_AUTHENTICATION",
            "description": "Multiple failed authentication attempts: 5"
        }

        result = normalise_alert(
            alert,
            "service_account_alerts"
        )

        self.assertEqual(result["rule_id"], "GCP-SA-001")
        self.assertEqual(result["risk_score"], 60)

    def test_single_authentication_failure_does_not_match_repeated_rule(self):
        alert = {
            "event_type": "SERVICE_ACCOUNT_AUTHENTICATION",
            "description": "Service account authentication failed"
        }

        result = normalise_alert(
            alert,
            "service_account_alerts"
        )

        self.assertEqual(result["rule_id"], "GENERAL-001")

    def test_out_of_hours_authentication_does_not_match_failure_rule(self):
        alert = {
            "event_type": "SERVICE_ACCOUNT_AUTHENTICATION",
            "description": "Authentication outside configured normal hours",
            "risk_score": 30
        }

        result = normalise_alert(
            alert,
            "service_account_alerts"
        )

        self.assertEqual(result["rule_id"], "GENERAL-001")
        self.assertEqual(result["risk_score"], 30)

    def test_unknown_gcp_event_has_no_specific_rule(self):
        rule_id, rule = identify_gcp_rule(
            method_name="GetOperation"
        )

        self.assertIsNone(rule_id)
        self.assertIsNone(rule)

    def test_gcp_alert_has_detection_metadata(self):
        alert = normalise_alert(
            {
                "event_id": "test-key-001",
                "method_name": "CreateServiceAccountKey",
                "service_name": "iam.googleapis.com"
            },
            "gcp_audit_logs"
        )

        self.assertEqual(alert["rule_id"], "GCP-IAM-002")
        self.assertEqual(alert["confidence"], "MEDIUM")
        self.assertEqual(
            alert["detection_status"],
            "REQUIRES_INVESTIGATION"
        )
        self.assertIn("recommendation", alert)
        self.assertIn("evidence", alert)

    def test_json_object_report_is_supported(self):
        report = {
            "timestamp": "2026-11-15T16:19:46Z",
            "risk_score": 100,
            "finding": "Sensitive IAM capabilities detected"
        }

        records = load_report_records(report)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["risk_score"], 100)

    def test_json_array_report_is_supported(self):
        report = [
            {"event_id": "one"},
            {"event_id": "two"}
        ]

        records = load_report_records(report)

        self.assertEqual(len(records), 2)


class TestGCPAuditLogDeduplication(unittest.TestCase):

    def test_same_event_id_from_same_source_is_deduplicated(self):
        alerts = [
            normalise_alert(
                {
                    "event_id": "gcp-event-001",
                    "method_name": "GetOperation",
                    "risk_score": 20
                },
                "gcp_audit_logs"
            ),
            normalise_alert(
                {
                    "event_id": "gcp-event-001",
                    "method_name": "CreateServiceAccountKey",
                    "risk_score": 90
                },
                "gcp_audit_logs"
            )
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["alert_id"], "gcp-event-001")
        self.assertEqual(result[0]["risk_score"], 90)

    def test_different_event_ids_with_same_timestamp_are_preserved(self):
        common_fields = {
            "timestamp": "2026-11-15T14:43:48.113521+00:00",
            "method_name": "EnableService",
            "service_name": "serviceusage.googleapis.com"
        }

        alerts = [
            normalise_alert(
                {**common_fields, "event_id": "gcp-event-002"},
                "gcp_audit_logs"
            ),
            normalise_alert(
                {**common_fields, "event_id": "gcp-event-003"},
                "gcp_audit_logs"
            )
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 2)
        self.assertEqual(
            {alert["alert_id"] for alert in result},
            {"gcp-event-002", "gcp-event-003"}
        )

    def test_same_event_id_from_different_sources_is_preserved(self):
        alerts = [
            normalise_alert(
                {"event_id": "gcp-event-004", "risk_score": 80},
                "gcp_audit_logs"
            ),
            normalise_alert(
                {"event_id": "gcp-event-004", "risk_score": 40},
                "iam_security_alerts"
            )
        ]

        result = deduplicate_alerts(alerts)

        self.assertEqual(len(result), 2)
        self.assertEqual(
            {alert["source_module"] for alert in result},
            {"gcp_audit_logs", "iam_security_alerts"}
        )


if __name__ == "__main__":
    unittest.main()
