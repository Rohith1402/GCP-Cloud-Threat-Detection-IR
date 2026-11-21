import json
import os
import tempfile
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from detection import gcp_audit_log_collector as collector
from detection.behaviour_alert_integration import main as run_behaviour
from detection.behaviour_anomaly_detector import (
    RULES,
    detect_cloud_account_enumeration,
    detect_iam_permission_discovery,
)


START = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)
ANALYST = "analyst@example.com"


def read_event(event_id, seconds, method, principal=ANALYST, service="iam.googleapis.com", source="SIMULATED_TEST"):
    return {
        "event_id": event_id,
        "timestamp": (START + timedelta(seconds=seconds)).isoformat(),
        "method_name": method,
        "service_name": service,
        "principal_email": principal,
        "log_type": "DATA_ACCESS",
        "source": source,
    }


def account_enumeration(prefix="acct", principal=ANALYST, source="SIMULATED_TEST"):
    methods = [
        "google.iam.admin.v1.ListServiceAccounts",
        "google.iam.admin.v1.GetServiceAccount",
        "google.iam.admin.v1.ListServiceAccountKeys",
        "google.iam.admin.v1.GetServiceAccount",
        "google.iam.admin.v1.ListServiceAccountKeys",
        "google.iam.admin.v1.GetServiceAccountKey",
    ]
    return [
        read_event(f"{prefix}-{i}", i * 20, method, principal, source=source)
        for i, method in enumerate(methods)
    ]


def permission_discovery(prefix="perm"):
    methods = [
        "GetIamPolicy",
        "TestIamPermissions",
        "google.iam.admin.v1.QueryGrantableRoles",
        "google.iam.admin.v1.ListRoles",
        "GetIamPolicy",
        "google.iam.admin.v1.GetRole",
    ]
    return [
        read_event(f"{prefix}-{i}", i * 30, method, service="cloudresourcemanager.googleapis.com")
        for i, method in enumerate(methods)
    ]


class TestRuleDefinitions(unittest.TestCase):

    def test_discovery_rules_are_low_confidence_discovery(self):
        for rule_id, technique, breadth in (
            ("BEHAV-004", "T1087.004", 3),
            ("BEHAV-005", "T1069.003", 2),
        ):
            with self.subTest(rule=rule_id):
                rule = RULES[rule_id]
                self.assertEqual(rule["mitre_technique"], technique)
                self.assertEqual(rule["confidence"], "LOW")
                self.assertEqual(rule["threshold"], 6)
                self.assertEqual(rule["min_distinct_methods"], breadth)


class TestAccountEnumeration(unittest.TestCase):

    def test_broad_enumeration_fires(self):
        results = detect_cloud_account_enumeration(account_enumeration())

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "BEHAV-004")
        self.assertEqual(results[0]["event_count"], 6)
        self.assertEqual(results[0]["source"], "SIMULATED")

    def test_repeated_page_loads_do_not_fire(self):
        reloads = [
            read_event(f"reload-{i}", i * 10, "google.iam.admin.v1.ListServiceAccounts")
            for i in range(12)
        ]
        self.assertEqual(detect_cloud_account_enumeration(reloads), [])

    def test_two_methods_are_not_enough(self):
        events = [
            read_event(f"two-{i}", i * 10, method)
            for i, method in enumerate(["ListServiceAccounts", "GetServiceAccount"] * 4)
        ]
        self.assertEqual(detect_cloud_account_enumeration(events), [])

    def test_too_few_calls_do_not_fire(self):
        self.assertEqual(detect_cloud_account_enumeration(account_enumeration()[:5]), [])

    def test_activity_spread_beyond_window_does_not_fire(self):
        events = [
            dict(event, timestamp=(START + timedelta(minutes=i * 3)).isoformat())
            for i, event in enumerate(account_enumeration())
        ]
        self.assertEqual(detect_cloud_account_enumeration(events), [])

    def test_principals_are_evaluated_separately(self):
        events = account_enumeration()[:3] + account_enumeration("other", "other@example.com")[3:]
        self.assertEqual(detect_cloud_account_enumeration(events), [])

    def test_real_events_are_labelled_real(self):
        results = detect_cloud_account_enumeration(
            account_enumeration(source=collector.SOURCE_LABEL)
        )
        self.assertEqual(results[0]["source"], "REAL")

    def test_permission_queries_do_not_count_as_account_enumeration(self):
        self.assertEqual(detect_cloud_account_enumeration(permission_discovery()), [])


class TestPermissionDiscovery(unittest.TestCase):

    def test_broad_permission_discovery_fires(self):
        results = detect_iam_permission_discovery(permission_discovery())

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "BEHAV-005")
        self.assertEqual(results[0]["mitre_technique"], "T1069.003")

    def test_real_world_pattern_fires(self):
        """Replays the methods actually logged in the 21 Nov 2026 real test."""

        methods = [
            "GetIamPolicy",
            "google.iam.admin.v1.QueryGrantableRoles",
            "google.iam.admin.v1.QueryGrantableRoles",
        ] * 4
        events = [
            read_event(f"real-{i}", i * 8, method, service="iam.googleapis.com", source="gcp_cloud_audit_logs")
            for i, method in enumerate(methods)
        ]

        results = detect_iam_permission_discovery(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["event_count"], 12)
        self.assertEqual(results[0]["source"], "REAL")

    def test_two_methods_below_volume_do_not_fire(self):
        events = [
            read_event(f"low-{i}", i * 10, method)
            for i, method in enumerate(["GetIamPolicy", "QueryGrantableRoles"] * 2)
        ]
        self.assertEqual(detect_iam_permission_discovery(events), [])

    def test_repeated_policy_reads_do_not_fire(self):
        reads = [read_event(f"gip-{i}", i * 15, "GetIamPolicy") for i in range(10)]
        self.assertEqual(detect_iam_permission_discovery(reads), [])


class TestIntegration(unittest.TestCase):

    def test_data_access_file_feeds_discovery_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            audit_file = directory / "audit.json"
            data_access_file = directory / "data_access.json"
            output_file = directory / "behaviour.json"

            audit_file.write_text("[]", encoding="utf-8")
            data_access_file.write_text(
                json.dumps(account_enumeration() + permission_discovery()),
                encoding="utf-8",
            )

            report = run_behaviour(audit_file, output_file, data_access_file)

        self.assertEqual(report["rule_summary"], {"BEHAV-004": 1, "BEHAV-005": 1})

    def test_explicit_input_never_reads_default_data_access_file(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            audit_file = directory / "audit.json"
            audit_file.write_text("[]", encoding="utf-8")

            with mock.patch(
                "detection.behaviour_alert_integration.load_audit_events",
                wraps=lambda path: [],
            ) as loader:
                run_behaviour(audit_file, directory / "out.json")

        self.assertEqual(loader.call_count, 1)


class TestCollector(unittest.TestCase):

    def test_no_hardcoded_project_id(self):
        source = Path(collector.__file__).read_text(encoding="utf-8")
        self.assertNotIn("PROJECT_ID = \"", source)
        self.assertNotIn("PROJECT_ID = '", source)

    def test_project_from_environment_or_client(self):
        with mock.patch.dict(os.environ, {"GCP_PROJECT_ID": "env-project"}):
            self.assertEqual(collector.resolve_project("client-project"), "env-project")

        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(collector.resolve_project("client-project"), "client-project")
            with self.assertRaises(SystemExit):
                collector.resolve_project(None)

    def test_filters_target_the_right_logs(self):
        start = datetime(2026, 11, 21, tzinfo=timezone.utc)
        data_access = collector.build_filter("p", collector.DATA_ACCESS_LOG, start)

        self.assertIn('logName="projects/p/logs/cloudaudit.googleapis.com%2Fdata_access"', data_access)
        self.assertIn("2026-11-21T00:00:00+00:00", data_access)

    def test_client_type_is_coarse(self):
        self.assertEqual(collector.client_type("google-cloud-sdk gcloud/500.0.0"), "gcloud")
        self.assertEqual(collector.client_type("Mozilla/5.0 (Macintosh),gzip(gfe)"), "console")
        self.assertEqual(collector.client_type(None), "unknown")

    def test_entry_conversion_keeps_no_raw_user_agent(self):
        class Entry:
            insert_id = "abc"
            timestamp = START
            severity = "INFO"
            payload = {
                "methodName": "google.iam.admin.v1.ListServiceAccounts",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": ANALYST},
                "resourceName": "projects/x",
                "requestMetadata": {"callerSuppliedUserAgent": "google-cloud-sdk gcloud/1"},
            }

        event = collector.entry_to_event(Entry(), "DATA_ACCESS")

        self.assertEqual(event["log_type"], "DATA_ACCESS")
        self.assertEqual(event["client_type"], "gcloud")
        self.assertEqual(event["source"], "gcp_cloud_audit_logs")
        self.assertNotIn("google-cloud-sdk", json.dumps(event))

    def test_merge_keeps_history_and_deduplicates(self):
        now = datetime(2026, 11, 21, tzinfo=timezone.utc)

        def ev(event_id, days_ago, method="SetIamPolicy"):
            return {
                "event_id": event_id,
                "timestamp": (now - timedelta(days=days_ago)).isoformat(),
                "method_name": method,
            }

        existing = [ev("old-setup", 6), ev("dup", 1, "Before"), ev("expired", 45)]
        new = [ev("dup", 1, "After"), ev("fresh", 0)]

        merged = collector.merge_events(existing, new, now=now)
        by_id = {event["event_id"]: event for event in merged}

        self.assertEqual([event["event_id"] for event in merged], ["fresh", "dup", "old-setup"])
        self.assertEqual(by_id["dup"]["method_name"], "After")
        self.assertNotIn("expired", by_id)

    def test_merge_drops_events_without_valid_timestamp(self):
        merged = collector.merge_events([{"event_id": "x", "timestamp": "not-a-date"}], [])
        self.assertEqual(merged, [])

    def test_write_events_merges_into_existing_file(self):
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(json.dumps([
                {"event_id": "a", "timestamp": (now - timedelta(days=5)).isoformat()}
            ]), encoding="utf-8")

            total, added = collector.write_events(path, [
                {"event_id": "a", "timestamp": (now - timedelta(days=5)).isoformat()},
                {"event_id": "b", "timestamp": now.isoformat()},
            ])
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual((total, added), (2, 1))
        self.assertEqual({event["event_id"] for event in saved}, {"a", "b"})

    def test_non_dict_payload_is_skipped(self):
        class Entry:
            payload = "text payload"

        self.assertIsNone(collector.entry_to_event(Entry(), "DATA_ACCESS"))


if __name__ == "__main__":
    unittest.main()
