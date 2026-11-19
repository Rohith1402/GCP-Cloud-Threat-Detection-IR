
import unittest

from datetime import datetime, timedelta, timezone

from detection.event_correlation import (
    correlate_events,
    detect_account_creation_then_key,
    detect_key_creation_then_iam_change,
    detect_repeated_sensitive_activity,
    prepare_events
)


class TestEventCorrelation(unittest.TestCase):

    def setUp(self):
        self.base_time = datetime(
            2026, 11, 17, 10, 0, 0,
            tzinfo=timezone.utc
        )

    def create_event(
        self,
        event_id,
        method_name,
        minutes_after=0,
        principal="analyst@example.com",
        resource="projects/test-project",
        timestamp=None
    ):
        if timestamp is None:
            timestamp = (
                self.base_time
                + timedelta(minutes=minutes_after)
            ).isoformat()

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "method_name": method_name,
            "service_name": "iam.googleapis.com",
            "principal_email": principal,
            "resource_name": resource,
            "severity": "NOTICE",
            "status": {}
        }

    # --------------------------------------------------
    # ORIGINAL TESTS
    # --------------------------------------------------

    def test_service_account_creation_followed_by_key_creation(self):
        events = [
            self.create_event(
                "event-001",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "event-002",
                "CreateServiceAccountKey",
                10
            )
        ]

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "CORR-001")
        self.assertEqual(results[0]["risk_score"], 85)
        self.assertEqual(results[0]["event_count"], 2)

    def test_key_creation_followed_by_iam_policy_modification(self):
        events = [
            self.create_event(
                "event-003",
                "CreateServiceAccountKey",
                0
            ),
            self.create_event(
                "event-004",
                "SetIamPolicy",
                15
            )
        ]

        results = detect_key_creation_then_iam_change(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "CORR-002")
        self.assertEqual(results[0]["risk_score"], 95)

    def test_repeated_sensitive_administrative_activity(self):
        events = [
            self.create_event(
                "event-005",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "event-006",
                "CreateServiceAccountKey",
                5
            ),
            self.create_event(
                "event-007",
                "SetIamPolicy",
                10
            )
        ]

        results = detect_repeated_sensitive_activity(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "CORR-003")
        self.assertEqual(results[0]["event_count"], 3)

    def test_different_principals_are_not_correlated(self):
        events = [
            self.create_event(
                "event-008",
                "CreateServiceAccount",
                0,
                "user-a@example.com"
            ),
            self.create_event(
                "event-009",
                "CreateServiceAccountKey",
                10,
                "user-b@example.com"
            )
        ]

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 0)

    def test_events_outside_correlation_window_are_not_matched(self):
        events = [
            self.create_event(
                "event-010",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "event-011",
                "CreateServiceAccountKey",
                90
            )
        ]

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 0)

    def test_normal_events_do_not_generate_correlations(self):
        events = [
            self.create_event(
                "event-012",
                "EnableService",
                0
            ),
            self.create_event(
                "event-013",
                "GetOperation",
                2
            )
        ]

        results = correlate_events(events)

        self.assertEqual(len(results), 0)

    def test_correlation_contains_evidence(self):
        events = [
            self.create_event(
                "event-014",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "event-015",
                "CreateServiceAccountKey",
                5
            )
        ]

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 1)
        self.assertIn("evidence", results[0])
        self.assertEqual(len(results[0]["evidence"]), 2)
        self.assertEqual(
            results[0]["detection_status"],
            "REQUIRES_INVESTIGATION"
        )

    # --------------------------------------------------
    # NEW EDGE-CASE TESTS
    # --------------------------------------------------

    def test_duplicate_event_ids_are_removed(self):
        creation = self.create_event(
            "duplicate-event",
            "CreateServiceAccount",
            0
        )

        key_creation = self.create_event(
            "unique-key-event",
            "CreateServiceAccountKey",
            5
        )

        events = [
            creation,
            dict(creation),
            key_creation
        ]

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["event_count"], 2)

        evidence_ids = [
            item["event_id"]
            for item in results[0]["evidence"]
        ]

        self.assertEqual(
            evidence_ids.count("duplicate-event"),
            1
        )

    def test_events_without_ids_are_retained(self):
        events = [
            self.create_event(
                None,
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                None,
                "CreateServiceAccountKey",
                5
            )
        ]

        prepared = prepare_events(events)

        self.assertEqual(len(prepared), 2)

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["event_count"], 2)

    def test_principal_matching_is_case_insensitive(self):
        events = [
            self.create_event(
                "event-case-001",
                "CreateServiceAccount",
                0,
                "Analyst@Example.com"
            ),
            self.create_event(
                "event-case-002",
                "CreateServiceAccountKey",
                5,
                "analyst@example.com"
            )
        ]

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "CORR-001")

    def test_invalid_timestamps_are_ignored(self):
        events = [
            self.create_event(
                "event-invalid",
                "CreateServiceAccount",
                timestamp="not-a-valid-timestamp"
            ),
            self.create_event(
                "event-valid-001",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "event-valid-002",
                "CreateServiceAccountKey",
                5
            )
        ]

        prepared = prepare_events(events)

        self.assertEqual(len(prepared), 2)

        results = detect_account_creation_then_key(events)

        self.assertEqual(len(results), 1)

    def test_multiple_separate_activity_windows_are_detected(self):
        events = [
            self.create_event(
                "burst-001",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "burst-002",
                "CreateServiceAccountKey",
                5
            ),
            self.create_event(
                "burst-003",
                "SetIamPolicy",
                10
            ),
            self.create_event(
                "burst-004",
                "CreateServiceAccount",
                30
            ),
            self.create_event(
                "burst-005",
                "CreateServiceAccountKey",
                35
            ),
            self.create_event(
                "burst-006",
                "SetIamPolicy",
                40
            )
        ]

        results = detect_repeated_sensitive_activity(events)

        self.assertEqual(len(results), 2)

        for result in results:
            self.assertEqual(result["rule_id"], "CORR-003")
            self.assertGreaterEqual(result["event_count"], 3)

    def test_activity_windows_do_not_overlap(self):
        events = [
            self.create_event(
                "overlap-001",
                "CreateServiceAccount",
                0
            ),
            self.create_event(
                "overlap-002",
                "CreateServiceAccountKey",
                5
            ),
            self.create_event(
                "overlap-003",
                "SetIamPolicy",
                10
            ),
            self.create_event(
                "overlap-004",
                "CreateServiceAccount",
                12
            ),
            self.create_event(
                "overlap-005",
                "CreateServiceAccount",
                30
            ),
            self.create_event(
                "overlap-006",
                "CreateServiceAccountKey",
                35
            ),
            self.create_event(
                "overlap-007",
                "SetIamPolicy",
                40
            )
        ]

        results = detect_repeated_sensitive_activity(events)

        self.assertEqual(len(results), 2)

        first_ids = {
            item["event_id"]
            for item in results[0]["evidence"]
        }

        second_ids = {
            item["event_id"]
            for item in results[1]["evidence"]
        }

        self.assertTrue(first_ids.isdisjoint(second_ids))


if __name__ == "__main__":
    unittest.main()
