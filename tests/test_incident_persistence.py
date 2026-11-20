
import unittest
from copy import deepcopy

from detection.incident_response import (
    create_incident,
    merge_incidents,
)


class TestIncidentPersistence(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "alert_id": "TEST-ALERT-001",
            "severity": "HIGH",
            "risk_score": 85,
            "description": "Test IAM security alert",
            "source_module": "iam_security",
        }

    def test_new_incident_is_added(self):
        incoming = [create_incident(self.alert)]

        result = merge_incidents([], incoming)

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["alert_id"],
            "TEST-ALERT-001",
        )

    def test_duplicate_incident_is_not_added(self):
        existing = [create_incident(self.alert)]
        incoming = [create_incident(self.alert)]

        result = merge_incidents(existing, incoming)

        self.assertEqual(len(result), 1)

    def test_existing_status_is_preserved(self):
        existing = [create_incident(self.alert)]
        existing[0]["status"] = "INVESTIGATING"

        incoming = [create_incident(self.alert)]

        result = merge_incidents(existing, incoming)

        self.assertEqual(result[0]["status"], "INVESTIGATING")

    def test_existing_approval_is_preserved(self):
        existing = [create_incident(self.alert)]
        existing[0]["approval"]["status"] = "APPROVED"
        existing[0]["approval"]["approved_by"] = "analyst"

        incoming = [create_incident(self.alert)]

        result = merge_incidents(existing, incoming)

        self.assertEqual(
            result[0]["approval"]["status"],
            "APPROVED",
        )
        self.assertEqual(
            result[0]["approval"]["approved_by"],
            "analyst",
        )

    def test_existing_timeline_is_preserved(self):
        existing = [create_incident(self.alert)]
        existing[0]["timeline"].append({
            "timestamp": "2026-11-20T10:00:00Z",
            "event": "INVESTIGATION_STARTED",
            "details": "Analyst started investigation",
            "actor": "analyst",
        })

        original_timeline = deepcopy(existing[0]["timeline"])
        incoming = [create_incident(self.alert)]

        result = merge_incidents(existing, incoming)

        self.assertEqual(
            result[0]["timeline"],
            original_timeline,
        )

    def test_new_incident_is_added_alongside_existing(self):
        existing = [create_incident(self.alert)]

        second_alert = {
            "alert_id": "TEST-ALERT-002",
            "severity": "CRITICAL",
            "risk_score": 95,
            "description": "Second test alert",
            "source_module": "iam_security",
        }

        incoming = [
            create_incident(self.alert),
            create_incident(second_alert),
        ]

        result = merge_incidents(existing, incoming)

        self.assertEqual(len(result), 2)
        self.assertEqual(
            {item["alert_id"] for item in result},
            {"TEST-ALERT-001", "TEST-ALERT-002"},
        )


if __name__ == "__main__":
    unittest.main()
