
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from detection.incident_response import (
    create_incident,
    generate_response_plan,
    recommend_action,
    save_incidents,
)


class TestIncidentResponse(unittest.TestCase):

    def setUp(self):
        self.critical_alert = {
            "alert_id": "scc-001",
            "source_module": "scc_security_alerts",
            "principal_or_resource": "projects/demo/buckets/public-data",
            "risk_score": 100,
            "severity": "CRITICAL",
            "description": "Cloud storage bucket allows public access",
        }

    def test_critical_alert_creates_incident(self):
        incidents = generate_response_plan([self.critical_alert])

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "CRITICAL")

    def test_medium_alert_does_not_create_incident(self):
        alert = {
            **self.critical_alert,
            "severity": "MEDIUM",
            "risk_score": 50,
        }

        incidents = generate_response_plan([alert])

        self.assertEqual(len(incidents), 0)

    def test_resource_is_extracted_correctly(self):
        incident = create_incident(self.critical_alert)

        self.assertEqual(
            incident["resource"],
            "projects/demo/buckets/public-data",
        )

    def test_incident_id_is_consistent(self):
        first = create_incident(self.critical_alert)
        second = create_incident(self.critical_alert)

        self.assertEqual(first["incident_id"], second["incident_id"])

    def test_public_bucket_action_is_urgent(self):
        recommendation = recommend_action(self.critical_alert)

        self.assertEqual(recommendation["priority"], "URGENT")
        self.assertIn("bucket permissions", recommendation["action"])

    def test_incident_requires_analyst_approval(self):
        incident = create_incident(self.critical_alert)

        self.assertEqual(
            incident["status"],
            "PENDING_ANALYST_APPROVAL",
        )

    def test_execution_is_simulation_only(self):
        incident = create_incident(self.critical_alert)

        self.assertEqual(
            incident["execution_mode"],
            "SIMULATION_ONLY",
        )

    def test_high_alert_creates_incident(self):
        alert = {
            **self.critical_alert,
            "severity": "HIGH",
            "risk_score": 85,
        }

        incidents = generate_response_plan([alert])

        self.assertEqual(len(incidents), 1)

    def test_incident_report_is_saved(self):
        incident = create_incident(self.critical_alert)

        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "incident_test.json"

            with patch(
                "detection.incident_response.INCIDENT_FILE",
                test_path,
            ):
                saved_path = save_incidents([incident])

            self.assertTrue(saved_path.exists())


if __name__ == "__main__":
    unittest.main()
