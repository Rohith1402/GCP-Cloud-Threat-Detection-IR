"""
Behaviour Alert Integration.

Runs the behaviour-based detection rules (BEHAV-001 to BEHAV-005)
against collected GCP audit events and writes the results to
reports/gcp_behaviour_alerts.json.

Inputs:
- reports/gcp_audit_logs.json: Admin Activity events (BEHAV-001 to 003)
- reports/gcp_data_access_logs.json: Data Access ADMIN_READ events
  (BEHAV-004 and BEHAV-005 discovery rules)

The SOC alert classifier reads that report and merges the behaviour
alerts into consolidated_soc_alerts.json, in the same way it already
handles gcp_event_correlations.json.

Alerts are investigation signals, not proof of compromise.
Detection is read-only.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from detection.behaviour_anomaly_detector import (
        detect_admin_activity_spike,
        detect_cloud_account_enumeration,
        detect_iam_permission_discovery,
        detect_repeated_service_enablement,
        detect_unusual_service_account_activity,
    )
except ImportError:  # Script run directly: python detection/<file>.py
    from behaviour_anomaly_detector import (
        detect_admin_activity_spike,
        detect_cloud_account_enumeration,
        detect_iam_permission_discovery,
        detect_repeated_service_enablement,
        detect_unusual_service_account_activity,
    )


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "reports" / "gcp_audit_logs.json"
DATA_ACCESS_FILE = BASE_DIR / "reports" / "gcp_data_access_logs.json"
OUTPUT_FILE = BASE_DIR / "reports" / "gcp_behaviour_alerts.json"

BEHAVIOUR_DETECTORS = (
    detect_admin_activity_spike,
    detect_repeated_service_enablement,
    detect_unusual_service_account_activity,
    detect_cloud_account_enumeration,
    detect_iam_permission_discovery,
)


def load_audit_events(input_file=INPUT_FILE):
    """Safely load audit events. Returns an empty list on any problem."""

    try:
        input_file = Path(input_file)

        if not input_file.exists():
            return []

        with input_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except (json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        print(f"[WARNING] Could not read audit events: {error}")
        return []

    if isinstance(data, dict):
        data = data.get("events", [])

    if not isinstance(data, list):
        return []

    return [item for item in data if isinstance(item, dict)]


def run_behaviour_detection(events):
    """Run all behaviour rules and return unique results."""

    results = []
    seen_ids = set()

    for detector in BEHAVIOUR_DETECTORS:
        try:
            detections = detector(events)
        except (KeyError, TypeError, ValueError) as error:
            print(
                f"[WARNING] {detector.__name__} failed: {error}"
            )
            continue

        for result in detections:
            alert_id = result.get("alert_id")

            if not alert_id or alert_id in seen_ids:
                continue

            seen_ids.add(alert_id)
            results.append(result)

    return results


def build_behaviour_report(events, results):
    """Build the behaviour alert report written to disk."""

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events_analyzed": len(events),
        "total_behaviour_alerts": len(results),
        "rule_summary": dict(
            Counter(result["rule_id"] for result in results)
        ),
        "source_summary": dict(
            Counter(result.get("source", "UNKNOWN") for result in results)
        ),
        "alerts": results,
    }


def main(input_file=None, output_file=OUTPUT_FILE, data_access_file=None):
    """
    Run behaviour detection.

    With no arguments, reads the default Admin Activity and Data Access
    reports. When input_file is given, only the files passed explicitly
    are read (so tests never pick up real local logs).
    """

    if input_file is None:
        input_file = INPUT_FILE
        data_access_file = DATA_ACCESS_FILE

    events = load_audit_events(input_file)

    if data_access_file is not None:
        events = events + load_audit_events(data_access_file)

    results = run_behaviour_detection(events)
    report = build_behaviour_report(events, results)

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n===== GCP BEHAVIOUR ANOMALY DETECTION =====")
    print(f"\nEvents analysed: {report['total_events_analyzed']}")
    print(f"Behaviour alerts: {report['total_behaviour_alerts']}")

    for rule_id, count in report["rule_summary"].items():
        print(f"{rule_id}: {count}")

    for result in results:
        print(
            f"\n[{result['rule_id']}] {result['rule_name']} | "
            f"Principal: {result['principal_email']} | "
            f"Events: {result['event_count']} | "
            f"Data: {result['source']}"
        )

    print(f"\nBehaviour report: {output_file}")

    return report


if __name__ == "__main__":
    main()
