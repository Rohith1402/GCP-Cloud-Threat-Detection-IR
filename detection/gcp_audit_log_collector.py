
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from google.cloud import logging


PROJECT_ID = "gcp-cloud-security-lab-514814"

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "reports"
OUTPUT_FILE = OUTPUT_DIR / "gcp_audit_logs.json"


def collect_audit_logs(hours=24, limit=100):
    """
    Retrieve real GCP Admin Activity audit logs.
    Uses Application Default Credentials from gcloud auth login.
    """

    client = logging.Client(project=PROJECT_ID)

    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    filter_query = (
        'logName="projects/'
        + PROJECT_ID
        + '/logs/cloudaudit.googleapis.com%2Factivity" '
        f'timestamp >= "{start_time.isoformat()}"'
    )

    entries = client.list_entries(
        filter_=filter_query,
        order_by="timestamp desc",
        max_results=limit,
    )

    audit_events = []

    for entry in entries:
        payload = entry.payload

        if not isinstance(payload, dict):
            continue

        event = {
            "event_id": entry.insert_id,
            "timestamp": (
                entry.timestamp.isoformat()
                if entry.timestamp
                else None
            ),
            "severity": entry.severity,
            "method_name": payload.get("methodName"),
            "service_name": payload.get("serviceName"),
            "principal_email": (
                payload.get("authenticationInfo", {})
                .get("principalEmail")
            ),
            "resource_name": payload.get("resourceName"),
            "status": payload.get("status", {}),
            "source": "gcp_cloud_audit_logs",
        }

        audit_events.append(event)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(audit_events, file, indent=4)

    print(f"Project: {PROJECT_ID}")
    print(f"Events collected: {len(audit_events)}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    collect_audit_logs(hours=24, limit=100)
