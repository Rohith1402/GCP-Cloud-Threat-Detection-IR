"""
GCP audit log collector.

Retrieves real GCP audit events with Application Default Credentials
(gcloud auth application-default login) and writes two private reports:

- reports/gcp_audit_logs.json: Admin Activity events (always on, free)
- reports/gcp_data_access_logs.json: Data Access ADMIN_READ events
  (enable "Admin Read" for the IAM and Cloud Resource Manager APIs),
  used only by the discovery rules BEHAV-004 and BEHAV-005

Data Access events are kept in a separate file so routine read calls
do not each become a SOC alert.

Each run MERGES new events into the existing reports (deduplicated by
event ID) and keeps RETENTION_DAYS of history, so older real events are
not lost when they fall outside the collection window. Use --hours to
re-fetch a longer period (GCP keeps Admin Activity logs for 400 days).

The project ID is never hardcoded. It is read from the GCP_PROJECT_ID
environment variable, or from the active gcloud / ADC configuration.
"""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path


OUTPUT_DIR = Path(__file__).resolve().parent.parent / "reports"
OUTPUT_FILE = OUTPUT_DIR / "gcp_audit_logs.json"
DATA_ACCESS_OUTPUT_FILE = OUTPUT_DIR / "gcp_data_access_logs.json"

ACTIVITY_LOG = "cloudaudit.googleapis.com%2Factivity"
DATA_ACCESS_LOG = "cloudaudit.googleapis.com%2Fdata_access"

SOURCE_LABEL = "gcp_cloud_audit_logs"
RETENTION_DAYS = 30


def build_filter(project_id, log_id, start_time):
    """Cloud Logging filter for one audit log since start_time."""

    return (
        f'logName="projects/{project_id}/logs/{log_id}" '
        f'timestamp >= "{start_time.isoformat()}"'
    )


def client_type(user_agent):
    """Coarse client category; the raw user agent is never stored."""

    agent = str(user_agent or "").lower()

    if not agent:
        return "unknown"
    if "google-cloud-sdk" in agent or "gcloud" in agent:
        return "gcloud"
    if "mozilla" in agent:
        return "console"
    if "gl-python" in agent or "gl-go" in agent or "gl-java" in agent:
        return "client_library"
    return "other"


def entry_to_event(entry, log_type):
    """Convert a Cloud Logging entry to the project's event format."""

    payload = getattr(entry, "payload", None)

    if not isinstance(payload, dict):
        return None

    timestamp = getattr(entry, "timestamp", None)
    request_metadata = payload.get("requestMetadata") or {}

    return {
        "event_id": getattr(entry, "insert_id", None),
        "timestamp": timestamp.isoformat() if timestamp else None,
        "severity": getattr(entry, "severity", None),
        "method_name": payload.get("methodName"),
        "service_name": payload.get("serviceName"),
        "principal_email": (
            (payload.get("authenticationInfo") or {}).get("principalEmail")
        ),
        "resource_name": payload.get("resourceName"),
        "status": payload.get("status", {}),
        "log_type": log_type,
        "client_type": client_type(
            request_metadata.get("callerSuppliedUserAgent")
        ),
        "source": SOURCE_LABEL,
    }


def fetch_events(client, project_id, log_id, log_type, start_time, limit):
    # One large page per call keeps API usage low (Logging allows up to
    # 1000 entries per page; read requests are rate limited per minute).
    entries = client.list_entries(
        filter_=build_filter(project_id, log_id, start_time),
        order_by="timestamp desc",
        max_results=limit,
        page_size=min(limit, 1000),
    )

    events = []

    for entry in entries:
        event = entry_to_event(entry, log_type)
        if event is not None:
            events.append(event)

    return events


def resolve_project(client_project=None):
    project = os.environ.get("GCP_PROJECT_ID") or client_project

    if not project:
        raise SystemExit(
            "No GCP project found. Set GCP_PROJECT_ID or run "
            "'gcloud config set project <id>'."
        )

    return project


def _event_time(event):
    try:
        value = datetime.fromisoformat(
            str(event.get("timestamp")).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value


def load_events(path):
    try:
        with Path(path).open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return []

    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def merge_events(existing, new, now=None, retention_days=RETENTION_DAYS):
    """
    Merge new events into existing ones: deduplicate by event ID (newer
    copy wins), drop events older than the retention period or without
    a valid timestamp, and sort newest first.
    """

    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    merged = {}

    for event in list(existing) + list(new):
        timestamp = _event_time(event)

        if timestamp is None or timestamp < cutoff:
            continue

        key = event.get("event_id") or (
            f"{event.get('timestamp')}|{event.get('method_name')}|"
            f"{event.get('principal_email')}"
        )
        merged[key] = event

    return sorted(merged.values(), key=_event_time, reverse=True)


def write_events(path, events):
    """Merge events into the report at path; return (total, added)."""

    path = Path(path)
    existing = load_events(path)
    known = {event.get("event_id") for event in existing}
    merged = merge_events(existing, events)
    added = sum(1 for event in events if event.get("event_id") not in known)

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(merged, file, indent=4)

    return len(merged), added


def collect_audit_logs(hours=24, limit=100, data_access_limit=500):
    """Collect Admin Activity and Data Access (ADMIN_READ) events."""

    from google.cloud import logging  # imported here so tests need no GCP SDK

    client = logging.Client(project=os.environ.get("GCP_PROJECT_ID"))
    project_id = resolve_project(client.project)
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    activity = fetch_events(
        client, project_id, ACTIVITY_LOG, "ADMIN_ACTIVITY", start_time, limit
    )
    data_access = fetch_events(
        client, project_id, DATA_ACCESS_LOG, "DATA_ACCESS",
        start_time, data_access_limit,
    )

    activity_total, activity_added = write_events(OUTPUT_FILE, activity)
    access_total, access_added = write_events(DATA_ACCESS_OUTPUT_FILE, data_access)

    print(f"Collection window: last {hours} hours")
    print(
        f"Admin Activity: {len(activity)} fetched, {activity_added} new, "
        f"{activity_total} kept -> {OUTPUT_FILE}"
    )
    print(
        f"Data Access: {len(data_access)} fetched, {access_added} new, "
        f"{access_total} kept -> {DATA_ACCESS_OUTPUT_FILE}"
    )

    if not access_total:
        print(
            "[INFO] No Data Access events. Discovery rules need "
            "'Admin Read' audit logs enabled for the IAM and Cloud "
            "Resource Manager APIs."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--hours", type=int, default=24,
        help="How far back to fetch (default 24). Results are merged.",
    )
    args = parser.parse_args()

    collect_audit_logs(hours=args.hours, limit=1000, data_access_limit=1000)
