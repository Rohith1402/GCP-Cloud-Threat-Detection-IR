
import json
import hashlib

from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "reports" / "gcp_audit_logs.json"
OUTPUT_DIR = BASE_DIR / "reports"
OUTPUT_FILE = OUTPUT_DIR / "gcp_event_correlations.json"

SEQUENCE_WINDOW_MINUTES = 60
SENSITIVE_ACTIVITY_WINDOW_MINUTES = 15
SENSITIVE_ACTIVITY_THRESHOLD = 3


# --------------------------------------------------
# EVENT NORMALIZATION
# --------------------------------------------------

def parse_timestamp(value):
    """Convert an ISO timestamp into a timezone-aware datetime."""

    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError, AttributeError):
        return None


def normalize_method(method_name):
    """Normalize GCP method names for rule matching."""

    return (method_name or "").strip().lower()


def normalize_principal(principal):
    """Normalize principal identifiers for comparison."""

    if not isinstance(principal, str):
        return None

    principal = principal.strip()

    return principal.casefold() if principal else None


def prepare_event(record):
    """Prepare a raw audit event for correlation."""

    if not isinstance(record, dict):
        return None

    timestamp = parse_timestamp(record.get("timestamp"))

    if timestamp is None:
        return None

    event = dict(record)

    event["_parsed_timestamp"] = timestamp
    event["_normalized_method"] = normalize_method(
        record.get("method_name")
    )
    event["_normalized_principal"] = normalize_principal(
        record.get("principal_email")
    )

    return event


def prepare_events(events):
    """
    Normalize events, discard invalid timestamps and remove
    duplicate non-empty event IDs.

    Events without IDs are retained because they may represent
    distinct audit events.
    """

    prepared = []
    seen_event_ids = set()

    for record in events:
        event = prepare_event(record)

        if event is None:
            continue

        event_id = event.get("event_id")

        if event_id:
            event_id = str(event_id)

            if event_id in seen_event_ids:
                continue

            seen_event_ids.add(event_id)

        prepared.append(event)

    prepared.sort(
        key=lambda item: item["_parsed_timestamp"]
    )

    return prepared


def load_audit_events():
    """Load audit events from the existing collector report."""

    if not INPUT_FILE.exists():
        print("[WARNING] GCP audit log report not found.")
        return []

    try:
        with INPUT_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        print(f"[ERROR] Unable to read audit logs: {error}")
        return []

    if not isinstance(data, list):
        print("[WARNING] Audit log report must contain a JSON array.")
        return []

    return prepare_events(data)


# --------------------------------------------------
# EVENT IDENTIFICATION
# --------------------------------------------------

def is_service_account_creation(event):
    method = (
        event.get("_normalized_method")
        or normalize_method(event.get("method_name"))
    )

    return (
        "createserviceaccount" in method
        and "key" not in method
    )


def is_service_account_key_creation(event):
    method = (
        event.get("_normalized_method")
        or normalize_method(event.get("method_name"))
    )

    return "createserviceaccountkey" in method


def is_iam_policy_modification(event):
    method = (
        event.get("_normalized_method")
        or normalize_method(event.get("method_name"))
    )

    return "setiampolicy" in method


def is_sensitive_admin_action(event):
    return (
        is_service_account_creation(event)
        or is_service_account_key_creation(event)
        or is_iam_policy_modification(event)
    )


# --------------------------------------------------
# CORRELATION HELPERS
# --------------------------------------------------

def make_correlation_id(rule_id, events):
    """Generate a deterministic correlation identifier."""

    identifiers = [
        str(
            event.get("event_id")
            or event.get("timestamp")
            or "unknown"
        )
        for event in events
    ]

    raw_value = rule_id + "|" + "|".join(identifiers)

    digest = hashlib.sha256(
        raw_value.encode("utf-8")
    ).hexdigest()[:12]

    return f"{rule_id}-{digest}"


def build_evidence(event):
    """Build private evidence for a correlated event."""

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "method_name": event.get("method_name"),
        "service_name": event.get("service_name"),
        "principal_email": event.get("principal_email"),
        "resource_name": event.get("resource_name"),
        "severity": event.get("severity"),
        "status": event.get("status")
    }


def build_correlation(
    rule_id,
    rule_name,
    description,
    events,
    risk_score
):
    """Create a standardized correlation result."""

    events = prepare_events(events)

    if not events:
        raise ValueError("A correlation must contain valid events.")

    return {
        "correlation_id": make_correlation_id(
            rule_id,
            events
        ),
        "rule_id": rule_id,
        "rule_name": rule_name,
        "description": description,
        "risk_score": risk_score,
        "severity": (
            "CRITICAL" if risk_score >= 90
            else "HIGH" if risk_score >= 70
            else "MEDIUM" if risk_score >= 30
            else "LOW"
        ),
        "confidence": "MEDIUM",
        "detection_status": "REQUIRES_INVESTIGATION",
        "event_count": len(events),
        "first_seen": events[0].get("timestamp"),
        "last_seen": events[-1].get("timestamp"),
        "principal_email": events[0].get("principal_email"),
        "evidence": [
            build_evidence(event)
            for event in events
        ],
        "recommendation": (
            "Review the actor, affected resources, event sequence, "
            "authorization context and business justification. "
            "Do not assume malicious activity without investigation."
        )
    }


def same_principal(first, second):
    """Check whether two events belong to the same known principal."""

    first_principal = (
        first.get("_normalized_principal")
        or normalize_principal(first.get("principal_email"))
    )

    second_principal = (
        second.get("_normalized_principal")
        or normalize_principal(second.get("principal_email"))
    )

    return (
        bool(first_principal)
        and bool(second_principal)
        and first_principal == second_principal
    )


def within_window(first, second, minutes):
    """Check whether two events are inside the permitted time window."""

    first_time = (
        first.get("_parsed_timestamp")
        or parse_timestamp(first.get("timestamp"))
    )

    second_time = (
        second.get("_parsed_timestamp")
        or parse_timestamp(second.get("timestamp"))
    )

    if first_time is None or second_time is None:
        return False

    difference = second_time - first_time

    return (
        timedelta(0) <= difference
        <= timedelta(minutes=minutes)
    )


# --------------------------------------------------
# CORR-001
# SERVICE ACCOUNT CREATION -> KEY CREATION
# --------------------------------------------------

def detect_account_creation_then_key(events):
    events = prepare_events(events)

    correlations = []

    creations = [
        event for event in events
        if is_service_account_creation(event)
    ]

    key_creations = [
        event for event in events
        if is_service_account_key_creation(event)
    ]

    for creation in creations:
        for key_creation in key_creations:

            if not same_principal(creation, key_creation):
                continue

            if not within_window(
                creation,
                key_creation,
                SEQUENCE_WINDOW_MINUTES
            ):
                continue

            correlations.append(
                build_correlation(
                    rule_id="CORR-001",
                    rule_name=(
                        "Service Account Creation Followed by Key Creation"
                    ),
                    description=(
                        "A principal created a service account and "
                        "subsequently created a service account key "
                        "within 60 minutes."
                    ),
                    events=[creation, key_creation],
                    risk_score=85
                )
            )

    return correlations


# --------------------------------------------------
# CORR-002
# KEY CREATION -> IAM POLICY MODIFICATION
# --------------------------------------------------

def detect_key_creation_then_iam_change(events):
    events = prepare_events(events)

    correlations = []

    key_creations = [
        event for event in events
        if is_service_account_key_creation(event)
    ]

    policy_changes = [
        event for event in events
        if is_iam_policy_modification(event)
    ]

    for key_creation in key_creations:
        for policy_change in policy_changes:

            if not same_principal(key_creation, policy_change):
                continue

            if not within_window(
                key_creation,
                policy_change,
                SEQUENCE_WINDOW_MINUTES
            ):
                continue

            correlations.append(
                build_correlation(
                    rule_id="CORR-002",
                    rule_name=(
                        "Service Account Key Creation Followed by "
                        "IAM Policy Modification"
                    ),
                    description=(
                        "A principal created a service account key "
                        "and subsequently modified an IAM policy "
                        "within 60 minutes."
                    ),
                    events=[key_creation, policy_change],
                    risk_score=95
                )
            )

    return correlations


# --------------------------------------------------
# CORR-003
# REPEATED SENSITIVE ADMINISTRATIVE ACTIVITY
# --------------------------------------------------

def detect_repeated_sensitive_activity(events):
    """
    Detect separate non-overlapping bursts of sensitive activity.

    Each qualifying window is anchored to its first event and
    covers no more than 15 minutes.
    """

    events = prepare_events(events)

    correlations = []

    principal_events = defaultdict(list)

    for event in events:
        principal = (
            event.get("_normalized_principal")
            or normalize_principal(event.get("principal_email"))
        )

        if principal and is_sensitive_admin_action(event):
            principal_events[principal].append(event)

    for principal, actor_events in principal_events.items():

        start_index = 0

        while start_index < len(actor_events):

            start_time = actor_events[
                start_index
            ]["_parsed_timestamp"]

            end_index = start_index

            while end_index < len(actor_events):

                event_time = actor_events[
                    end_index
                ]["_parsed_timestamp"]

                if (
                    event_time - start_time
                    > timedelta(
                        minutes=SENSITIVE_ACTIVITY_WINDOW_MINUTES
                    )
                ):
                    break

                end_index += 1

            window_events = actor_events[
                start_index:end_index
            ]

            if len(window_events) >= SENSITIVE_ACTIVITY_THRESHOLD:

                correlations.append(
                    build_correlation(
                        rule_id="CORR-003",
                        rule_name=(
                            "Repeated Sensitive Administrative Activity"
                        ),
                        description=(
                            "The same principal performed at least three "
                            "sensitive administrative actions within "
                            "15 minutes."
                        ),
                        events=window_events,
                        risk_score=75
                    )
                )

                # Move past this window to prevent overlapping alerts.
                start_index = end_index

            else:
                # Advance one event to find a later qualifying window.
                start_index += 1

    return correlations


# --------------------------------------------------
# MAIN CORRELATION ENGINE
# --------------------------------------------------

def correlate_events(events):
    """Run all correlation rules against normalized events."""

    events = prepare_events(events)

    correlations = []

    correlations.extend(
        detect_account_creation_then_key(events)
    )

    correlations.extend(
        detect_key_creation_then_iam_change(events)
    )

    correlations.extend(
        detect_repeated_sensitive_activity(events)
    )

    return correlations


def main():
    print("=" * 60)
    print("GCP AUDIT EVENT CORRELATION ENGINE")
    print("=" * 60)

    events = load_audit_events()

    print(f"Valid unique audit events: {len(events)}")

    correlations = correlate_events(events)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "total_events_analyzed": len(events),
                "total_correlations": len(correlations),
                "correlations": correlations
            },
            file,
            indent=4
        )

    print(f"Correlations detected: {len(correlations)}")
    print(f"Output file: {OUTPUT_FILE}")

    if not correlations:
        print(
            "[INFO] No matching event sequences found. "
            "This does not prove that the environment is threat-free."
        )

    for correlation in correlations:
        print(
            f"{correlation['rule_id']} | "
            f"{correlation['severity']} | "
            f"{correlation['rule_name']}"
        )


if __name__ == "__main__":
    main()
