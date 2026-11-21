
"""
Behaviour-Based GCP Anomaly Detection Engine.

Detects selected administrative patterns in GCP audit events.

Alerts are investigation signals, not proof of compromise.
Detection is read-only.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone


RULES = {
    "BEHAV-001": {
        "name": "Administrative Activity Spike",
        "description": (
            "Multiple security-sensitive IAM operations by one "
            "principal within a short time window."
        ),
        "risk_score": 70,
        "confidence": "MEDIUM",
        "window_minutes": 10,
        "threshold": 5,
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
    },
    "BEHAV-002": {
        "name": "Repeated Service Enablement",
        "description": (
            "Repeated service enablement operations by one principal. "
            "This activity requires contextual investigation."
        ),
        "risk_score": 55,
        "confidence": "LOW",
        "window_minutes": 15,
        "threshold": 3,
        "mitre_technique": None,
        "mitre_name": None,
    },
    "BEHAV-003": {
        "name": "Unusual Service Account Administration",
        "description": (
            "Service account creation followed by key creation "
            "by the same principal within a short time window."
        ),
        "risk_score": 65,
        "confidence": "MEDIUM",
        "window_minutes": 60,
        "threshold": 2,
        "mitre_technique": "T1098.001",
        "mitre_name": "Additional Cloud Credentials",
    },
    "BEHAV-004": {
        "name": "Cloud Account Enumeration",
        "description": (
            "Burst of programmatic (API/CLI) service-account and key "
            "enumeration by one principal using several different "
            "discovery methods. Requires contextual review."
        ),
        "risk_score": 50,
        "confidence": "LOW",
        "window_minutes": 10,
        "threshold": 6,
        "min_distinct_methods": 3,
        "mitre_technique": "T1087.004",
        "mitre_name": "Account Discovery: Cloud Account",
    },
    "BEHAV-005": {
        "name": "IAM Permission Discovery",
        "description": (
            "Burst of programmatic (API/CLI) IAM policy, permission and "
            "role queries by one principal using more than one discovery "
            "method. Requires contextual review."
        ),
        "risk_score": 50,
        "confidence": "LOW",
        "window_minutes": 10,
        "threshold": 6,
        # Tuned on real data: in Admin Read audit logs only GetIamPolicy
        # and QueryGrantableRoles are recorded for permission discovery
        # (GetRole, ListRoles and testIamPermissions were not logged), so
        # requiring three different methods could never fire.
        "min_distinct_methods": 2,
        "mitre_technique": "T1069.003",
        "mitre_name": "Permission Groups Discovery: Cloud Groups",
    },
}


SENSITIVE_IAM_METHODS = (
    "setiampolicy",
    "createserviceaccount",
    "createserviceaccountkey",
    "deleteserviceaccount",
    "deleteserviceaccountkey",
    "setserviceaccount",
)


# Discovery methods seen in Data Access (ADMIN_READ) audit logs.
ACCOUNT_DISCOVERY_METHODS = (
    "listserviceaccounts",
    "getserviceaccount",
    "listserviceaccountkeys",
    "getserviceaccountkey",
)

PERMISSION_DISCOVERY_METHODS = (
    "getiampolicy",
    "testiampermissions",
    "querygrantableroles",
    "querytestablepermissions",
    "queryauditableservices",
    "listroles",
    "getrole",
)


# Discovery rules count only programmatic access (gcloud, API, SDK).
# Real-data validation (21 Nov 2026) showed ordinary console browsing of
# IAM pages produces dozens of QueryGrantableRoles / ListRoles calls and
# triggered BEHAV-005. Events without a client_type (older or simulated
# data) still count. Known gap: manual enumeration in the console.
DISCOVERY_EXCLUDED_CLIENTS = {"console"}


def is_programmatic(event):
    return str(event.get("client_type") or "").lower() not in DISCOVERY_EXCLUDED_CLIENTS


def method_key(event):
    """Short, lower-case method name (last dotted segment)."""

    return str(event.get("method_name") or "").split(".")[-1].lower()


def parse_timestamp(value):
    """Parse an ISO timestamp and normalise it to UTC."""

    if not value or not isinstance(value, str):
        return None

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def prepare_events(events):
    """Validate timestamps and deduplicate non-empty event IDs."""

    prepared = []
    seen_ids = set()

    if not isinstance(events, list):
        return prepared

    for event in events:
        if not isinstance(event, dict):
            continue

        timestamp = parse_timestamp(event.get("timestamp"))

        if timestamp is None:
            continue

        event_id = event.get("event_id")

        if event_id:
            if event_id in seen_ids:
                continue
            seen_ids.add(event_id)

        item = dict(event)
        item["_parsed_timestamp"] = timestamp
        prepared.append(item)

    return sorted(
        prepared,
        key=lambda item: item["_parsed_timestamp"],
    )


def get_source_label(events):
    """Identify whether evidence is simulated, real, or mixed."""

    sources = {
        str(event.get("source", "")).upper()
        for event in events
    }

    if sources and all("SIMULATED" in source for source in sources):
        return "SIMULATED"

    if sources and all("SIMULATED" not in source for source in sources):
        return "REAL"

    return "MIXED"


def build_result(rule_id, events, principal):
    """Build a consistent detection result."""

    rule = RULES[rule_id]

    evidence = [
        {
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "method_name": event.get("method_name"),
            "service_name": event.get("service_name"),
        }
        for event in events
    ]

    timestamps = [
        event["_parsed_timestamp"]
        for event in events
    ]

    return {
        "alert_id": "{}-{}".format(
            rule_id,
            events[0].get("event_id") or "unknown",
        ),
        "rule_id": rule_id,
        "rule_name": rule["name"],
        "description": rule["description"],
        "risk_score": rule["risk_score"],
        "confidence": rule["confidence"],
        "severity": (
            "HIGH" if rule["risk_score"] >= 70 else "MEDIUM"
        ),
        "detection_status": "REQUIRES_INVESTIGATION",
        "principal_email": principal,
        "event_count": len(events),
        "first_seen": min(timestamps).isoformat(),
        "last_seen": max(timestamps).isoformat(),
        "source": get_source_label(events),
        "mitre_technique": rule["mitre_technique"],
        "mitre_name": rule["mitre_name"],
        "evidence": evidence,
        "recommendation": (
            "Review the principal's activity and validate its "
            "business justification. Investigate related audit "
            "events before taking response action."
        ),
    }


def group_by_principal(events):
    """Group events by known principal identity."""

    grouped = defaultdict(list)

    for event in events:
        principal = event.get("principal_email")

        if not principal:
            continue

        grouped[str(principal).lower()].append(event)

    return grouped


def find_activity_windows(
    events,
    window_minutes,
    predicate,
    threshold,
):
    """Find non-overlapping windows meeting an activity threshold."""

    results = []
    window = timedelta(minutes=window_minutes)
    matching = [
        event for event in events
        if predicate(event)
    ]

    start_index = 0

    for index, first_event in enumerate(matching):
        if index < start_index:
            continue

        end_time = (
            first_event["_parsed_timestamp"] + window
        )

        window_events = [
            event for event in matching[index:]
            if event["_parsed_timestamp"] <= end_time
        ]

        if len(window_events) >= threshold:
            results.append(window_events)
            start_index = index + len(window_events)

    return results


def find_breadth_windows(
    events,
    window_minutes,
    predicate,
    min_events,
    min_distinct_methods,
):
    """
    Find non-overlapping windows with at least min_events matching
    events that use at least min_distinct_methods different methods.
    Breadth separates systematic enumeration from repeated page loads.
    """

    results = []
    window = timedelta(minutes=window_minutes)
    matching = [event for event in events if predicate(event)]
    start_index = 0

    for index, first_event in enumerate(matching):
        if index < start_index:
            continue

        end_time = first_event["_parsed_timestamp"] + window

        window_events = [
            event for event in matching[index:]
            if event["_parsed_timestamp"] <= end_time
        ]

        distinct = {method_key(event) for event in window_events}

        if (
            len(window_events) >= min_events
            and len(distinct) >= min_distinct_methods
        ):
            results.append(window_events)
            start_index = index + len(window_events)

    return results


def _detect_discovery(events, rule_id, methods):
    rule = RULES[rule_id]
    prepared = prepare_events(events)
    results = []

    def predicate(event):
        return method_key(event) in methods and is_programmatic(event)

    for principal, principal_events in group_by_principal(prepared).items():
        for window_events in find_breadth_windows(
            principal_events,
            window_minutes=rule["window_minutes"],
            predicate=predicate,
            min_events=rule["threshold"],
            min_distinct_methods=rule["min_distinct_methods"],
        ):
            results.append(build_result(rule_id, window_events, principal))

    return results


def detect_cloud_account_enumeration(events):
    """
    BEHAV-004:
    At least six service-account / key discovery calls using at least
    three different methods by one principal within ten minutes.
    Validated on simulated scenarios only (the lab project has no
    service accounts to enumerate).
    """

    return _detect_discovery(events, "BEHAV-004", ACCOUNT_DISCOVERY_METHODS)


def detect_iam_permission_discovery(events):
    """
    BEHAV-005:
    At least six IAM policy / permission / role discovery calls using at
    least two different methods by one principal within ten minutes.
    Validated on real Data Access logs (21 Nov 2026).
    """

    return _detect_discovery(events, "BEHAV-005", PERMISSION_DISCOVERY_METHODS)


def is_sensitive_iam_operation(event):
    """Return True only for explicitly selected sensitive IAM methods."""

    method = str(
        event.get("method_name", "")
    ).lower()

    return any(
        sensitive_method in method
        for sensitive_method in SENSITIVE_IAM_METHODS
    )


def detect_admin_activity_spike(events):
    """
    BEHAV-001:
    Detect at least five security-sensitive IAM operations
    by the same principal within ten minutes.
    """

    prepared = prepare_events(events)
    results = []

    for principal, principal_events in group_by_principal(
        prepared
    ).items():

        windows = find_activity_windows(
            principal_events,
            window_minutes=10,
            predicate=is_sensitive_iam_operation,
            threshold=5,
        )

        for window_events in windows:
            results.append(
                build_result(
                    "BEHAV-001",
                    window_events,
                    principal,
                )
            )

    return results


def detect_repeated_service_enablement(events):
    """
    BEHAV-002:
    Detect at least three service enablement operations
    by the same principal within fifteen minutes.

    LOW confidence: repeated service enablement may be legitimate.
    """

    prepared = prepare_events(events)
    results = []

    def is_service_enablement(event):
        method = str(
            event.get("method_name", "")
        ).lower()

        return (
            "enableservice" in method
            and "serviceusage" in method
        )

    for principal, principal_events in group_by_principal(
        prepared
    ).items():

        windows = find_activity_windows(
            principal_events,
            window_minutes=15,
            predicate=is_service_enablement,
            threshold=3,
        )

        for window_events in windows:
            results.append(
                build_result(
                    "BEHAV-002",
                    window_events,
                    principal,
                )
            )

    return results


def detect_unusual_service_account_activity(events):
    """
    BEHAV-003:
    Detect service account creation followed by key creation
    by the same principal within sixty minutes.
    """

    prepared = prepare_events(events)
    results = []

    for principal, principal_events in group_by_principal(
        prepared
    ).items():

        creations = [
            event for event in principal_events
            if "createserviceaccount" in str(
                event.get("method_name", "")
            ).lower()
            and "createserviceaccountkey" not in str(
                event.get("method_name", "")
            ).lower()
        ]

        key_creations = [
            event for event in principal_events
            if "createserviceaccountkey" in str(
                event.get("method_name", "")
            ).lower()
        ]

        for creation in creations:
            start = creation["_parsed_timestamp"]

            matching_keys = [
                event for event in key_creations
                if start <= event["_parsed_timestamp"]
                <= start + timedelta(minutes=60)
            ]

            if matching_keys:
                results.append(
                    build_result(
                        "BEHAV-003",
                        [creation, matching_keys[0]],
                        principal,
                    )
                )

    return results
