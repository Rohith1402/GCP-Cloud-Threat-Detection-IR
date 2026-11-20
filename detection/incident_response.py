
import json
import hashlib
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "reports" / "consolidated_soc_alerts.json"
INCIDENT_FILE = BASE_DIR / "reports" / "incident_response_log.json"

EXECUTION_MODE = "SIMULATION_ONLY"

INCIDENT_STATUSES = {
    "PENDING_ANALYST_APPROVAL",
    "INVESTIGATING",
    "CONTAINMENT_PENDING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
}

ALLOWED_TRANSITIONS = {
    "PENDING_ANALYST_APPROVAL": {
        "INVESTIGATING",
        "CLOSED",
    },
    "INVESTIGATING": {
        "CONTAINMENT_PENDING",
        "RESOLVED",
        "CLOSED",
    },
    "CONTAINMENT_PENDING": {
        "INVESTIGATING",
        "CONTAINED",
    },
    "CONTAINED": {
        "INVESTIGATING",
        "RESOLVED",
    },
    "RESOLVED": {
        "INVESTIGATING",
        "CLOSED",
    },
    "CLOSED": set(),
}

RESPONSE_RULES = [
    {
        "keywords": ["public access", "public bucket"],
        "action": "Review bucket permissions and remove unintended public access.",
        "priority": "URGENT",
        "category": "CLOUD_STORAGE_EXPOSURE",
        "investigation_steps": [
            "Identify the affected storage bucket.",
            "Review bucket IAM policies and access configuration.",
            "Determine whether public access was intentional.",
            "Review relevant audit logs for access activity.",
        ],
        "response_steps": [
            "Document the exposure and affected resource.",
            "Prepare a simulated public access restriction.",
            "Request analyst approval before containment.",
            "Validate the proposed remediation.",
        ],
    },
    {
        "keywords": ["sensitive iam", "excessive iam", "privileged role"],
        "action": "Review IAM bindings and remove unnecessary privileged permissions.",
        "priority": "HIGH",
        "category": "IAM_PRIVILEGE_RISK",
        "investigation_steps": [
            "Identify the affected identity and resource.",
            "Review current IAM role assignments.",
            "Check recent IAM policy modifications.",
            "Validate whether the permissions are required.",
        ],
        "response_steps": [
            "Document excessive permissions.",
            "Prepare a simulated IAM permission reduction.",
            "Request analyst approval.",
            "Validate the proposed access configuration.",
        ],
    },
    {
        "keywords": ["service account key", "key creation"],
        "action": "Validate key creation and rotate or revoke the key if unauthorised.",
        "priority": "HIGH",
        "category": "SERVICE_ACCOUNT_SECURITY",
        "investigation_steps": [
            "Identify the affected service account.",
            "Review key creation audit events.",
            "Verify the creating principal.",
            "Check whether the key creation was authorised.",
        ],
        "response_steps": [
            "Document the key creation event.",
            "Prepare a simulated key revocation or rotation.",
            "Request analyst approval.",
            "Validate the proposed remediation.",
        ],
    },
    {
        "keywords": ["failed authentication", "failed attempts"],
        "action": "Investigate authentication failures and verify service account activity.",
        "priority": "HIGH",
        "category": "AUTHENTICATION_RISK",
        "investigation_steps": [
            "Identify the affected account.",
            "Review authentication failure timestamps.",
            "Correlate activity with other audit events.",
            "Check for unusual authentication patterns.",
        ],
        "response_steps": [
            "Document the suspicious authentication activity.",
            "Prepare a simulated account protection action.",
            "Request analyst approval.",
            "Review subsequent authentication activity.",
        ],
    },
    {
        "keywords": ["critical vulnerability"],
        "action": "Validate the vulnerability and prioritise patching the affected resource.",
        "priority": "HIGH",
        "category": "VULNERABILITY",
        "investigation_steps": [
            "Identify the affected resource.",
            "Review the vulnerability finding.",
            "Validate severity and exposure.",
            "Determine the remediation requirements.",
        ],
        "response_steps": [
            "Document the vulnerability.",
            "Prepare a simulated remediation plan.",
            "Request analyst approval.",
            "Validate remediation readiness.",
        ],
    },
    {
        "keywords": ["unusual network", "network activity"],
        "action": "Investigate network activity and review relevant logs.",
        "priority": "MEDIUM",
        "category": "NETWORK_SECURITY",
        "investigation_steps": [
            "Identify the affected network resource.",
            "Review relevant network activity.",
            "Correlate timestamps with audit events.",
            "Determine whether the activity is expected.",
        ],
        "response_steps": [
            "Document suspicious network activity.",
            "Prepare a simulated network containment plan.",
            "Request analyst approval.",
            "Review the proposed action.",
        ],
    },
    {
        "keywords": ["setiampolicy", "sensitive operation"],
        "action": "Review the administrative operation and verify whether it was authorised.",
        "priority": "MEDIUM",
        "category": "ADMINISTRATIVE_ACTIVITY",
        "investigation_steps": [
            "Identify the administrative operation.",
            "Review the principal responsible.",
            "Inspect related audit events.",
            "Verify whether the operation was authorised.",
        ],
        "response_steps": [
            "Document the administrative activity.",
            "Prepare a simulated corrective action if required.",
            "Request analyst approval.",
            "Validate the proposed action.",
        ],
    },
]


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def load_alerts():
    if not ALERT_FILE.exists():
        raise FileNotFoundError(
            f"Consolidated alert report not found: {ALERT_FILE}"
        )

    with ALERT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict) and isinstance(data.get("alerts"), list):
        return data["alerts"]

    raise ValueError("Unexpected consolidated alert report format.")


def recommend_action(alert):
    description = str(alert.get("description", "")).lower()
    source = str(
        alert.get("source_module", alert.get("source", ""))
    ).lower()

    searchable_text = f"{description} {source}"

    for rule in RESPONSE_RULES:
        if any(
            keyword in searchable_text
            for keyword in rule["keywords"]
        ):
            return {
                "action": rule["action"],
                "priority": rule["priority"],
                "category": rule["category"],
                "investigation_steps": rule["investigation_steps"],
                "response_steps": rule["response_steps"],
            }

    return {
        "action": "Manually investigate the alert and collect supporting evidence.",
        "priority": "REVIEW",
        "category": "GENERAL_SECURITY",
        "investigation_steps": [
            "Review the original alert.",
            "Identify the affected resource.",
            "Collect supporting evidence.",
            "Determine whether the activity was authorised.",
        ],
        "response_steps": [
            "Document investigation findings.",
            "Prepare an appropriate response plan.",
            "Request analyst approval before containment.",
        ],
    }


def extract_evidence(alert):
    evidence_items = []

    supplied_evidence = alert.get("evidence", [])

    if isinstance(supplied_evidence, list):
        for item in supplied_evidence:
            if isinstance(item, dict):
                evidence_items.append(deepcopy(item))

    if not evidence_items:
        evidence_items.append({
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "source_module": alert.get("source_module", "unknown"),
            "timestamp": alert.get("timestamp"),
            "rule_id": alert.get("rule_id"),
            "rule_name": alert.get("rule_name"),
            "confidence": alert.get("confidence"),
            "mitre_technique_id": alert.get("mitre_technique_id"),
            "mitre_technique_name": alert.get("mitre_technique_name"),
            "description": alert.get("description"),
        })

    return {"evidence_items": evidence_items}


def create_incident(alert):
    """Create a structured incident from a SOC alert."""

    alert_id = str(alert.get("alert_id", "UNKNOWN"))

    identifier = hashlib.sha256(
        alert_id.encode("utf-8")
    ).hexdigest()[:10].upper()

    incident_id = f"IR-{identifier}"

    recommendation = recommend_action(alert)
    created_at = current_timestamp()

    return {
        "incident_id": incident_id,
        "alert_id": alert_id,
        "source_module": alert.get("source_module", "unknown"),
        "severity": alert.get("severity", "UNKNOWN"),
        "risk_score": alert.get("risk_score", 0),
        "resource": alert.get(
            "principal_or_resource",
            alert.get("resource", alert.get("principal", "unknown")),
        ),
        "description": alert.get("description", "No description"),
        "recommended_action": recommendation["action"],
        "response_priority": recommendation["priority"],
        "incident_category": recommendation["category"],
        "status": "PENDING_ANALYST_APPROVAL",
        "execution_mode": EXECUTION_MODE,
        "approval": {
            "status": "PENDING",
            "approved_by": None,
            "approved_at": None,
            "decision": None,
        },
        "evidence": extract_evidence(alert),
        "playbook": {
            "investigation_steps": recommendation["investigation_steps"],
            "response_steps": recommendation["response_steps"],
        },
        "timeline": [
            {
                "timestamp": created_at,
                "event": "INCIDENT_CREATED",
                "details": "Incident generated from a consolidated SOC alert.",
                "actor": "SYSTEM",
            }
        ],
        "response_actions": [],
        "created_at": created_at,
        "updated_at": created_at,
        "closed_at": None,
    }


def generate_response_plan(alerts):
    """
    Generate incidents for active HIGH and CRITICAL alerts without
    duplicates. Suppressed and rolled-up alerts are skipped.
    """

    incidents = []
    seen_incident_ids = set()

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        # Tuned alerts (suppressed or rolled up) never open incidents.
        if str(alert.get("status", "OPEN")).upper() in {"SUPPRESSED", "ROLLED_UP"}:
            continue

        severity = str(alert.get("severity", "")).upper()

        if severity not in {"CRITICAL", "HIGH"}:
            continue

        incident = create_incident(alert)

        if incident["incident_id"] in seen_incident_ids:
            continue

        seen_incident_ids.add(incident["incident_id"])
        incidents.append(incident)

    return incidents


def load_incidents():
    """Load previously saved incidents."""

    if not INCIDENT_FILE.exists():
        return []

    with INCIDENT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("Unexpected incident report format.")

    return data


def save_incidents(incidents):
    """Save incident records to the private reports directory."""

    INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with INCIDENT_FILE.open("w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

    return INCIDENT_FILE


def merge_incidents(existing_incidents, incoming_incidents):
    """Add new incidents without overwriting existing incident history."""

    if not isinstance(existing_incidents, list):
        raise ValueError("Existing incidents must be a list.")

    if not isinstance(incoming_incidents, list):
        raise ValueError("Incoming incidents must be a list.")

    merged = deepcopy(existing_incidents)

    existing_ids = {
        item.get("incident_id")
        for item in merged
        if isinstance(item, dict) and item.get("incident_id")
    }

    added_count = 0

    for incident in incoming_incidents:
        if not isinstance(incident, dict):
            continue

        incident_id = incident.get("incident_id")

        if not incident_id or incident_id in existing_ids:
            continue

        merged.append(deepcopy(incident))
        existing_ids.add(incident_id)
        added_count += 1

    print(f"Existing incidents preserved: {len(existing_incidents)}")
    print(f"New incidents added: {added_count}")
    print(f"Total incidents after merge: {len(merged)}")

    return merged


def add_timeline_event(
    incident,
    event,
    details,
    actor="ANALYST",
):
    if not isinstance(incident.get("timeline"), list):
        incident["timeline"] = []

    timestamp = current_timestamp()

    incident["timeline"].append({
        "timestamp": timestamp,
        "event": event,
        "details": details,
        "actor": actor,
    })

    incident["updated_at"] = timestamp


def transition_incident(incident, new_status):
    """Validate and apply an incident lifecycle transition."""

    if new_status not in INCIDENT_STATUSES:
        raise ValueError(f"Unknown incident status: {new_status}")

    current_status = incident.get("status")

    if current_status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid current incident status: {current_status}")

    if new_status not in ALLOWED_TRANSITIONS[current_status]:
        raise ValueError(
            f"Transition from {current_status} to {new_status} is not allowed."
        )

    if new_status == "CONTAINED":
        if incident.get("approval", {}).get("status") != "APPROVED":
            raise PermissionError("Analyst approval is required for containment.")

        if not incident.get("response_actions"):
            raise ValueError("A simulated response action must be recorded first.")

    incident["status"] = new_status

    if new_status == "CLOSED":
        incident["closed_at"] = current_timestamp()

    add_timeline_event(
        incident,
        "STATUS_CHANGED",
        f"Incident status changed from {current_status} to {new_status}.",
    )

    return incident


def add_evidence(incident, evidence):
    """Append supporting evidence to an incident."""

    if not isinstance(evidence, dict):
        raise ValueError("Evidence must be a dictionary.")

    if not isinstance(incident.get("evidence"), dict):
        incident["evidence"] = {"evidence_items": []}

    if not isinstance(
        incident["evidence"].get("evidence_items"),
        list,
    ):
        incident["evidence"]["evidence_items"] = []

    incident["evidence"]["evidence_items"].append(deepcopy(evidence))

    add_timeline_event(
        incident,
        "EVIDENCE_ADDED",
        "Additional supporting evidence was attached to the incident.",
    )

    return incident


def approve_response(
    incident,
    approved_by,
    approved=True,
):
    """Record an analyst's explicit response approval decision."""

    if incident.get("status") not in {
        "INVESTIGATING",
        "CONTAINMENT_PENDING",
    }:
        raise ValueError(
            "Response approval requires an active investigation or pending containment."
        )

    if not approved_by or not str(approved_by).strip():
        raise ValueError("An analyst identifier is required.")

    timestamp = current_timestamp()
    decision = "APPROVED" if approved else "REJECTED"

    incident["approval"] = {
        "status": decision,
        "approved_by": str(approved_by),
        "approved_at": timestamp,
        "decision": decision,
    }

    add_timeline_event(
        incident,
        "RESPONSE_APPROVED" if approved else "RESPONSE_REJECTED",
        f"Response {decision.lower()} by analyst {approved_by}.",
        actor=str(approved_by),
    )

    return incident


def record_response_action(
    incident,
    action,
    result="SIMULATED",
):
    """Record a simulation-only response action."""

    if incident.get("status") != "CONTAINMENT_PENDING":
        raise ValueError(
            "Response actions require CONTAINMENT_PENDING status."
        )

    if incident.get("approval", {}).get("status") != "APPROVED":
        raise PermissionError(
            "An approved analyst decision is required before response."
        )

    if result != "SIMULATED":
        raise ValueError(
            "Only SIMULATED response actions are permitted."
        )

    timestamp = current_timestamp()

    response_action = {
        "timestamp": timestamp,
        "action": action,
        "result": "SIMULATED",
        "execution_mode": EXECUTION_MODE,
    }

    if not isinstance(incident.get("response_actions"), list):
        incident["response_actions"] = []

    incident["response_actions"].append(response_action)

    add_timeline_event(
        incident,
        "RESPONSE_ACTION_SIMULATED",
        f"Simulated response action recorded: {action}",
        actor="SYSTEM",
    )

    return response_action


def find_incident(incidents, incident_id):
    """Find an incident by its stable incident ID."""

    for incident in incidents:
        if (
            isinstance(incident, dict)
            and incident.get("incident_id") == incident_id
        ):
            return incident

    return None


def main():
    print("\n===== INCIDENT RESPONSE AUTOMATION =====")

    try:
        alerts = load_alerts()
        incoming_incidents = generate_response_plan(alerts)

        existing_incidents = load_incidents()

        incidents = merge_incidents(
            existing_incidents,
            incoming_incidents,
        )

        output_file = save_incidents(incidents)

        print(f"\nTotal SOC alerts reviewed: {len(alerts)}")
        print(f"New incidents generated: {len(incoming_incidents)}")
        print(f"Total persistent incidents: {len(incidents)}")

        for incident in incidents:
            print("\n-----------------------------------")
            print(f"Incident ID: {incident['incident_id']}")
            print(f"Severity: {incident['severity']}")
            print(f"Risk score: {incident['risk_score']}")
            print(f"Resource: {incident['resource']}")
            print(f"Priority: {incident['response_priority']}")
            print(f"Recommended action: {incident['recommended_action']}")
            print(f"Status: {incident['status']}")

        print(f"\nIncident report saved: {output_file}")
        print("\nSimulation only: no cloud resources were modified.")

    except (
        FileNotFoundError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
