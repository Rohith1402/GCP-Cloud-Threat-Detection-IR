
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "reports" / "consolidated_soc_alerts.json"
INCIDENT_FILE = BASE_DIR / "reports" / "incident_response_log.json"

RESPONSE_RULES = [
    {
        "keywords": ["public access", "public bucket"],
        "action": "Review bucket permissions and remove unintended public access.",
        "priority": "URGENT",
    },
    {
        "keywords": ["sensitive iam", "excessive iam", "privileged role"],
        "action": "Review IAM bindings and remove unnecessary privileged permissions.",
        "priority": "HIGH",
    },
    {
        "keywords": ["service account key", "key creation"],
        "action": "Validate key creation and rotate or revoke the key if unauthorised.",
        "priority": "HIGH",
    },
    {
        "keywords": ["failed authentication", "failed attempts"],
        "action": "Investigate authentication failures and verify service account activity.",
        "priority": "HIGH",
    },
    {
        "keywords": ["critical vulnerability"],
        "action": "Validate the vulnerability and prioritise patching the affected resource.",
        "priority": "HIGH",
    },
    {
        "keywords": ["unusual network", "network activity"],
        "action": "Investigate network activity and review relevant logs.",
        "priority": "MEDIUM",
    },
    {
        "keywords": ["setiampolicy", "sensitive operation"],
        "action": "Review the administrative operation and verify whether it was authorised.",
        "priority": "MEDIUM",
    },
]


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
    source = str(alert.get("source_module", alert.get("source", ""))).lower()
    searchable_text = f"{description} {source}"

    for rule in RESPONSE_RULES:
        if any(keyword in searchable_text for keyword in rule["keywords"]):
            return {
                "action": rule["action"],
                "priority": rule["priority"],
            }

    return {
        "action": "Manually investigate the alert and collect supporting evidence.",
        "priority": "REVIEW",
    }


def create_incident(alert):
    alert_id = str(alert.get("alert_id", "UNKNOWN"))

    # Create a short, consistent incident reference without exposing email addresses.
    identifier = hashlib.sha256(alert_id.encode("utf-8")).hexdigest()[:10].upper()
    incident_id = f"IR-{identifier}"

    recommendation = recommend_action(alert)

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
        "status": "PENDING_ANALYST_APPROVAL",
        "execution_mode": "SIMULATION_ONLY",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_response_plan(alerts):
    incidents = []

    for alert in alerts:
        severity = str(alert.get("severity", "")).upper()

        if severity in {"CRITICAL", "HIGH"}:
            incidents.append(create_incident(alert))

    return incidents


def save_incidents(incidents):
    INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with INCIDENT_FILE.open("w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

    return INCIDENT_FILE


def main():
    print("\n===== INCIDENT RESPONSE AUTOMATION =====")

    try:
        alerts = load_alerts()
        incidents = generate_response_plan(alerts)
        output_file = save_incidents(incidents)

        print(f"\nTotal SOC alerts reviewed: {len(alerts)}")
        print(f"Incidents generated: {len(incidents)}")

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

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
