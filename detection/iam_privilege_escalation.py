
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent

POLICY_FILE = BASE_DIR / "sample_data" / "iam_policy.json"
ROLE_FILE = BASE_DIR / "sample_data" / "role_definitions.json"
REPORT_FILE = BASE_DIR / "reports" / "iam_privilege_alerts.json"

RISKY_PERMISSIONS = {
    "iam.serviceAccounts.actAs": 30,
    "iam.serviceAccounts.getAccessToken": 40,
    "iam.serviceAccountKeys.create": 50,
    "resourcemanager.projects.setIamPolicy": 50,
    "iam.roles.create": 40,
    "iam.roles.update": 40,
}


def classify_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def analyze_permissions(policy, role_definitions):
    alerts = []

    for binding in policy.get("bindings", []):
        role = binding.get("role", "unknown")
        members = binding.get("members", [])

        role_data = role_definitions.get(role, {})
        permissions = role_data.get("permissions", [])

        risky_permissions = [
            permission
            for permission in permissions
            if permission in RISKY_PERMISSIONS
        ]

        if not risky_permissions:
            continue

        score = min(
            100,
            sum(RISKY_PERMISSIONS[p] for p in risky_permissions)
        )

        for member in members:
            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "principal": member,
                "role": role,
                "risk_score": score,
                "severity": classify_severity(score),
                "risky_permissions": risky_permissions,
                "finding": "Sensitive IAM capabilities detected",
                "source": "GCP IAM Role Analysis"
            })

    return alerts


def main():
    for file_path in [POLICY_FILE, ROLE_FILE]:
        if not file_path.exists():
            print(f"[ERROR] Required file not found: {file_path}")
            return

    with POLICY_FILE.open("r", encoding="utf-8") as file:
        policy = json.load(file)

    with ROLE_FILE.open("r", encoding="utf-8") as file:
        role_definitions = json.load(file)

    alerts = analyze_permissions(policy, role_definitions)

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n===== IAM PRIVILEGE ESCALATION ANALYSIS =====")

    if not alerts:
        print("No configured risky permissions detected.")

    for alert in alerts:
        print(f"\nPrincipal: {alert['principal']}")
        print(f"Role: {alert['role']}")
        print(f"Risk Score: {alert['risk_score']}")
        print(f"Severity: {alert['severity']}")

        print("Risky permissions:")
        for permission in alert["risky_permissions"]:
            print(f"  - {permission}")

    print(f"\nTotal alerts generated: {len(alerts)}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
