
import json
from pathlib import Path
from datetime import datetime, timezone

POLICY_FILE = Path("sample_data/iam_policy.json")
REPORT_FILE = Path("reports/iam_security_alerts.json")

PRIVILEGED_ROLES = {
    "roles/owner": 50,
    "roles/editor": 40,
    "roles/iam.securityAdmin": 50,
    "roles/iam.serviceAccountAdmin": 40,
    "roles/iam.serviceAccountTokenCreator": 40,
}

PUBLIC_PRINCIPALS = {
    "allUsers",
    "allAuthenticatedUsers",
}


def classify_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def analyze_iam_policy(policy):
    alerts = []

    for binding in policy.get("bindings", []):
        role = binding.get("role", "unknown")
        members = binding.get("members", [])

        for member in members:
            score = 0
            findings = []

            if role in PRIVILEGED_ROLES:
                score += PRIVILEGED_ROLES[role]
                findings.append(f"Privileged role assigned: {role}")

            if member in PUBLIC_PRINCIPALS:
                score += 70
                findings.append(f"Public principal detected: {member}")

            if member.startswith("serviceAccount:"):
                if role in {
                    "roles/owner",
                    "roles/editor",
                    "roles/iam.serviceAccountTokenCreator",
                }:
                    score += 20
                    findings.append(
                        "Service account has sensitive permissions"
                    )

            if not findings:
                continue

            score = min(score, 100)

            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "principal": member,
                "role": role,
                "risk_score": score,
                "severity": classify_severity(score),
                "findings": findings,
                "source": "GCP IAM Policy",
            })

    return alerts


def main():
    if not POLICY_FILE.exists():
        print(f"[ERROR] IAM policy file not found: {POLICY_FILE}")
        return

    with POLICY_FILE.open("r", encoding="utf-8") as file:
        policy = json.load(file)

    alerts = analyze_iam_policy(policy)

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n===== GCP IAM SECURITY ANALYSIS =====")

    if not alerts:
        print("No configured IAM risk patterns detected.")

    for alert in alerts:
        print(f"\nPrincipal: {alert['principal']}")
        print(f"Role: {alert['role']}")
        print(f"Risk Score: {alert['risk_score']}")
        print(f"Severity: {alert['severity']}")
        print(f"Findings: {', '.join(alert['findings'])}")

    print(f"\nTotal alerts generated: {len(alerts)}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
