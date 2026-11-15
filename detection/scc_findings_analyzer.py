
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

FINDINGS_FILE = (
    BASE_DIR
    / "sample_data"
    / "scc_findings"
    / "sample_scc_findings.json"
)

REPORT_FILE = (
    BASE_DIR
    / "reports"
    / "scc_security_alerts.json"
)

SEVERITY_SCORES = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 20
}

CATEGORY_RISK = {
    "PUBLIC_BUCKET_ACCESS": 20,
    "CRITICAL_VULNERABILITY": 15,
    "OVER_PRIVILEGED_IAM": 20,
    "SUSPICIOUS_NETWORK_ACTIVITY": 15,
    "OUTDATED_SOFTWARE": 5
}


def classify_severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def analyze_scc_findings(findings):
    alerts = []

    for finding in findings:

        state = finding.get("state", "").upper()

        # Process only active findings
        if state != "ACTIVE":
            continue

        severity = finding.get("severity", "LOW").upper()
        category = finding.get("category", "UNKNOWN")

        severity_score = SEVERITY_SCORES.get(severity, 10)
        category_score = CATEGORY_RISK.get(category, 0)

        risk_score = min(
            100,
            severity_score + category_score
        )

        alerts.append({
            "finding_id": finding.get("finding_id", "unknown"),
            "category": category,
            "original_severity": severity,
            "risk_score": risk_score,
            "priority": classify_severity(risk_score),
            "state": state,
            "resource_name": finding.get(
                "resource_name", "unknown"
            ),
            "description": finding.get(
                "description", "No description available"
            ),
            "source": finding.get(
                "source", "Security Command Center"
            )
        })

    # Highest-risk findings appear first
    alerts.sort(
        key=lambda alert: alert["risk_score"],
        reverse=True
    )

    return alerts


def main():

    if not FINDINGS_FILE.exists():
        print(f"[ERROR] Findings file not found: {FINDINGS_FILE}")
        return

    with FINDINGS_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    findings = data.get("findings", [])

    alerts = analyze_scc_findings(findings)

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n===== GCP SECURITY COMMAND CENTER ANALYZER =====")

    for alert in alerts:

        print(f"\nFinding ID: {alert['finding_id']}")
        print(f"Category: {alert['category']}")
        print(f"Resource: {alert['resource_name']}")
        print(f"Original Severity: {alert['original_severity']}")
        print(f"Risk Score: {alert['risk_score']}")
        print(f"Priority: {alert['priority']}")
        print(f"Description: {alert['description']}")

    print(f"\nTotal active findings analysed: {len(alerts)}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
