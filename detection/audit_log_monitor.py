
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = (
    BASE_DIR
    / "sample_data"
    / "audit_logs"
    / "sample_audit_logs.json"
)

REPORT_FILE = (
    BASE_DIR
    / "reports"
    / "audit_log_alerts.json"
)

RISKY_OPERATIONS = {
    "SetIamPolicy": 40,
    "CreateServiceAccountKey": 50,
    "CreateServiceAccount": 30
}


def classify_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def detect_suspicious_activity(audit_logs):
    alerts = []

    for event in audit_logs:
        payload = event.get("protoPayload", {})

        method = payload.get("methodName", "")

        principal = payload.get(
            "authenticationInfo", {}
        ).get("principalEmail", "unknown")

        status_code = payload.get(
            "status", {}
        ).get("code", 0)

        # Extract the exact API operation name
        actual_operation = method.split(".")[-1]

        risk_score = 0
        findings = []

        # Detect sensitive IAM and service account operations
        if actual_operation in RISKY_OPERATIONS:
            operation_score = RISKY_OPERATIONS[actual_operation]

            risk_score = max(risk_score, operation_score)

            findings.append(
                f"Sensitive operation detected: {actual_operation}"
            )

        # Detect failed operations
        if status_code != 0:
            risk_score += 20

            findings.append(
                "Failed administrative operation"
            )

        if not findings:
            continue

        risk_score = min(risk_score, 100)

        alerts.append({
            "timestamp": event.get(
                "timestamp",
                datetime.now(timezone.utc).isoformat()
            ),
            "insert_id": event.get("insertId", "unknown"),
            "principal": principal,
            "method": method,
            "risk_score": risk_score,
            "severity": classify_severity(risk_score),
            "findings": findings,
            "status_code": status_code
        })

    return alerts


def main():

    if not LOG_FILE.exists():
        print(f"[ERROR] Audit log file not found: {LOG_FILE}")
        return

    with LOG_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    audit_logs = data.get("audit_logs", [])

    alerts = detect_suspicious_activity(audit_logs)

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n===== GCP CLOUD AUDIT LOG MONITOR =====")

    for alert in alerts:

        print(f"\nPrincipal: {alert['principal']}")
        print(f"Operation: {alert['method']}")
        print(f"Risk Score: {alert['risk_score']}")
        print(f"Severity: {alert['severity']}")

        for finding in alert["findings"]:
            print(f"Finding: {finding}")

    print(f"\nTotal alerts generated: {len(alerts)}")

    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
