
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = (
    BASE_DIR
    / "sample_data"
    / "service_account_logs"
    / "sample_service_account_logs.json"
)

REPORT_FILE = (
    BASE_DIR
    / "reports"
    / "service_account_alerts.json"
)

# Detection thresholds
FAILED_ATTEMPT_THRESHOLD = 3
NORMAL_START_HOUR = 6
NORMAL_END_HOUR = 22


def classify_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def detect_suspicious_activity(events):
    alerts = []

    for event in events:
        risk_score = 0
        findings = []

        event_type = event.get("event_type", "")
        status = event.get("status", "")
        source_ip = event.get("source_ip", "")
        failed_attempts = event.get("failed_attempts", 0)
        timestamp = event.get("timestamp", "")

        # Detect service account key creation
        if event_type == "SERVICE_ACCOUNT_KEY_CREATED":
            risk_score += 50
            findings.append("Service account key creation detected")

        # Detect authentication outside configured hours
        if event_type == "SERVICE_ACCOUNT_AUTHENTICATION" and timestamp:
            try:
                event_time = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

                hour = event_time.hour

                if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:
                    risk_score += 30
                    findings.append(
                        "Authentication outside configured normal hours"
                    )

            except ValueError:
                findings.append("Invalid timestamp format")

        # Detect repeated failed authentication attempts
        if failed_attempts >= FAILED_ATTEMPT_THRESHOLD:
            risk_score += 40
            findings.append(
                f"Multiple failed authentication attempts: {failed_attempts}"
            )

        # Detect failed authentication
        if status == "FAILED":
            risk_score += 20
            findings.append("Service account authentication failed")

        if not findings:
            continue

        risk_score = min(risk_score, 100)

        alerts.append({
            "event_id": event.get("event_id", "unknown"),
            "timestamp": timestamp,
            "service_account": event.get(
                "service_account", "unknown"
            ),
            "source_ip": source_ip,
            "event_type": event_type,
            "risk_score": risk_score,
            "severity": classify_severity(risk_score),
            "findings": findings
        })

    return alerts


def main():

    if not LOG_FILE.exists():
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return

    with LOG_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    events = data.get("service_account_events", [])

    alerts = detect_suspicious_activity(events)

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n===== SERVICE ACCOUNT THREAT MONITOR =====")

    for alert in alerts:
        print(f"\nService Account: {alert['service_account']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Event: {alert['event_type']}")
        print(f"Risk Score: {alert['risk_score']}")
        print(f"Severity: {alert['severity']}")

        for finding in alert["findings"]:
            print(f"Finding: {finding}")

    print(f"\nTotal alerts generated: {len(alerts)}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
