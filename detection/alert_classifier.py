
import json
from pathlib import Path
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_FILES = [
    BASE_DIR / "reports" / "iam_security_alerts.json",
    BASE_DIR / "reports" / "iam_privilege_alerts.json",
    BASE_DIR / "reports" / "audit_log_alerts.json",
    BASE_DIR / "reports" / "service_account_alerts.json",
    BASE_DIR / "reports" / "scc_security_alerts.json"
]

OUTPUT_FILE = BASE_DIR / "reports" / "consolidated_soc_alerts.json"


def classify_severity(score):
    """Classify alerts using a consistent risk-score scale."""

    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def normalise_alert(alert, source_file):
    """Convert different detection outputs into one common format."""

    raw_score = alert.get("risk_score", 0)

    try:
        risk_score = int(raw_score)
        risk_score = max(0, min(100, risk_score))
    except (ValueError, TypeError):
        risk_score = 0

    severity = classify_severity(risk_score)

    if "finding_id" in alert:
        alert_id = alert["finding_id"]
    elif "event_id" in alert:
        alert_id = alert["event_id"]
    elif "insert_id" in alert:
        alert_id = alert["insert_id"]
    else:
        alert_id = (
            f"{source_file}:"
            f"{alert.get('principal', 'unknown')}"
        )

    principal = (
        alert.get("principal")
        or alert.get("service_account")
        or alert.get("resource_name")
        or "unknown"
    )

    findings = alert.get("findings", [])

    if not findings and alert.get("finding"):
        findings = [alert["finding"]]

    return {
        "alert_id": str(alert_id),
        "source_module": source_file,
        "principal_or_resource": principal,
        "category": alert.get(
            "category",
            alert.get(
                "event_type",
                alert.get("method", "GENERAL_SECURITY_ALERT")
            )
        ),
        "risk_score": risk_score,
        "severity": severity,
        "description": alert.get(
            "description",
            "; ".join(str(item) for item in findings)
            or "Security alert detected"
        ),
        "status": "OPEN"
    }


def deduplicate_alerts(alerts):
    """Remove duplicates within the same source module."""

    unique_alerts = {}

    for alert in alerts:
        key = (
            alert["source_module"],
            alert["alert_id"]
        )

        if key not in unique_alerts:
            unique_alerts[key] = alert

        elif alert["risk_score"] > unique_alerts[key]["risk_score"]:
            unique_alerts[key] = alert

    return list(unique_alerts.values())


def classify_alerts(alerts):
    """Deduplicate, prioritise and summarise security alerts."""

    alerts = deduplicate_alerts(alerts)

    alerts.sort(
        key=lambda item: (
            item["risk_score"],
            item["severity"]
        ),
        reverse=True
    )

    summary = Counter(
        alert["severity"] for alert in alerts
    )

    return alerts, dict(summary)


def main():

    all_alerts = []

    for report_file in REPORT_FILES:

        if not report_file.exists():
            print(
                f"[INFO] Report not available yet: "
                f"{report_file.name}"
            )
            continue

        try:
            with report_file.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, list):
                print(
                    f"[WARNING] Invalid report format: "
                    f"{report_file.name}"
                )
                continue

            for alert in data:
                all_alerts.append(
                    normalise_alert(
                        alert,
                        report_file.stem
                    )
                )

        except (json.JSONDecodeError, OSError) as error:
            print(
                f"[WARNING] Could not read "
                f"{report_file.name}: {error}"
            )

    classified_alerts, summary = classify_alerts(all_alerts)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {
        "total_alerts": len(classified_alerts),
        "severity_summary": summary,
        "alerts": classified_alerts
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n===== UNIFIED SOC ALERT CLASSIFICATION ENGINE =====")

    print(f"\nTotal alerts: {len(classified_alerts)}")

    print("\nSeverity Summary:")

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"{severity}: {summary.get(severity, 0)}")

    print("\nPrioritised Alerts:")

    for alert in classified_alerts:

        print(
            f"\n[{alert['severity']}] "
            f"Score: {alert['risk_score']} | "
            f"ID: {alert['alert_id']}"
        )

        print(f"Source: {alert['source_module']}")
        print(f"Resource: {alert['principal_or_resource']}")
        print(f"Description: {alert['description']}")

    print(f"\nConsolidated report: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
