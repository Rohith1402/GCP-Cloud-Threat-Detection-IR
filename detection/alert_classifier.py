
import json
from pathlib import Path
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_FILES = [
    BASE_DIR / "reports" / "iam_security_alerts.json",
    BASE_DIR / "reports" / "iam_privilege_alerts.json",
    BASE_DIR / "reports" / "audit_log_alerts.json",
    BASE_DIR / "reports" / "service_account_alerts.json",
    BASE_DIR / "reports" / "scc_security_alerts.json",
    BASE_DIR / "reports" / "gcp_audit_logs.json",
]

OUTPUT_FILE = BASE_DIR / "reports" / "consolidated_soc_alerts.json"

CORRELATION_REPORT_FILE = (
    BASE_DIR / "reports" / "gcp_event_correlations.json"
)

BEHAVIOUR_REPORT_FILE = (
    BASE_DIR / "reports" / "gcp_behaviour_alerts.json"
)


DETECTION_RULES = {
    "GCP-IAM-001": {
        "name": "IAM Policy Modification",
        "methods": ["setiampolicy"],
        "event_types": [],
        "categories": [],
        "risk_score": 80,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Review the actor, affected resource, IAM policy changes, "
            "added or removed members, granted roles and authorisation."
        )
    },
    "GCP-IAM-002": {
        "name": "Service Account Key Creation",
        "methods": ["createserviceaccountkey"],
        "event_types": ["SERVICE_ACCOUNT_KEY_CREATED"],
        "categories": [],
        "risk_score": 90,
        "confidence": "MEDIUM",
        "mitre_id": "T1098.001",
        "mitre_name": "Additional Cloud Credentials",
        "recommendation": (
            "Verify the actor and business justification. Review key "
            "ownership, creation time, usage and rotation or revocation "
            "requirements."
        )
    },
    "GCP-IAM-003": {
        "name": "Service Account Key Deletion",
        "methods": ["deleteserviceaccountkey"],
        "event_types": ["SERVICE_ACCOUNT_KEY_DELETED"],
        "categories": [],
        "risk_score": 70,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Verify whether the deletion was authorised. Check for "
            "service disruption, incident response activity or "
            "unexpected credential removal."
        )
    },
    "GCP-IAM-004": {
        "name": "Service Account Creation",
        "methods": ["createserviceaccount"],
        "event_types": ["SERVICE_ACCOUNT_CREATED"],
        "categories": [],
        "risk_score": 40,
        "confidence": "LOW",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Verify the creator, purpose, assigned roles and whether "
            "the account follows organisational policy."
        )
    },
    "GCP-IAM-005": {
        "name": "Privileged IAM Role Assignment",
        "methods": [],
        "event_types": [],
        "categories": ["PRIVILEGED_ROLE_ASSIGNMENT"],
        "risk_score": 50,
        "confidence": "MEDIUM",
        "mitre_id": "T1098.003",
        "mitre_name": "Additional Cloud Roles",
        "recommendation": (
            "Verify who assigned the privileged role, when it was "
            "assigned, its scope and whether the assignment was approved."
        )
    },
    "GCP-IAM-006": {
        "name": "Sensitive IAM Permission Combination",
        "methods": [],
        "event_types": [],
        "categories": ["SENSITIVE_IAM_PERMISSION_COMBINATION"],
        "risk_score": 100,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Review effective permissions, principal, role assignment, "
            "permission combinations and change history. Determine "
            "whether the access is necessary and authorised."
        )
    },
    "GCP-SA-001": {
        "name": "Repeated Service Account Authentication Failures",
        "methods": [],
        "event_types": [],
        "categories": ["REPEATED_AUTHENTICATION_FAILURES"],
        "risk_score": 60,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Review failure count, authentication source, timestamps, "
            "service-account ownership and related authentication events."
        )
    },
    "GCP-SCC-001": {
        "name": "Public Storage Bucket Access",
        "methods": [],
        "event_types": [],
        "categories": ["PUBLIC_BUCKET_ACCESS"],
        "risk_score": 100,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Verify whether public access is intended. Review bucket "
            "IAM and ACL policies, exposed data and access logs."
        )
    },
    "GCP-SCC-002": {
        "name": "Excessive IAM Permissions",
        "methods": [],
        "event_types": [],
        "categories": ["OVER_PRIVILEGED_IAM"],
        "risk_score": 90,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Review excessive permissions, affected principals and "
            "resources. Apply least privilege where appropriate."
        )
    },
    "GCP-SCC-003": {
        "name": "Critical Compute Vulnerability",
        "methods": [],
        "event_types": [],
        "categories": ["CRITICAL_VULNERABILITY"],
        "risk_score": 85,
        "confidence": "MEDIUM",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Validate the vulnerability, affected workload, severity, "
            "exposure and available patch or mitigation."
        )
    },
    "GCP-SCC-004": {
        "name": "Suspicious Network Activity",
        "methods": [],
        "event_types": [],
        "categories": [
            "SUSPICIOUS_NETWORK_ACTIVITY",
            "UNUSUAL_NETWORK_ACTIVITY"
        ],
        "risk_score": 55,
        "confidence": "LOW",
        "mitre_id": None,
        "mitre_name": None,
        "recommendation": (
            "Review network flow evidence, destination, source, workload "
            "and expected application behaviour."
        )
    }
}


def classify_severity(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def identify_gcp_rule(method_name="", event_type="", category=""):
    method = (method_name or "").lower()
    event_type = (event_type or "").upper()
    category = (category or "").upper()

    for rule_id, rule in DETECTION_RULES.items():
        method_match = any(
            pattern in method for pattern in rule["methods"]
        )
        event_match = event_type in rule["event_types"]
        category_match = category in rule["categories"]

        if method_match or event_match or category_match:
            return rule_id, rule

    return None, None


def assess_gcp_risk(method_name):
    _, rule = identify_gcp_rule(method_name=method_name)

    if rule:
        return rule["risk_score"]

    method = (method_name or "").lower()

    if "enableservice" in method:
        return 20
    if "createproject" in method:
        return 20
    if "getoperation" in method:
        return 5

    return 10


def _extract_risky_permissions(alert):
    permissions = alert.get("risky_permissions", [])

    if isinstance(permissions, str):
        permissions = [permissions]

    if not isinstance(permissions, list):
        permissions = []

    return {
        str(permission).lower()
        for permission in permissions
    }


def _identify_privilege_finding(alert, source_file):
    if source_file != "iam_privilege_alerts":
        return None, None

    permissions = _extract_risky_permissions(alert)

    sensitive_permissions = {
        "iam.serviceaccounts.actas",
        "iam.serviceaccounts.getaccesstoken",
        "iam.serviceaccountkeys.create",
        "resourcemanager.projects.setiampolicy",
        "iam.roles.create",
        "iam.roles.update"
    }

    if permissions.intersection(sensitive_permissions):
        return "GCP-IAM-006", DETECTION_RULES["GCP-IAM-006"]

    return None, None


def _identify_privileged_role(alert, source_file):
    if source_file != "iam_security_alerts":
        return None, None

    role = str(alert.get("role", "")).lower()
    findings = alert.get("findings", [])

    if not isinstance(findings, list):
        findings = [findings]

    finding_text = " ".join(
        str(item) for item in findings
    ).lower()

    description = str(alert.get("description", "")).lower()

    if (
        role == "roles/owner"
        or "roles/owner" in finding_text
        or "roles/owner" in description
    ):
        return "GCP-IAM-005", DETECTION_RULES["GCP-IAM-005"]

    return None, None


def _identify_service_account_failure(alert, source_file):
    if source_file != "service_account_alerts":
        return None, None

    event_type = str(alert.get("event_type", "")).upper()

    if event_type != "SERVICE_ACCOUNT_AUTHENTICATION":
        return None, None

    description = str(alert.get("description", "")).lower()
    findings = alert.get("findings", [])

    if not isinstance(findings, list):
        findings = [findings]

    finding_text = " ".join(
        str(item) for item in findings
    ).lower()

    evidence_text = description + " " + finding_text

    failure_count = alert.get(
        "failed_attempts",
        alert.get("failure_count", 0)
    )

    try:
        failure_count = int(failure_count)
    except (ValueError, TypeError):
        failure_count = 0

    has_multiple_failures = (
        failure_count >= 3
        or "multiple failed authentication" in evidence_text
        or "repeated failed authentication" in evidence_text
        or "multiple authentication failures" in evidence_text
    )

    if has_multiple_failures:
        return "GCP-SA-001", DETECTION_RULES["GCP-SA-001"]

    return None, None


def _identify_rule(alert, source_file):
    method = (
        alert.get("method_name")
        or alert.get("method")
        or ""
    )

    event_type = alert.get("event_type", "")
    category = alert.get("category", "")

    for detector in (
        _identify_privilege_finding,
        _identify_privileged_role,
        _identify_service_account_failure
    ):
        rule_id, rule = detector(alert, source_file)

        if rule:
            return rule_id, rule

    return identify_gcp_rule(
        method_name=method,
        event_type=event_type,
        category=category
    )


def normalise_alert(alert, source_file):
    method_name = (
        alert.get("method_name")
        or alert.get("method")
        or ""
    )

    event_type = alert.get("event_type", "")
    category_value = alert.get("category", "")

    rule_id, rule = _identify_rule(alert, source_file)

    is_gcp = source_file == "gcp_audit_logs"

    if rule:
        raw_score = rule["risk_score"]
    elif is_gcp:
        raw_score = assess_gcp_risk(method_name)
    else:
        raw_score = alert.get("risk_score", 0)

    try:
        risk_score = max(0, min(100, int(raw_score)))
    except (ValueError, TypeError):
        risk_score = 0

    severity = classify_severity(risk_score)

    alert_id = (
        alert.get("finding_id")
        or alert.get("event_id")
        or alert.get("insert_id")
        or f"{source_file}:{alert.get('principal', 'unknown')}"
    )

    principal = (
        alert.get("principal")
        or alert.get("principal_email")
        or alert.get("service_account")
        or alert.get("resource_name")
        or "unknown"
    )

    findings = alert.get("findings", [])

    if not isinstance(findings, list):
        findings = [findings] if findings else []

    if not findings and alert.get("finding"):
        findings = [alert["finding"]]

    if is_gcp:
        description = (
            f"GCP Cloud Audit event: {method_name or 'Unknown'}. "
            f"Service: {alert.get('service_name') or alert.get('service') or 'Unknown'}. "
            "This event requires contextual review and is not "
            "confirmation of malicious activity."
        )
        output_category = method_name or "GENERAL_GCP_ACTIVITY"
    else:
        description = alert.get(
            "description",
            "; ".join(str(item) for item in findings)
            or alert.get("finding")
            or "Security alert detected"
        )
        output_category = (
            category_value
            or event_type
            or method_name
            or "GENERAL_SECURITY_ALERT"
        )

    return {
        "alert_id": str(alert_id),
        "source_module": source_file,
        "principal_or_resource": principal,
        "category": output_category,
        "risk_score": risk_score,
        "severity": severity,
        "description": str(description),
        "timestamp": alert.get("timestamp"),
        "status": "OPEN",
        "rule_id": rule_id or "GENERAL-001",
        "rule_name": rule["name"] if rule else "General Security Activity",
        "confidence": rule["confidence"] if rule else "LOW",
        "mitre_technique_id": rule["mitre_id"] if rule else None,
        "mitre_technique_name": rule["mitre_name"] if rule else None,
        "evidence": {
            "method": method_name or None,
            "event_type": event_type or None,
            "category": category_value or None,
            "service": (
                alert.get("service_name")
                or alert.get("service")
            ),
            "risky_permissions": sorted(
                _extract_risky_permissions(alert)
            )
        },
        "recommendation": (
            rule["recommendation"]
            if rule
            else (
                "Review the event context, affected resource, actor, "
                "related activity and business justification."
            )
        ),
        "detection_status": (
            "REQUIRES_INVESTIGATION"
            if rule or is_gcp
            else "DETECTION_OUTPUT"
        )
    }


def load_report_records(data):
    if isinstance(data, list):
        return [
            item for item in data
            if isinstance(item, dict)
        ]

    if isinstance(data, dict):
        for key in ("alerts", "findings", "events"):
            value = data.get(key)

            if isinstance(value, list):
                return [
                    item for item in value
                    if isinstance(item, dict)
                ]

        if any(
            key in data
            for key in (
                "risk_score",
                "finding",
                "findings",
                "event_type",
                "method",
                "method_name",
                "category"
            )
        ):
            return [data]

    return []


def load_correlation_records(report_file=CORRELATION_REPORT_FILE):
    """Safely load correlation records from the correlation report."""

    try:
        report_file = Path(report_file)

        if not report_file.exists():
            return []

        with report_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            return []

        correlations = data.get("correlations", [])

        if not isinstance(correlations, list):
            return []

        return [
            item for item in correlations
            if isinstance(item, dict)
            and item.get("correlation_id")
            and item.get("rule_id")
        ]

    except (json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        print(
            f"[WARNING] Could not read correlation report: {error}"
        )
        return []


def normalise_correlation(correlation):
    """Convert a correlation result into the standard SOC alert format."""

    try:
        risk_score = max(
            0,
            min(100, int(correlation.get("risk_score", 0)))
        )
    except (ValueError, TypeError):
        risk_score = 0

    evidence = correlation.get("evidence", [])

    if not isinstance(evidence, list):
        evidence = []

    try:
        event_count = int(correlation.get("event_count", len(evidence)))
    except (ValueError, TypeError):
        event_count = len(evidence)

    event_count = max(0, event_count)

    principal = (
        correlation.get("principal_email")
        or "unknown"
    )

    return {
        "alert_id": str(correlation["correlation_id"]),
        "source_module": "gcp_event_correlations",
        "principal_or_resource": principal,
        "category": correlation.get("rule_id", "GCP_EVENT_CORRELATION"),
        "risk_score": risk_score,
        "severity": classify_severity(risk_score),
        "description": str(
            correlation.get("description")
            or correlation.get("rule_name")
            or "Correlated GCP audit activity requires investigation."
        ),
        "timestamp": correlation.get("first_seen"),
        "status": "OPEN",
        "rule_id": str(correlation["rule_id"]),
        "rule_name": str(
            correlation.get("rule_name")
            or "GCP Event Correlation"
        ),
        "confidence": str(
            correlation.get("confidence") or "LOW"
        ),
        "mitre_technique_id": None,
        "mitre_technique_name": None,
        "evidence": {
            "correlation_id": str(correlation["correlation_id"]),
            "event_count": event_count,
            "first_seen": correlation.get("first_seen"),
            "last_seen": correlation.get("last_seen"),
            "events": evidence
        },
        "recommendation": str(
            correlation.get("recommendation")
            or (
                "Review the actor, affected resources, event sequence "
                "and business justification."
            )
        ),
        "detection_status": str(
            correlation.get("detection_status")
            or "REQUIRES_INVESTIGATION"
        )
    }


def load_behaviour_records(report_file=BEHAVIOUR_REPORT_FILE):
    """Safely load behaviour detections from the behaviour report."""

    try:
        report_file = Path(report_file)

        if not report_file.exists():
            return []

        with report_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            return []

        alerts = data.get("alerts", [])

        if not isinstance(alerts, list):
            return []

        return [
            item for item in alerts
            if isinstance(item, dict)
            and item.get("alert_id")
            and str(item.get("rule_id", "")).startswith("BEHAV-")
        ]

    except (json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        print(
            f"[WARNING] Could not read behaviour report: {error}"
        )
        return []


def normalise_behaviour_alert(record):
    """Convert a behaviour detection into the standard SOC alert format."""

    try:
        risk_score = max(
            0,
            min(100, int(record.get("risk_score", 0)))
        )
    except (ValueError, TypeError):
        risk_score = 0

    events = record.get("evidence", [])

    if not isinstance(events, list):
        events = []

    try:
        event_count = int(record.get("event_count", len(events)))
    except (ValueError, TypeError):
        event_count = len(events)

    event_count = max(0, event_count)

    return {
        "alert_id": str(record["alert_id"]),
        "source_module": "gcp_behaviour_alerts",
        "principal_or_resource": (
            record.get("principal_email") or "unknown"
        ),
        "category": str(record["rule_id"]),
        "risk_score": risk_score,
        "severity": classify_severity(risk_score),
        "description": str(
            record.get("description")
            or record.get("rule_name")
            or "Behavioural GCP activity requires investigation."
        ),
        "timestamp": record.get("first_seen"),
        "status": "OPEN",
        "rule_id": str(record["rule_id"]),
        "rule_name": str(
            record.get("rule_name") or "GCP Behaviour Anomaly"
        ),
        "confidence": str(record.get("confidence") or "LOW"),
        "mitre_technique_id": record.get("mitre_technique"),
        "mitre_technique_name": record.get("mitre_name"),
        "evidence": {
            "event_count": event_count,
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "data_source": str(record.get("source") or "UNKNOWN"),
            "events": events
        },
        "recommendation": str(
            record.get("recommendation")
            or (
                "Review the principal's activity and validate its "
                "business justification."
            )
        ),
        "detection_status": str(
            record.get("detection_status")
            or "REQUIRES_INVESTIGATION"
        )
    }


def deduplicate_alerts(alerts):
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

    # Load and normalise individual security reports.
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

            records = load_report_records(data)

            if not records:
                print(
                    f"[WARNING] No usable alert records in: "
                    f"{report_file.name}"
                )
                continue

            for alert in records:
                all_alerts.append(
                    normalise_alert(alert, report_file.stem)
                )

        except (json.JSONDecodeError, OSError) as error:
            print(
                f"[WARNING] Could not read "
                f"{report_file.name}: {error}"
            )

    # Load and normalise correlated GCP audit events.
    correlation_records = load_correlation_records()

    print(
        f"\nCorrelation records loaded: "
        f"{len(correlation_records)}"
    )

    for correlation in correlation_records:
        try:
            all_alerts.append(
                normalise_correlation(correlation)
            )
        except (KeyError, TypeError, ValueError) as error:
            print(
                f"[WARNING] Skipping invalid correlation record: {error}"
            )

    # Load and normalise behaviour-based detections.
    behaviour_records = load_behaviour_records(BEHAVIOUR_REPORT_FILE)

    print(
        f"Behaviour records loaded: "
        f"{len(behaviour_records)}"
    )

    for record in behaviour_records:
        try:
            all_alerts.append(
                normalise_behaviour_alert(record)
            )
        except (KeyError, TypeError, ValueError) as error:
            print(
                f"[WARNING] Skipping invalid behaviour record: {error}"
            )

    # Deduplicate and prioritise all SOC alerts.
    classified_alerts, summary = classify_alerts(all_alerts)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    rule_summary = dict(
        Counter(
            alert["rule_id"]
            for alert in classified_alerts
        )
    )

    source_summary = dict(
        Counter(
            alert["source_module"]
            for alert in classified_alerts
        )
    )

    report = {
        "total_alerts": len(classified_alerts),
        "severity_summary": summary,
        "rule_summary": rule_summary,
        "source_summary": source_summary,
        "correlation_alert_count": sum(
            1 for alert in classified_alerts
            if alert["source_module"] == "gcp_event_correlations"
        ),
        "behaviour_alert_count": sum(
            1 for alert in classified_alerts
            if alert["source_module"] == "gcp_behaviour_alerts"
        ),
        "alerts": classified_alerts
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n===== PHASE 2 GCP THREAT DETECTION ENGINE =====")
    print(f"\nTotal alerts: {len(classified_alerts)}")
    print(
        f"Correlation alerts: "
        f"{report['correlation_alert_count']}"
    )
    print(
        f"Behaviour alerts: "
        f"{report['behaviour_alert_count']}"
    )

    print("\nSeverity Summary:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"{severity}: {summary.get(severity, 0)}")

    print("\nDetection Rule Summary:")
    for rule_id, count in rule_summary.items():
        print(f"{rule_id}: {count}")

    print("\nSource Summary:")
    for source, count in source_summary.items():
        print(f"{source}: {count}")

    print("\nPrioritised Alerts:")
    for alert in classified_alerts:
        print(
            f"\n[{alert['severity']}] "
            f"Score: {alert['risk_score']} | "
            f"ID: {alert['alert_id']}"
        )
        print(f"Rule: {alert['rule_id']} - {alert['rule_name']}")
        print(f"Confidence: {alert['confidence']}")
        print(f"Source: {alert['source_module']}")
        print(f"Resource: {alert['principal_or_resource']}")

        if alert["mitre_technique_id"]:
            print(
                "MITRE ATT&CK: "
                f"{alert['mitre_technique_id']} - "
                f"{alert['mitre_technique_name']}"
            )

        print(f"Description: {alert['description']}")
        print(f"Recommendation: {alert['recommendation']}")

    print(f"\nConsolidated report: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
