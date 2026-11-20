"""
Publish SOC results for the public Cyber SOC website.

Reads reports/consolidated_soc_alerts.json (the output of the Python
detection pipeline) and writes a sanitised copy to
website/data/soc_alerts.json, which the website loads.

Sanitisation:
- Real email addresses are replaced with stable aliases
  (user-01, service-account-01). Fictional example.com
  addresses used in training data are kept.
- Resource names are replaced with their type (for example
  "Storage bucket"), so no bucket, instance or project names appear.
- GCP project IDs and project numbers are replaced with [PROJECT].
- Long numeric identifiers are replaced with [ID].

A final leak check refuses to write the file if any real email
address or project identifier survives sanitisation.
"""

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from detection.behaviour_anomaly_detector import RULES as BEHAVIOUR_RULES
    from detection.mitre_mapping import build_coverage
except ImportError:  # Script run directly: python detection/<file>.py
    from behaviour_anomaly_detector import RULES as BEHAVIOUR_RULES
    from mitre_mapping import build_coverage


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "reports" / "consolidated_soc_alerts.json"
OUTPUT_FILE = BASE_DIR / "website" / "data" / "soc_alerts.json"

# Where each source module's data comes from. Edit if a module's
# input changes between real GCP data and synthetic training data.
SOURCE_DATA_LABELS = {
    "gcp_audit_logs": "REAL",
    "gcp_event_correlations": "REAL",
    "iam_security_alerts": "REAL",
    "iam_privilege_alerts": "REAL",
    "audit_log_alerts": "SYNTHETIC",
    "service_account_alerts": "SYNTHETIC",
    "scc_security_alerts": "SYNTHETIC",
}

EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PROJECT_PATTERN = re.compile(r"projects/([A-Za-z0-9][A-Za-z0-9-]{3,})")
LONG_NUMBER_PATTERN = re.compile(r"\d{10,}")
RESOURCE_PATH_PATTERN = re.compile(r"projects/[^\s,;]+")

SAFE_EMAIL_DOMAINS = ("example.com",)

# Resource names are never published; only their type is shown.
RESOURCE_TYPES = (
    ("/buckets/", "Storage bucket"),
    ("/instances/", "Compute instance"),
    ("/serviceaccounts/", "Service account"),
    ("projects/", "GCP project"),
)
PLACEHOLDER_PROJECTS = {"project", "demo-project", "synthetic-security-lab"}


class SanitisationError(ValueError):
    """Raised when sensitive data survives sanitisation."""


def is_safe_email(email):
    domain = email.rsplit("@", 1)[-1].lower()
    return any(
        domain == safe or domain.endswith("." + safe)
        for safe in SAFE_EMAIL_DOMAINS
    )


def iter_strings(value):
    """Yield every string inside nested lists and dictionaries."""

    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(key)
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


class Sanitiser:
    """Consistently replaces sensitive identifiers across a report."""

    def __init__(self, data):
        self.email_aliases = {}
        self.counters = Counter()
        self.project_tokens = set()

        for text in iter_strings(data):
            for match in PROJECT_PATTERN.findall(text):
                if match.lower() not in PLACEHOLDER_PROJECTS:
                    self.project_tokens.add(match)

    def alias_email(self, match):
        email = match.group(0)

        if is_safe_email(email):
            return email

        key = email.lower()

        if key not in self.email_aliases:
            kind = (
                "service-account"
                if key.endswith("gserviceaccount.com")
                else "user"
            )
            self.counters[kind] += 1
            self.email_aliases[key] = f"{kind}-{self.counters[kind]:02d}"

        return self.email_aliases[key]

    def clean_text(self, text):
        text = EMAIL_PATTERN.sub(self.alias_email, text)
        text = RESOURCE_PATH_PATTERN.sub("[RESOURCE]", text)

        # Longest first, so a project ID is not partly replaced
        # by a shorter token it contains.
        for token in sorted(self.project_tokens, key=len, reverse=True):
            text = text.replace(token, "[PROJECT]")

        return LONG_NUMBER_PATTERN.sub("[ID]", text)

    def clean(self, value):
        if isinstance(value, str):
            return self.clean_text(value)
        if isinstance(value, dict):
            return {
                self.clean(key): self.clean(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        return value


def check_for_leaks(data, sanitiser):
    """Refuse to publish if a real identifier is still present."""

    for text in iter_strings(data):
        for email in EMAIL_PATTERN.findall(text):
            if not is_safe_email(email):
                raise SanitisationError(
                    "Unmasked email address found in output."
                )

        for token in sanitiser.project_tokens:
            if token in text:
                raise SanitisationError(
                    "Unmasked GCP project identifier found in output."
                )

        if "projects/" in text:
            raise SanitisationError(
                "GCP resource name found in output."
            )

        if LONG_NUMBER_PATTERN.search(text):
            raise SanitisationError(
                "Unmasked numeric identifier found in output."
            )


def load_consolidated_alerts(input_file=INPUT_FILE):
    input_file = Path(input_file)

    with input_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict):
        data = data.get("alerts", [])

    if not isinstance(data, list):
        raise ValueError("Unexpected consolidated alert report format.")

    return [item for item in data if isinstance(item, dict)]


def data_label(alert):
    evidence = alert.get("evidence")

    if alert.get("source_module") == "gcp_behaviour_alerts":
        if isinstance(evidence, dict):
            return str(evidence.get("data_source") or "UNKNOWN")
        return "UNKNOWN"

    return SOURCE_DATA_LABELS.get(
        alert.get("source_module"),
        "UNKNOWN",
    )


def evidence_summary(alert):
    """Keep sequence evidence for behaviour and correlation alerts."""

    evidence = alert.get("evidence")

    if not isinstance(evidence, dict) or "events" not in evidence:
        return None

    events = evidence.get("events")

    if not isinstance(events, list):
        events = []

    return {
        "event_count": evidence.get("event_count", len(events)),
        "first_seen": evidence.get("first_seen"),
        "last_seen": evidence.get("last_seen"),
        "events": [
            {
                "event_id": event.get("event_id"),
                "timestamp": event.get("timestamp"),
                "method_name": event.get("method_name"),
                "service_name": event.get("service_name"),
            }
            for event in events
            if isinstance(event, dict)
        ],
    }


def public_principal(value):
    """
    Keep identities (masked later as aliases) but never publish
    resource names: replace them with a generic resource type.
    """

    text = str(value or "")

    if EMAIL_PATTERN.search(text):
        return text

    lowered = text.lower()

    for marker, label in RESOURCE_TYPES:
        if marker in lowered:
            return label

    return "GCP resource" if text else "unknown"


def to_public_alert(alert):
    return {
        "alert_id": alert.get("alert_id"),
        "rule_id": alert.get("rule_id"),
        "rule_name": alert.get("rule_name"),
        "severity": str(alert.get("severity") or "LOW").upper(),
        "risk_score": alert.get("risk_score", 0),
        "confidence": alert.get("confidence"),
        "source_module": alert.get("source_module"),
        "data_label": data_label(alert),
        "principal": public_principal(alert.get("principal_or_resource")),
        "description": alert.get("description"),
        "mitre_technique_id": alert.get("mitre_technique_id"),
        "mitre_technique_name": alert.get("mitre_technique_name"),
        "mitre_tactics": list(alert.get("mitre_tactics") or []),
        "timestamp": alert.get("timestamp"),
        "status": alert.get("status"),
        "recommendation": alert.get("recommendation"),
        "evidence": evidence_summary(alert),
    }


def behaviour_rule_catalogue():
    return [
        {
            "rule_id": rule_id,
            "name": rule["name"],
            "description": rule["description"],
            "window_minutes": rule["window_minutes"],
            "threshold": rule["threshold"],
            "risk_score": rule["risk_score"],
            "confidence": rule["confidence"],
            "mitre_technique": rule["mitre_technique"],
            "mitre_name": rule["mitre_name"],
        }
        for rule_id, rule in BEHAVIOUR_RULES.items()
    ]


def build_public_report(alerts, generated_at=None):
    public_alerts = sorted(
        (to_public_alert(alert) for alert in alerts),
        key=lambda item: item["risk_score"] or 0,
        reverse=True,
    )

    def count_source(module):
        return sum(
            1 for alert in public_alerts
            if alert["source_module"] == module
        )

    report = {
        "source": "PYTHON_DETECTION_PIPELINE",
        "generated_at": (
            generated_at or datetime.now(timezone.utc).isoformat()
        ),
        "summary": {
            "total_alerts": len(public_alerts),
            "severity": dict(
                Counter(alert["severity"] for alert in public_alerts)
            ),
            "data_labels": dict(
                Counter(alert["data_label"] for alert in public_alerts)
            ),
            "rules": dict(
                Counter(alert["rule_id"] for alert in public_alerts)
            ),
            "behaviour_alerts": count_source("gcp_behaviour_alerts"),
            "correlation_alerts": count_source("gcp_event_correlations"),
        },
        "behaviour_rules": behaviour_rule_catalogue(),
        "mitre_coverage": build_coverage(
            alert["rule_id"] for alert in public_alerts
        ),
        "alerts": public_alerts,
    }

    sanitiser = Sanitiser(report)
    cleaned = sanitiser.clean(report)
    check_for_leaks(cleaned, sanitiser)

    return cleaned


def main(input_file=INPUT_FILE, output_file=OUTPUT_FILE):
    alerts = load_consolidated_alerts(input_file)
    report = build_public_report(alerts)

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    summary = report["summary"]

    print("\n===== CYBER SOC WEBSITE DATA =====")
    print(f"\nAlerts published: {summary['total_alerts']}")
    print(f"Behaviour alerts: {summary['behaviour_alerts']}")
    print(f"Correlation alerts: {summary['correlation_alerts']}")
    print(f"Data labels: {summary['data_labels']}")
    print("Sanitisation and leak check: passed")
    print(f"\nWebsite data: {output_file}")

    return report


if __name__ == "__main__":
    main()
