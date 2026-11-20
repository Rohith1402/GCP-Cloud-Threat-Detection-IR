"""
Alert tuning: analyst dispositions, suppression rules and roll-up.

Reads version-controlled tuning rules from config/alert_tuning.json and
applies them to prioritised SOC alerts.

Each alert gets:
- status: OPEN (active queue), SUPPRESSED (matched an approved tuning
  rule) or ROLLED_UP (generic GENERAL-001 raw event already evidence in
  a behaviour or correlation alert)
- disposition: UNREVIEWED, BENIGN_TRUE_POSITIVE (rule correct, activity
  authorised) or FALSE_POSITIVE (rule logic wrong)

Suppressed and rolled-up alerts are kept for audit, never deleted.
Every tuning rule needs a justification, an approver and an expiry
date; expired rules stop matching automatically.

Principals are matched by the SHA-256 hash of the normalised identity,
so the tuning file never contains an email address. Note: an unsalted
hash of a guessable address can be confirmed by someone who already
suspects it; it prevents casual exposure, not targeted guessing.
"""

import hashlib
import json
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

try:
    from detection.risk_prioritisation import principal_key
except ImportError:  # Script run directly: python detection/<file>.py
    from risk_prioritisation import principal_key


BASE_DIR = Path(__file__).resolve().parent.parent
TUNING_FILE = BASE_DIR / "config" / "alert_tuning.json"

DISPOSITIONS = {"BENIGN_TRUE_POSITIVE", "FALSE_POSITIVE"}
ROLL_UP_SOURCES = {"gcp_behaviour_alerts", "gcp_event_correlations"}
RAW_EVENT_SOURCE = "gcp_audit_logs"
# Only generic raw events are rolled up. A raw event that matched its own
# detection rule (for example GCP-IAM-001) always stays in the queue.
GENERAL_RULE = "GENERAL-001"
EXPIRY_WARNING_DAYS = 14

REQUIRED_FIELDS = (
    "id",
    "rule_id",
    "disposition",
    "justification",
    "approved_by",
    "approved_on",
    "expires_on",
    "match",
)


def hash_principal(value):
    """Return the SHA-256 hex digest of a normalised principal."""

    key = principal_key({"principal_or_resource": value})

    if not key:
        return None

    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _parse_date(value):
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value):
    if not value or not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def validate_rule(rule):
    """Return a list of problems with a tuning rule (empty if valid)."""

    if not isinstance(rule, dict):
        return ["rule is not an object"]

    problems = [
        f"missing {field}"
        for field in REQUIRED_FIELDS
        if not rule.get(field)
    ]

    if problems:
        return problems

    if rule["disposition"] not in DISPOSITIONS:
        problems.append("unknown disposition")

    if _parse_date(rule["approved_on"]) is None:
        problems.append("invalid approved_on date")

    if _parse_date(rule["expires_on"]) is None:
        problems.append("invalid expires_on date")

    if "@" in str(rule["approved_by"]):
        problems.append("approved_by must not contain an email address")

    match = rule["match"]

    if not isinstance(match, dict) or not match:
        problems.append("match must contain at least one condition")
    else:
        for field in ("first_seen_after", "first_seen_before"):
            if field in match and _parse_timestamp(match[field]) is None:
                problems.append(f"invalid {field}")

        if "principal_sha256" in match:
            digest = str(match["principal_sha256"])
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                problems.append("principal_sha256 must be a SHA-256 hex digest")

    return problems


def load_tuning_rules(tuning_file=TUNING_FILE):
    """Load valid tuning rules; invalid ones are reported and skipped."""

    try:
        tuning_file = Path(tuning_file)

        if not tuning_file.exists():
            return []

        with tuning_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except (json.JSONDecodeError, OSError) as error:
        print(f"[WARNING] Could not read tuning file: {error}")
        return []

    rules = data.get("rules", []) if isinstance(data, dict) else []
    valid = []

    for rule in rules if isinstance(rules, list) else []:
        problems = validate_rule(rule)

        if problems:
            rule_id = rule.get("id", "unknown") if isinstance(rule, dict) else "unknown"
            print(
                f"[WARNING] Skipping tuning rule {rule_id}: "
                + "; ".join(problems)
            )
            continue

        valid.append(rule)

    return valid


def is_expired(rule, today):
    return _parse_date(rule["expires_on"]) < today


def _alert_methods(alert):
    evidence = alert.get("evidence")

    if not isinstance(evidence, dict):
        return []

    events = evidence.get("events")

    if isinstance(events, list) and events:
        return [
            str(event.get("method_name") or "")
            for event in events
            if isinstance(event, dict)
        ]

    method = evidence.get("method")
    return [str(method)] if method else []


def _alert_first_seen(alert):
    evidence = alert.get("evidence")

    if isinstance(evidence, dict) and evidence.get("first_seen"):
        return _parse_timestamp(evidence["first_seen"])

    return _parse_timestamp(alert.get("timestamp"))


def rule_matches(alert, rule, today):
    """Return True if an unexpired tuning rule matches the alert."""

    if alert.get("rule_id") != rule["rule_id"] or is_expired(rule, today):
        return False

    match = rule["match"]

    if "principal_sha256" in match:
        if hash_principal(alert.get("principal_or_resource")) != match["principal_sha256"]:
            return False

    if "first_seen_after" in match or "first_seen_before" in match:
        first_seen = _alert_first_seen(alert)

        if first_seen is None:
            return False

        after = _parse_timestamp(match.get("first_seen_after"))
        before = _parse_timestamp(match.get("first_seen_before"))

        if after and first_seen < after:
            return False

        if before and first_seen > before:
            return False

    if "methods" in match:
        allowed = [str(item).lower() for item in match["methods"]]
        methods = _alert_methods(alert)

        if not methods:
            return False

        if not all(
            any(pattern in method.lower() for pattern in allowed)
            for method in methods
        ):
            return False

    return True


def _covering_alerts(alerts):
    """Map raw event IDs to the behaviour/correlation alert that covers them."""

    covered = {}

    for alert in alerts:
        if alert.get("source_module") not in ROLL_UP_SOURCES:
            continue

        evidence = alert.get("evidence")
        events = evidence.get("events") if isinstance(evidence, dict) else None

        for event in events if isinstance(events, list) else []:
            if isinstance(event, dict) and event.get("event_id"):
                covered.setdefault(str(event["event_id"]), alert["alert_id"])

    return covered


def apply_tuning(alerts, rules, today=None):
    """
    Apply tuning rules and roll-up to alerts.

    Returns new alert dictionaries: active (OPEN) alerts first in their
    existing order, then suppressed and rolled-up alerts.
    """

    today = today or datetime.now(timezone.utc).date()
    covered = _covering_alerts(alerts)
    tuned = []

    for alert in alerts:
        result = {
            **alert,
            "status": "OPEN",
            "disposition": "UNREVIEWED",
            "tuning": None,
            "covered_by": None,
        }

        rule = next(
            (item for item in rules if rule_matches(alert, item, today)),
            None,
        )

        if rule:
            result["status"] = "SUPPRESSED"
            result["disposition"] = rule["disposition"]
            result["tuning"] = {
                "tuning_id": rule["id"],
                "justification": rule["justification"],
                "approved_by": rule["approved_by"],
                "approved_on": rule["approved_on"],
                "expires_on": rule["expires_on"],
            }
        elif (
            alert.get("source_module") == RAW_EVENT_SOURCE
            and alert.get("rule_id") == GENERAL_RULE
            and str(alert.get("alert_id")) in covered
        ):
            result["status"] = "ROLLED_UP"
            result["covered_by"] = covered[str(alert["alert_id"])]

        tuned.append(result)

    order = {"OPEN": 0, "SUPPRESSED": 1, "ROLLED_UP": 2}
    return sorted(tuned, key=lambda item: order[item["status"]])


def build_quality_report(alerts, rules, today=None):
    """Per-rule detection quality and tuning-rule health."""

    today = today or datetime.now(timezone.utc).date()
    per_rule = defaultdict(Counter)

    for alert in alerts:
        rule_id = alert.get("rule_id") or "UNKNOWN"
        per_rule[rule_id]["fired"] += 1
        per_rule[rule_id][alert.get("status", "OPEN")] += 1

        disposition = alert.get("disposition")
        if disposition in DISPOSITIONS:
            per_rule[rule_id][disposition] += 1

    rules_report = []

    for rule_id in sorted(per_rule):
        counts = per_rule[rule_id]
        fired = counts["fired"]
        noise = counts["SUPPRESSED"] + counts["ROLLED_UP"]

        rules_report.append({
            "rule_id": rule_id,
            "fired": fired,
            "active": counts["OPEN"],
            "suppressed": counts["SUPPRESSED"],
            "rolled_up": counts["ROLLED_UP"],
            "benign_true_positive": counts["BENIGN_TRUE_POSITIVE"],
            "false_positive": counts["FALSE_POSITIVE"],
            "noise_rate": round(noise / fired, 2) if fired else 0.0,
        })

    warning_date = today + timedelta(days=EXPIRY_WARNING_DAYS)

    return {
        "total_alerts": len(alerts),
        "active_alerts": sum(1 for a in alerts if a.get("status") == "OPEN"),
        "suppressed_alerts": sum(1 for a in alerts if a.get("status") == "SUPPRESSED"),
        "rolled_up_alerts": sum(1 for a in alerts if a.get("status") == "ROLLED_UP"),
        "rules": rules_report,
        "tuning_rules": [
            {
                "tuning_id": rule["id"],
                "rule_id": rule["rule_id"],
                "disposition": rule["disposition"],
                "expires_on": rule["expires_on"],
                "state": (
                    "EXPIRED" if is_expired(rule, today)
                    else "EXPIRING_SOON"
                    if _parse_date(rule["expires_on"]) <= warning_date
                    else "ACTIVE"
                ),
            }
            for rule in rules
        ],
    }
