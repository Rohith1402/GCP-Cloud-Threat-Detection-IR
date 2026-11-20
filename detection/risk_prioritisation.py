"""
Context-aware alert prioritisation for the Cyber SOC pipeline.

Each alert keeps its rule-based risk_score and severity unchanged.
This module adds:

- priority_score: risk_score adjusted for context, capped to 0-100
- priority: P1-P4 band derived from priority_score
- score_factors: every adjustment applied, with the reason

Adjustments:
- Confidence: HIGH +5, MEDIUM 0, LOW -10
- Privileged principal: +10 when the same principal has a privileged
  role or sensitive IAM permission finding (GCP-IAM-005 / GCP-IAM-006)
- Multiple signals: +10 when two or more different detection rules
  fired for the same principal
- High-impact tactic: +5 for Privilege Escalation, Credential Access
  or Impact

GENERAL-001 events do not count as a signal and receive no context
boosts. Synthetic and simulated alerts are not down-weighted; their
data label already distinguishes them.
"""

from collections import defaultdict


GENERAL_RULE = "GENERAL-001"

PRIVILEGE_RULES = {"GCP-IAM-005", "GCP-IAM-006"}

HIGH_IMPACT_TACTICS = {
    "Privilege Escalation",
    "Credential Access",
    "Impact",
}

CONFIDENCE_ADJUSTMENTS = {
    "HIGH": 5,
    "MEDIUM": 0,
    "LOW": -10,
}

PRIVILEGED_PRINCIPAL_BOOST = 10
MULTI_SIGNAL_BOOST = 10
HIGH_IMPACT_TACTIC_BOOST = 5

PRIORITY_BANDS = (
    (90, "P1"),
    (70, "P2"),
    (40, "P3"),
    (0, "P4"),
)

IDENTITY_PREFIXES = (
    "user:",
    "serviceaccount:",
    "group:",
    "domain:",
)


def principal_key(alert):
    """Normalise a principal so the same identity matches across modules."""

    value = str(alert.get("principal_or_resource") or "").strip().lower()

    for prefix in IDENTITY_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break

    if not value or value == "unknown":
        return None

    return value


def priority_band(score):
    for threshold, band in PRIORITY_BANDS:
        if score >= threshold:
            return band
    return "P4"


def _to_score(value):
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def build_entity_context(alerts):
    """Collect, per principal, which rules fired."""

    rules_by_principal = defaultdict(set)

    for alert in alerts:
        rule_id = alert.get("rule_id")
        key = principal_key(alert)

        if key and rule_id and rule_id != GENERAL_RULE:
            rules_by_principal[key].add(rule_id)

    return rules_by_principal


def score_alert(alert, rules_by_principal):
    """Return priority fields for one alert."""

    base = _to_score(alert.get("risk_score", 0))
    rule_id = alert.get("rule_id")
    key = principal_key(alert)
    is_signal = bool(rule_id) and rule_id != GENERAL_RULE

    factors = [{
        "factor": "Rule risk score",
        "adjustment": base,
        "reason": f"Base score from {rule_id or 'unknown rule'}",
    }]

    confidence = str(alert.get("confidence") or "").upper()
    confidence_adjustment = CONFIDENCE_ADJUSTMENTS.get(confidence, 0)

    if confidence_adjustment:
        factors.append({
            "factor": "Confidence",
            "adjustment": confidence_adjustment,
            "reason": f"{confidence.title()} confidence detection",
        })

    if is_signal and key:
        principal_rules = rules_by_principal.get(key, set())

        privilege_findings = principal_rules & PRIVILEGE_RULES

        if privilege_findings and rule_id not in PRIVILEGE_RULES:
            factors.append({
                "factor": "Privileged principal",
                "adjustment": PRIVILEGED_PRINCIPAL_BOOST,
                "reason": (
                    "Principal also has privilege findings: "
                    + ", ".join(sorted(privilege_findings))
                ),
            })

        if len(principal_rules) >= 2:
            factors.append({
                "factor": "Multiple signals",
                "adjustment": MULTI_SIGNAL_BOOST,
                "reason": (
                    f"{len(principal_rules)} different rules fired for "
                    "this principal"
                ),
            })

    tactics = set(alert.get("mitre_tactics") or [])
    impact_tactics = tactics & HIGH_IMPACT_TACTICS

    if is_signal and impact_tactics:
        factors.append({
            "factor": "High-impact tactic",
            "adjustment": HIGH_IMPACT_TACTIC_BOOST,
            "reason": "MITRE tactic: " + ", ".join(sorted(impact_tactics)),
        })

    score = max(0, min(100, sum(item["adjustment"] for item in factors)))

    return {
        "priority_score": score,
        "priority": priority_band(score),
        "score_factors": factors,
    }


def prioritise_alerts(alerts):
    """
    Add priority fields to every alert and sort by priority.

    Returns new alert dictionaries; the input alerts are not modified.
    Ties are broken by the original risk score.
    """

    rules_by_principal = build_entity_context(alerts)

    prioritised = [
        {**alert, **score_alert(alert, rules_by_principal)}
        for alert in alerts
    ]

    prioritised.sort(
        key=lambda item: (
            item["priority_score"],
            _to_score(item.get("risk_score", 0)),
        ),
        reverse=True,
    )

    return prioritised
