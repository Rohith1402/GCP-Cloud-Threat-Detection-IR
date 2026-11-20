"""
MITRE ATT&CK mapping for Cyber SOC detection rules.

Single source of truth for which ATT&CK (Enterprise) technique each
detection rule maps to. Used by the rule-based classifier, event
correlations and behaviour-based detections.

Mappings describe the adversary behaviour a rule is designed to
surface. A mapped alert is not confirmation that the technique was
used; alerts still require analyst investigation.
"""


MITRE_MAPPINGS = {
    # Rule-based GCP detections
    "GCP-IAM-001": {
        "technique_id": "T1098.003",
        "technique_name": "Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "IAM policy changes are how new roles are granted.",
    },
    "GCP-IAM-002": {
        "technique_id": "T1098.001",
        "technique_name": "Additional Cloud Credentials",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "A new service-account key is an additional credential.",
    },
    "GCP-IAM-003": {
        "technique_id": "T1531",
        "technique_name": "Account Access Removal",
        "tactics": ["Impact"],
        "rationale": (
            "Key deletion can remove legitimate access. Often routine "
            "key rotation, so context is required."
        ),
    },
    "GCP-IAM-004": {
        "technique_id": "T1136.003",
        "technique_name": "Create Account: Cloud Account",
        "tactics": ["Persistence"],
        "rationale": "A new service account can be used for persistence.",
    },
    "GCP-IAM-005": {
        "technique_id": "T1098.003",
        "technique_name": "Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "A privileged role was assigned to a principal.",
    },
    "GCP-IAM-006": {
        "technique_id": "T1548.005",
        "technique_name": "Temporary Elevated Cloud Access",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "rationale": (
            "Permissions such as getAccessToken and actAs allow "
            "service-account impersonation."
        ),
    },
    "GCP-SA-001": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactics": ["Credential Access"],
        "rationale": "Repeated failed authentication attempts.",
    },
    "GCP-SCC-001": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactics": ["Collection"],
        "rationale": "Public access exposes bucket data to collection.",
    },
    "GCP-SCC-003": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "rationale": (
            "Relevant only if the vulnerable instance is "
            "internet-exposed."
        ),
    },

    # Event correlations
    "CORR-001": {
        "technique_id": "T1098.001",
        "technique_name": "Additional Cloud Credentials",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "Service account created, then a key generated for it.",
    },
    "CORR-002": {
        "technique_id": "T1098.003",
        "technique_name": "Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "New credentials followed by an IAM role change.",
    },
    "CORR-003": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "Repeated sensitive administrative changes.",
    },

    # Behaviour-based detections
    "BEHAV-001": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "Burst of sensitive IAM operations by one principal.",
    },
    "BEHAV-003": {
        "technique_id": "T1098.001",
        "technique_name": "Additional Cloud Credentials",
        "tactics": ["Persistence", "Privilege Escalation"],
        "rationale": "Service account created, then a key generated for it.",
    },
}


# Rules intentionally left unmapped, with the reason.
UNMAPPED_RULES = {
    "GCP-SCC-002": (
        "Posture finding (excessive permissions), not adversary behaviour."
    ),
    "GCP-SCC-004": (
        "Too generic to map to a specific technique without "
        "more network context."
    ),
    "BEHAV-002": (
        "Repeated service enablement has no clean ATT&CK match and is "
        "usually legitimate project setup."
    ),
    "GENERAL-001": "Generic activity, not a detection rule.",
}


def get_mitre(rule_id):
    """Return the ATT&CK mapping for a rule, or None if unmapped."""

    mapping = MITRE_MAPPINGS.get(str(rule_id or ""))

    if not mapping:
        return None

    return {
        "technique_id": mapping["technique_id"],
        "technique_name": mapping["technique_name"],
        "tactics": list(mapping["tactics"]),
    }


def mitre_fields(rule_id):
    """Return the standard SOC alert MITRE fields for a rule."""

    mapping = get_mitre(rule_id)

    if not mapping:
        return {
            "mitre_technique_id": None,
            "mitre_technique_name": None,
            "mitre_tactics": [],
        }

    return {
        "mitre_technique_id": mapping["technique_id"],
        "mitre_technique_name": mapping["technique_name"],
        "mitre_tactics": mapping["tactics"],
    }


# ATT&CK Enterprise tactics, in kill-chain order.
ENTERPRISE_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]


def build_coverage(fired_rules=None):
    """
    Build a per-tactic coverage matrix of the detection rules.

    fired_rules: optional mapping or iterable of rule IDs that produced
    alerts in the latest run. Techniques reached by those rules are
    marked as active.
    """

    fired = set(fired_rules or [])
    tactics = []

    for tactic_id, tactic_name in ENTERPRISE_TACTICS:
        techniques = {}

        for rule_id, mapping in MITRE_MAPPINGS.items():
            if tactic_name not in mapping["tactics"]:
                continue

            technique = techniques.setdefault(
                mapping["technique_id"],
                {
                    "technique_id": mapping["technique_id"],
                    "technique_name": mapping["technique_name"],
                    "rules": [],
                    "active": False,
                },
            )
            technique["rules"].append(rule_id)

            if rule_id in fired:
                technique["active"] = True

        technique_list = sorted(
            techniques.values(),
            key=lambda item: item["technique_id"],
        )

        for technique in technique_list:
            technique["rules"].sort()

        tactics.append({
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "covered": bool(technique_list),
            "active": any(item["active"] for item in technique_list),
            "rule_count": sum(len(item["rules"]) for item in technique_list),
            "techniques": technique_list,
        })

    return {
        "total_tactics": len(tactics),
        "covered_tactics": sum(1 for item in tactics if item["covered"]),
        "active_tactics": sum(1 for item in tactics if item["active"]),
        "mapped_rules": len(MITRE_MAPPINGS),
        "total_rules": len(MITRE_MAPPINGS) + len(UNMAPPED_RULES),
        "unique_techniques": len({
            mapping["technique_id"] for mapping in MITRE_MAPPINGS.values()
        }),
        "tactics": tactics,
        "unmapped_rules": [
            {"rule_id": rule_id, "reason": reason}
            for rule_id, reason in sorted(UNMAPPED_RULES.items())
        ],
    }


def coverage_markdown(coverage=None):
    """Render the coverage matrix as a Markdown table."""

    coverage = coverage or build_coverage()
    lines = [
        "| Tactic | Techniques | Rules |",
        "|---|---|---|",
    ]

    for tactic in coverage["tactics"]:
        if tactic["covered"]:
            techniques = "<br>".join(
                f"{item['technique_id']} {item['technique_name']}"
                for item in tactic["techniques"]
            )
            rules = ", ".join(
                rule
                for item in tactic["techniques"]
                for rule in item["rules"]
            )
        else:
            techniques, rules = "No coverage", "-"

        lines.append(
            f"| {tactic['tactic_id']} {tactic['tactic_name']} "
            f"| {techniques} | {rules} |"
        )

    return "\n".join(lines)


if __name__ == "__main__":
    summary = build_coverage()
    print(
        f"Tactics covered: {summary['covered_tactics']} of "
        f"{summary['total_tactics']} | Rules mapped: "
        f"{summary['mapped_rules']} of {summary['total_rules']} | "
        f"Unique techniques: {summary['unique_techniques']}\n"
    )
    print(coverage_markdown(summary))
