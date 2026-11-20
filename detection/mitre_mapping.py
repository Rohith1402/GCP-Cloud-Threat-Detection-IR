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
