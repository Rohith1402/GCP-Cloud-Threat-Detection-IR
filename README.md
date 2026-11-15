# GCP Cloud Threat Detection & Incident Response

A hands-on Google Cloud security monitoring and detection project built using Python.

The goal is to demonstrate practical cloud security, IAM monitoring, security alert classification, and SOC investigation capabilities.

## Project Objectives

- Identify potentially risky GCP IAM role assignments.
- Analyse cloud IAM policies.
- Detect public and broadly accessible principals.
- Identify privileged service-account permissions.
- Generate structured security alerts.
- Classify findings based on risk scores and severity.
- Develop automated incident response capabilities.

## Current Implementation

### GCP IAM Misconfiguration Detection

The first detection module analyses exported GCP IAM policies.

Current detection capabilities:

- Owner role assignments.
- Editor role assignments.
- Public principal exposure.
- Broadly accessible principals.
- Privileged service-account role assignments.

### Risk Classification

| Risk Score | Severity |
|---|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

### Security Reporting

The detector generates structured JSON alerts containing:

- Timestamp
- Principal
- IAM role
- Risk score
- Severity
- Detection findings
- Event source

## Technology Stack

- Google Cloud Platform
- Cloud IAM
- Python
- JSON
- Python unittest
- Git and GitHub

## Project Structure

```text
GCP-Cloud-Security-Lab/
├── detection/
│   └── iam_misconfiguration.py
├── tests/
│   └── test_iam_detection.py
├── sample_data/
├── reports/
├── .gitignore
└── README.md
```

## Running the Project

Clone the repository:

```bash
git clone https://github.com/Rohith1402/GCP-Cloud-Threat-Detection-IR.git
```

Navigate into the project:

```bash
cd GCP-Cloud-Threat-Detection-IR
```

Run the IAM detector:

```bash
python3 detection/iam_misconfiguration.py
```

Run automated tests:

```bash
python3 -m unittest discover -s tests -v
```

## Testing

The current IAM detection module includes five automated unit tests covering:

- Owner role detection
- Public principal detection
- Privileged service-account role detection
- Normal Viewer role handling
- Severity classification

All five tests passed during initial development.

## Planned Enhancements

- IAM privilege escalation detection
- Cloud Audit Logs monitoring
- Suspicious service-account activity detection
- Security Command Center findings analysis
- Advanced Python security alert classification
- Automated incident response workflows
- Security monitoring dashboard

## Disclaimer

This project is developed for educational and authorised security testing purposes. Detection rules are heuristic and require contextual investigation before treating an alert as malicious.

No automated remediation is enabled by default.
