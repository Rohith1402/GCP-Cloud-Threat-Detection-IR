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

## Module 2: IAM Privilege Escalation Detection

This module analyses IAM policy bindings against a role-permission catalogue to identify sensitive IAM capabilities.

### Detection capabilities
- Detects sensitive service-account permissions.
- Identifies permissions that can modify project IAM policies.
- Flags role creation and role-update capabilities.
- Calculates risk scores and classifies findings as LOW, MEDIUM, or HIGH.
- Generates a JSON alert report.

### Test coverage
- Owner role with sensitive permissions.
- Service Account Token Creator role.
- Normal Viewer role.
- Unknown roles.
- Severity classification.

### Run tests

```bash
python3 -m unittest discover -s tests -v
```

**Note:** `sample_data/role_definitions.json` currently contains synthetic test data. It is not a verified export of Google's predefined IAM roles.

## Module 3: GCP Cloud Audit Logs Monitoring

This module analyses Cloud Audit Log events using Python to identify potentially suspicious administrative activities.

### Detection capabilities
- IAM policy modification detection.
- Service account key creation detection.
- Failed administrative operation detection.
- Risk scoring and severity classification.
- JSON alert report generation.

### Test coverage
- IAM policy modification.
- Service account key creation.
- Failed service account creation.
- Normal operation filtering.
- Severity classification.

### Run detection

```bash
python3 detection/audit_log_monitor.py
```

### Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

**Note:** The current audit log events are synthetic training data, not live GCP audit records.

## Module 4: Suspicious Service Account Activity Detection

This module analyses service-account activity events to identify potentially suspicious behaviour.

### Detection capabilities
- Service-account key creation detection.
- Authentication outside configured normal hours.
- Multiple failed authentication attempts.
- Failed authentication detection.
- Risk scoring and severity classification.
- JSON alert report generation.

### Test coverage
- Service-account key creation.
- Authentication outside normal hours.
- Multiple failed authentication attempts.
- Normal authentication filtering.
- Severity classification.

### Run detection

```bash
python3 detection/service_account_monitor.py
```

### Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

**Note:** The current service-account events are synthetic training data.

## Module 5: Security Command Center Findings Analysis

This module analyses Security Command Center findings and prioritises active cloud security risks.

### Detection capabilities
- Public cloud storage exposure detection.
- Critical vulnerability prioritisation.
- Over-privileged IAM finding analysis.
- Suspicious network activity categorisation.
- Inactive finding filtering.
- Risk scoring and priority classification.
- JSON alert report generation.

### Test coverage
- Public bucket access.
- Over-privileged IAM.
- Inactive finding filtering.
- Suspicious network activity.
- Risk-based finding sorting.
- Severity classification.

### Run analyzer

```bash
python3 detection/scc_findings_analyzer.py
```

### Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

**Note:** Current SCC findings are synthetic training data, not live Security Command Center findings.

## Module 6: Unified SOC Alert Classification Engine

This module consolidates security alerts from Modules 1–5 into a central SOC alert feed.

### Capabilities
- Normalises different security alert formats.
- Applies consistent risk-based severity classification.
- Supports CRITICAL, HIGH, MEDIUM and LOW priorities.
- Deduplicates alerts within the same source module.
- Sorts alerts by risk score.
- Generates consolidated severity summaries.
- Exports a unified JSON alert report.

### Risk classification
| Risk score | Severity |
|---|---|
| 90–100 | CRITICAL |
| 70–89 | HIGH |
| 30–69 | MEDIUM |
| 0–29 | LOW |

### Run classifier
```bash
python3 detection/alert_classifier.py
```

### Run automated tests
```bash
python3 -m unittest discover -s tests -v
```

**Note:** This module consolidates locally generated reports from synthetic training data. It is not yet connected to a live SIEM or GCP event stream.

## Module 7: Incident Response Automation

This module generates incident response plans from consolidated SOC alerts.

### Capabilities
- Reviews consolidated security alerts.
- Generates incidents for CRITICAL and HIGH severity alerts.
- Assigns unique, consistent incident references.
- Extracts affected principals and resources.
- Recommends response actions based on alert characteristics.
- Assigns response priorities.
- Maintains analyst approval status.
- Saves incident records in JSON format.

### Safety controls
- Simulation-only execution.
- No automatic changes to GCP resources.
- Analyst approval required before response.
- Local incident audit report.

### Run incident response engine
```bash
python3 detection/incident_response.py
```

### Run Module 7 tests
```bash
python3 -m unittest tests.test_incident_response -v
```

### Run complete test suite
```bash
python3 -m unittest discover -s tests -v
```

**Validation:** All 43 project tests passed.

**Note:** The project currently uses synthetic training data and locally generated reports. Live GCP integrations and real response actions are not enabled.
