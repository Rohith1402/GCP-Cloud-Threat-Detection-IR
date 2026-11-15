# GCP Cloud Threat Detection & Incident Response

A hands-on Google Cloud security monitoring and threat detection project built using Python.

This project demonstrates practical cloud security monitoring, IAM risk analysis, Cloud Audit Logs collection, security alert classification, SOC investigation, and simulation-based incident response.

## Project Objectives

- Identify potentially risky GCP IAM role assignments.
- Analyse cloud IAM policies and privileged permissions.
- Detect public and broadly accessible principals.
- Collect and analyse GCP Cloud Audit Logs.
- Identify suspicious service-account activities.
- Analyse Security Command Center findings.
- Generate structured security alerts.
- Classify and prioritise findings based on risk scores and severity.
- Consolidate alerts into a unified SOC workflow.
- Generate incident response recommendations.
- Visualise security events through an interactive SOC dashboard.

## Project Architecture

The project contains eight security modules:

1. GCP IAM Misconfiguration Detection
2. IAM Privilege Escalation Detection
3. Cloud Audit Logs Monitoring
4. Suspicious Service Account Activity Detection
5. Security Command Center Findings Analysis
6. Unified SOC Alert Classification Engine
7. Incident Response Automation
8. SOC Security Dashboard and Reporting

The project combines synthetic security training datasets with an on-demand integration that retrieves real GCP Admin Activity audit events.

## Technology Stack

- Google Cloud Platform
- Google Cloud IAM
- Google Cloud Audit Logs
- Google Cloud Logging Python Client
- Python 3.12
- Streamlit
- Plotly
- Pandas
- JSON
- Python unittest
- Git and GitHub

---

## Module 1: GCP IAM Misconfiguration Detection

Analyses exported GCP IAM policies to identify potentially risky permissions and access configurations.

### Detection capabilities

- Owner role assignments.
- Editor role assignments.
- Public principal exposure.
- Broadly accessible principals.
- Privileged service-account role assignments.

### Security reporting

Generates structured JSON alerts containing:

- Timestamp
- Principal
- IAM role
- Risk score
- Severity
- Detection findings
- Event source

### Run detector

```bash
python3 detection/iam_misconfiguration.py
```

---

## Module 2: IAM Privilege Escalation Detection

Analyses IAM policy bindings against a role-permission catalogue to identify sensitive IAM capabilities.

### Detection capabilities

- Detects sensitive service-account permissions.
- Identifies permissions that can modify project IAM policies.
- Flags role creation and role-update capabilities.
- Calculates risk scores.
- Generates JSON alert reports.

### Test coverage

- Owner role with sensitive permissions.
- Service Account Token Creator role.
- Normal Viewer role.
- Unknown roles.
- Severity classification.

**Note:** `sample_data/role_definitions.json` contains synthetic test data and is not a verified export of Google's predefined IAM roles.

---

## Module 3: GCP Cloud Audit Logs Monitoring

This module analyses Cloud Audit Log events to identify potentially suspicious administrative activities.

### Detection capabilities

- IAM policy modification detection.
- Service-account key creation detection.
- Failed administrative operation detection.
- Risk scoring and severity classification.
- JSON alert report generation.

### Run detection

```bash
python3 detection/audit_log_monitor.py
```

### Live GCP integration

An additional collector retrieves real GCP Admin Activity audit events using the Google Cloud Logging Python client.

**Collector capabilities:**

- Authenticates using Google Application Default Credentials.
- Retrieves Admin Activity audit events from the configured GCP project.
- Collects events from the previous 24 hours.
- Retrieves up to 100 events per execution.
- Extracts event IDs, timestamps, methods, services, principals and resources.
- Saves the collected events to a local JSON report.

### Configure authentication

Install and configure the Google Cloud CLI, then authenticate:

```bash
gcloud auth login
```

Configure Application Default Credentials:

```bash
gcloud auth application-default login --disable-quota-project
```

Install the logging dependency:

```bash
python3 -m pip install google-cloud-logging
```

### Run live GCP collector

```bash
python detection/gcp_audit_log_collector.py
```

Output:

```text
reports/gcp_audit_logs.json
```

The collector retrieves a snapshot when executed. It does not currently provide continuous streaming or scheduled ingestion.

**Important:** Real audit events are not automatically evidence of malicious activity. They require contextual investigation.

---

## Module 4: Suspicious Service Account Activity Detection

Analyses service-account activity events to identify potentially suspicious behaviour.

### Detection capabilities

- Service-account key creation detection.
- Authentication outside configured normal hours.
- Multiple failed authentication attempts.
- Failed authentication detection.
- Risk scoring and severity classification.
- JSON alert report generation.

### Run detection

```bash
python3 detection/service_account_monitor.py
```

**Note:** The existing service-account training events are synthetic data.

---

## Module 5: Security Command Center Findings Analysis

Analyses Security Command Center findings and prioritises cloud security risks.

### Detection capabilities

- Public cloud storage exposure detection.
- Critical vulnerability prioritisation.
- Over-privileged IAM finding analysis.
- Suspicious network activity categorisation.
- Inactive finding filtering.
- Risk scoring and priority classification.
- JSON alert report generation.

### Run analyzer

```bash
python3 detection/scc_findings_analyzer.py
```

**Note:** Existing SCC findings are synthetic training data, not live Security Command Center findings.

---

## Module 6: Unified SOC Alert Classification Engine

Consolidates security alerts from Modules 1–5 and the GCP Cloud Audit Logs collector into a central SOC alert feed.

### Capabilities

- Normalises different security alert formats.
- Integrates collected GCP audit events.
- Applies consistent risk-based severity classification.
- Supports CRITICAL, HIGH, MEDIUM and LOW priorities.
- Deduplicates alerts within the same source module.
- Sorts alerts by risk score.
- Generates consolidated severity summaries.
- Exports a unified JSON alert report.

### Severity classification

| Risk score | Severity |
|---|---|
| 90–100 | CRITICAL |
| 70–89 | HIGH |
| 30–69 | MEDIUM |
| 0–29 | LOW |

### Initial GCP event triage rules

| GCP audit event | Initial risk score |
|---|---:|
| Service-account key creation | 90 |
| IAM policy modification | 80 |
| Service-account key deletion | 70 |
| Service-account creation | 40 |
| Service enablement | 20 |
| Project creation | 20 |
| Operation status retrieval | 5 |
| Other events | 10 |

These are initial heuristic triage scores, not proof of malicious activity. Contextual detection and analyst investigation are required.

### Run classifier

```bash
python detection/alert_classifier.py
```

Output:

```text
reports/consolidated_soc_alerts.json
```

---

## Module 7: Incident Response Automation

Generates incident response plans from consolidated SOC alerts.

### Capabilities

- Reviews consolidated security alerts.
- Generates incidents for CRITICAL and HIGH severity alerts.
- Assigns unique incident references.
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

---

## Module 8: SOC Security Dashboard and Reporting

An interactive SOC dashboard built using Streamlit, Plotly and Pandas.

### Dashboard features

- Total security alerts and incident KPIs.
- Alert severity distribution.
- Alerts by detection module.
- Risk score distribution.
- Prioritised SOC alert table.
- Incident response tracking.
- CSV exports for alerts and incidents.
- Live GCP Cloud Audit Events section in the local environment.
- Masking of displayed email addresses.
- Local security report and public demo data separation.

### Run the dashboard

Install project dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Launch:

```bash
python3 -m streamlit run dashboard.py
```

Open:

```text
http://localhost:8501
```

### Data source behaviour

**Local environment**

When both local consolidated alert and incident reports are available, the dashboard loads local security reports and displays the GCP audit events from the local collector report when available.

**Public deployment**

The public Streamlit deployment uses sanitized fictional demo data. It does not have access to local GCP credentials or local audit reports.

---

## Project Validation

The original project test suite reported 43 passing automated tests during development.

The latest live integration was manually verified:

- GCP Cloud Logging Python client installed.
- Python 3.12 environment verified.
- Seven real GCP Admin Activity events collected.
- Unified SOC classifier successfully processed 20 alerts.
- Live GCP events included in the consolidated report.
- Local Streamlit dashboard displayed the seven GCP events.
- Email masking verified.
- Public Streamlit deployment verified using demo data.

These are integration checks; the original 43-test result should not be interpreted as a newly executed test run after every