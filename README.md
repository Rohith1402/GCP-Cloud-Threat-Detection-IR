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

Later phases extend the pipeline:

- **Phase 2:** rule-based GCP detections with MITRE ATT&CK mapping (`GCP-IAM-*`, `GCP-SA-*`, `GCP-SCC-*`) and multi-event correlation (`CORR-001` to `CORR-003`).
- **Phase 3:** incident response lifecycle with persistence and simulation-only response actions.
- **Phase 4:** behaviour-based anomaly detection (`BEHAV-001` to `BEHAV-003`) and publication of sanitised results to the public Cyber SOC website.

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
- Behaviour-Based Detections section: rule catalogue, triggered behaviour alerts, real/simulated data labels and the contributing audit events for each alert.

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

## Phase 2: GCP Threat Detection Engine

Phase 2 moves beyond single-event alerts with named detection rules and multi-event correlation.

### Rule-based detections

The SOC classifier maps alerts to named detection rules with a risk score, confidence level, analyst recommendation and, where applicable, a MITRE ATT&CK technique.

| Rule | Detection | Risk | MITRE ATT&CK |
|---|---|---:|---|
| GCP-IAM-001 | IAM policy modification | 80 | T1098.003 |
| GCP-IAM-002 | Service-account key creation | 90 | T1098.001 |
| GCP-IAM-003 | Service-account key deletion | 70 | T1531 |
| GCP-IAM-004 | Service-account creation | 40 | T1136.003 |
| GCP-IAM-005 | Privileged IAM role assignment | 50 | T1098.003 |
| GCP-IAM-006 | Sensitive IAM permission combination | 100 | T1548.005 |
| GCP-SA-001 | Repeated service-account authentication failures | 60 | T1110 |
| GCP-SCC-001 | Public storage bucket access | 100 | T1530 |
| GCP-SCC-002 | Excessive IAM permissions | 90 | - |
| GCP-SCC-003 | Critical compute vulnerability | 85 | T1190 |
| GCP-SCC-004 | Suspicious network activity | 55 | - |

### Event correlation

`detection/event_correlation.py` links related audit events by the same principal:

| Rule | Correlation | Risk | MITRE ATT&CK |
|---|---|---:|---|
| CORR-001 | Service-account creation followed by key creation (60 min) | 85 | T1098.001 |
| CORR-002 | Service-account key creation followed by IAM policy modification (60 min) | 95 | T1098.003 |
| CORR-003 | Repeated sensitive administrative activity (3+ in 15 min) | 75 | T1098 |

```bash
python3 detection/event_correlation.py
```

Output: `reports/gcp_event_correlations.json`

---

## Phase 4: Behaviour-Based Anomaly Detection

Phase 4 looks at who acted, how often and how quickly.

### Behaviour rules

`detection/behaviour_anomaly_detector.py` detects activity patterns per principal using time windows and thresholds:

| Rule | Behaviour | Window | Min. events | Risk | Confidence | MITRE ATT&CK |
|---|---|---:|---:|---:|---|---|
| BEHAV-001 | Administrative activity spike (sensitive IAM operations) | 10 min | 5 | 70 | MEDIUM | T1098 Account Manipulation |
| BEHAV-002 | Repeated service enablement | 15 min | 3 | 55 | LOW | - |
| BEHAV-003 | Service-account creation followed by key creation | 60 min | 2 | 65 | MEDIUM | T1098.001 Additional Cloud Credentials |

Design choices:

- Only explicitly selected sensitive IAM methods count towards BEHAV-001, so normal project setup (CreateProject, EnableService, GetOperation) does not trigger it.
- Events with missing or invalid timestamps are ignored, and duplicate event IDs are not double-counted.
- Every alert is labelled `REAL`, `SIMULATED` or `MIXED` according to the source of its evidence, so test data is never mistaken for live activity.
- All contributing events are preserved as evidence for the analyst.

`detection/behaviour_alert_integration.py` runs all three rules against the collected audit events and writes a behaviour report. The SOC classifier then merges these alerts into the consolidated feed, where they are deduplicated and prioritised alongside every other alert.

```bash
python3 detection/behaviour_alert_integration.py
```

Output: `reports/gcp_behaviour_alerts.json`

### Live result

Run against the project's real GCP Admin Activity events, BEHAV-002 fired once: four service enablements within two seconds during initial project setup. It was classified as MEDIUM severity with LOW confidence and labelled `REAL`. This is expected legitimate activity, and the rule's LOW confidence reflects that service enablement often has a valid business reason.

### MITRE ATT&CK enrichment and coverage

`detection/mitre_mapping.py` is the single source of truth for ATT&CK mappings. Every SOC alert (rule-based, correlation and behaviour) carries `mitre_technique_id`, `mitre_technique_name` and `mitre_tactics`.

Coverage: **7 of 14 Enterprise tactics**, **14 of 18 rules** mapped, **9 unique techniques**.

| Tactic | Techniques | Rules |
|---|---|---|
| TA0043 Reconnaissance | No coverage | - |
| TA0042 Resource Development | No coverage | - |
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | GCP-SCC-003 |
| TA0002 Execution | No coverage | - |
| TA0003 Persistence | T1098 Account Manipulation<br>T1098.001 Additional Cloud Credentials<br>T1098.003 Additional Cloud Roles<br>T1136.003 Create Account: Cloud Account | BEHAV-001, CORR-003, BEHAV-003, CORR-001, GCP-IAM-002, CORR-002, GCP-IAM-001, GCP-IAM-005, GCP-IAM-004 |
| TA0004 Privilege Escalation | T1098 Account Manipulation<br>T1098.001 Additional Cloud Credentials<br>T1098.003 Additional Cloud Roles<br>T1548.005 Temporary Elevated Cloud Access | BEHAV-001, CORR-003, BEHAV-003, CORR-001, GCP-IAM-002, CORR-002, GCP-IAM-001, GCP-IAM-005, GCP-IAM-006 |
| TA0005 Defense Evasion | T1548.005 Temporary Elevated Cloud Access | GCP-IAM-006 |
| TA0006 Credential Access | T1110 Brute Force | GCP-SA-001 |
| TA0007 Discovery | No coverage | - |
| TA0008 Lateral Movement | No coverage | - |
| TA0009 Collection | T1530 Data from Cloud Storage | GCP-SCC-001 |
| TA0011 Command and Control | No coverage | - |
| TA0010 Exfiltration | No coverage | - |
| TA0040 Impact | T1531 Account Access Removal | GCP-IAM-003 |

Rules intentionally not mapped:

- `BEHAV-002`: Repeated service enablement has no clean ATT&CK match and is usually legitimate project setup.
- `GCP-SCC-002`: Posture finding (excessive permissions), not adversary behaviour.
- `GCP-SCC-004`: Too generic to map to a specific technique without more network context.
- `GENERAL-001`: Generic activity, not a detection rule.

Leaving these unmapped is deliberate: forcing a technique onto a posture finding or generic activity would overstate coverage. The uncovered tactics are listed openly as candidates for future detections.

Print the current matrix:

```bash
python3 detection/mitre_mapping.py
```

A mapped alert is not confirmation that the technique was used; it shows which adversary behaviour the rule is designed to surface.

### Public website publication

The public Cyber SOC website (https://cyber-soc.pages.dev/) shows the pipeline's results. `detection/publish_website_data.py` converts the consolidated report into `website/data/soc_alerts.json`:

- Real email addresses become aliases (`user-01`, `service-account-01`).
- Resource names are replaced by their type (for example "Storage bucket"); project IDs and numbers are removed.
- Every alert is labelled `REAL` or `SYNTHETIC`.
- A final leak check refuses to write the file if any email address, project identifier or resource name remains.

```bash
python3 detection/publish_website_data.py
```

The website is deployed with Cloudflare Pages from the `website/` folder of the `main` branch. A separate Google Apps Script collector provides a sanitised live feed of Admin Activity events (timestamp, method, service, severity and status only).

### Full pipeline order

```bash
python detection/gcp_audit_log_collector.py
python3 detection/event_correlation.py
python3 detection/behaviour_alert_integration.py
python3 detection/alert_classifier.py
python3 detection/incident_response.py
python3 detection/publish_website_data.py
python3 -m streamlit run dashboard.py
```

### Run all tests

```bash
python3 -m pytest -q tests
```

---

## Project Validation

The full automated test suite (`python -m pytest -v`) covers the detection modules, rule classification, deduplication, event correlation, behaviour-based detection its integration into the SOC pipeline, website data sanitisation, and incident response.

The live integration was also manually verified:

- GCP Cloud Logging Python client installed.
- Python 3.12 environment verified.
- Seven real GCP Admin Activity events collected.
- Unified SOC classifier successfully processed 21 alerts, including one behaviour-based alert.
- Live GCP events included in the consolidated report.
- Local Streamlit dashboard displayed the seven GCP events.
- Email masking verified.
- Public Streamlit deployment verified using demo data.

Real audit events are not automatically evidence of malicious activity. All detections are investigation signals that require analyst review, and incident response remains simulation-only.