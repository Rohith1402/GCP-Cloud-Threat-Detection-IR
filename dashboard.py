
import json
import re
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ==================================================
# 1. CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

REPORT_DIR = BASE_DIR / "reports"
DEMO_DIR = BASE_DIR / "demo_data"

LOCAL_ALERT_FILE = REPORT_DIR / "consolidated_soc_alerts.json"
LOCAL_INCIDENT_FILE = REPORT_DIR / "incident_response_log.json"
GCP_AUDIT_FILE = REPORT_DIR / "gcp_audit_logs.json"

DEMO_ALERT_FILE = DEMO_DIR / "consolidated_soc_alerts.json"
DEMO_INCIDENT_FILE = DEMO_DIR / "incident_response_log.json"

st.set_page_config(
    page_title="GCP SOC Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==================================================
# 2. SELECT DATA SOURCE
# ==================================================

if LOCAL_ALERT_FILE.exists() and LOCAL_INCIDENT_FILE.exists():
    ALERT_FILE = LOCAL_ALERT_FILE
    INCIDENT_FILE = LOCAL_INCIDENT_FILE
    DATA_MODE = "LOCAL SECURITY REPORTS"
    IS_DEMO = False
else:
    ALERT_FILE = DEMO_ALERT_FILE
    INCIDENT_FILE = DEMO_INCIDENT_FILE
    DATA_MODE = "PUBLIC DEMO DATA"
    IS_DEMO = True

# ==================================================
# 3. HEADER AND SIDEBAR
# ==================================================

st.title("🛡️ GCP Cloud Security Operations Dashboard")

st.caption(
    "Cloud Threat Detection | SOC Monitoring | "
    "Alert Classification | Incident Response"
)

st.sidebar.title("🛡️ SOC Dashboard")
st.sidebar.caption("GCP Cloud Security Lab")
st.sidebar.divider()

st.sidebar.info(f"Data Source: {DATA_MODE}")

if IS_DEMO:
    st.sidebar.warning(
        "Demo environment: All displayed records are fictional."
    )
else:
    st.sidebar.success(
        "Using local security reports."
    )

if st.sidebar.button("🔄 Refresh Dashboard", width="stretch"):
    st.rerun()

st.sidebar.divider()
st.sidebar.caption(
    "Built with Python, Streamlit, Plotly and Pandas"
)

# ==================================================
# 4. DATA LOADING FUNCTIONS
# ==================================================

def load_json(path):
    """Load JSON data safely."""

    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError) as error:
        st.error(f"Unable to read {path.name}: {error}")
        return None


def extract_alerts(data):
    """Support list and dictionary JSON formats."""

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        alerts = data.get("alerts", [])

        if isinstance(alerts, list):
            return alerts

    return []


def mask_email(value):
    """Mask email addresses in displayed information."""

    return re.sub(
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        "[REDACTED_EMAIL]",
        str(value),
    )


# ==================================================
# 5. LOAD REPORTS
# ==================================================

alert_data = load_json(ALERT_FILE)
incident_data = load_json(INCIDENT_FILE)

if alert_data is None:
    st.error(
        "Alert report not found. Check the selected data source."
    )
    st.stop()

if incident_data is None:
    st.error(
        "Incident report not found. Check the selected data source."
    )
    st.stop()

alerts = extract_alerts(alert_data)

incidents = (
    incident_data
    if isinstance(incident_data, list)
    else []
)

alerts_df = pd.DataFrame(alerts)
incidents_df = pd.DataFrame(incidents)

# ==================================================
# 6. NORMALISE ALERT DATA
# ==================================================

if not alerts_df.empty:

    if "severity" not in alerts_df.columns:
        alerts_df["severity"] = "UNKNOWN"

    if "risk_score" not in alerts_df.columns:
        alerts_df["risk_score"] = 0

    if "source_module" not in alerts_df.columns:
        alerts_df["source_module"] = "Unknown"

    alerts_df["severity"] = (
        alerts_df["severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
    )

    alerts_df["risk_score"] = pd.to_numeric(
        alerts_df["risk_score"],
        errors="coerce",
    ).fillna(0)

# ==================================================
# 7. SECURITY KPI CALCULATIONS
# ==================================================

severity_counts = (
    alerts_df["severity"].value_counts()
    if not alerts_df.empty
    else pd.Series(dtype=int)
)

total_alerts = len(alerts_df)

critical_count = int(severity_counts.get("CRITICAL", 0))
high_count = int(severity_counts.get("HIGH", 0))
medium_count = int(severity_counts.get("MEDIUM", 0))
low_count = int(severity_counts.get("LOW", 0))

total_incidents = len(incidents_df)

pending_incidents = 0

if not incidents_df.empty and "status" in incidents_df.columns:
    pending_incidents = int(
        incidents_df["status"]
        .astype(str)
        .str.upper()
        .eq("PENDING_ANALYST_APPROVAL")
        .sum()
    )

# ==================================================
# 8. SECURITY OVERVIEW
# ==================================================

st.subheader("📊 Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical Alerts", critical_count)
col3.metric("High Alerts", high_count)
col4.metric("Total Incidents", total_incidents)
col5.metric("Pending Approval", pending_incidents)

st.divider()

# ==================================================
# 9. LIVE GCP AUDIT EVENTS
# ==================================================

st.subheader("☁️ Live GCP Cloud Audit Events")

if IS_DEMO:
    st.info(
        "Live GCP telemetry is available only in the local "
        "authenticated environment. The public dashboard "
        "continues to use sanitized demo data."
    )

elif GCP_AUDIT_FILE.exists():

    gcp_data = load_json(GCP_AUDIT_FILE)

    if isinstance(gcp_data, list) and gcp_data:

        gcp_df = pd.DataFrame(gcp_data)

        st.success(
            f"Latest local collection: {len(gcp_df)} "
            "GCP audit events"
        )

        if "timestamp" in gcp_df.columns:
            gcp_df["timestamp"] = pd.to_datetime(
                gcp_df["timestamp"],
                errors="coerce",
                utc=True,
            )

        if "principal_email" in gcp_df.columns:
            gcp_df["principal_email"] = (
                gcp_df["principal_email"]
                .fillna("Unknown")
                .apply(mask_email)
            )

        if "resource_name" in gcp_df.columns:
            gcp_df["resource_name"] = (
                gcp_df["resource_name"]
                .fillna("Unknown")
                .apply(mask_email)
            )

        gcp_columns = [
            column
            for column in [
                "timestamp",
                "method_name",
                "service_name",
                "severity",
                "principal_email",
                "resource_name",
            ]
            if column in gcp_df.columns
        ]

        gcp_display_df = gcp_df[gcp_columns].copy()

        st.dataframe(
            gcp_display_df,
            width="stretch",
            hide_index=True,
        )

        gcp_csv = gcp_display_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="📥 Download GCP Audit Events CSV",
            data=gcp_csv,
            file_name="gcp_audit_events.csv",
            mime="text/csv",
        )

    else:
        st.info(
            "No GCP audit events are currently available "
            "in the local report."
        )

else:
    st.info(
        "GCP audit report not found. Run the GCP audit-log "
        "collector to retrieve events."
    )

st.divider()

# ==================================================
# 10. ALERT SEVERITY DISTRIBUTION
# ==================================================

st.subheader("🚨 Alert Severity Distribution")

if not alerts_df.empty:

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN",
    ]

    severity_df = (
        alerts_df["severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
        .rename_axis("Severity")
        .reset_index(name="Count")
    )

    severity_df = severity_df[
        severity_df["Count"] > 0
    ]

    severity_chart = px.pie(
        severity_df,
        names="Severity",
        values="Count",
        hole=0.45,
        title="Security Alerts by Severity",
    )

    severity_chart.update_traces(
        textposition="inside",
        textinfo="percent+label",
    )

    st.plotly_chart(
        severity_chart,
        width="stretch",
    )

else:
    st.info("No severity information available.")

st.divider()

# ==================================================
# 11. DETECTION MODULE DISTRIBUTION
# ==================================================

left, right = st.columns(2)

with left:

    st.subheader("🔍 Alerts by Detection Module")

    if not alerts_df.empty:

        module_df = (
            alerts_df["source_module"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("Detection Module")
            .reset_index(name="Alerts")
        )

        module_chart = px.bar(
            module_df,
            x="Detection Module",
            y="Alerts",
            title="Detection Module Distribution",
            text="Alerts",
        )

        module_chart.update_layout(
            xaxis_title="Detection Module",
            yaxis_title="Number of Alerts",
        )

        st.plotly_chart(
            module_chart,
            width="stretch",
        )

    else:
        st.info("Detection module information unavailable.")

# ==================================================
# 12. RISK SCORE DISTRIBUTION
# ==================================================

with right:

    st.subheader("📈 Risk Score Distribution")

    if not alerts_df.empty:

        risk_chart = px.histogram(
            alerts_df,
            x="risk_score",
            nbins=10,
            title="Alert Risk Scores",
            labels={
                "risk_score": "Risk Score",
            },
        )

        risk_chart.update_layout(
            xaxis_title="Risk Score",
            yaxis_title="Number of Alerts",
        )

        st.plotly_chart(
            risk_chart,
            width="stretch",
        )

    else:
        st.info("Risk score information unavailable.")

st.divider()

# ==================================================
# 13. PRIORITISED SOC ALERTS
# ==================================================

st.subheader("⚠️ Prioritised SOC Alerts")

if not alerts_df.empty:

    display_columns = [
        column
        for column in [
            "alert_id",
            "source_module",
            "severity",
            "risk_score",
            "principal_or_resource",
            "description",
        ]
        if column in alerts_df.columns
    ]

    display_df = alerts_df[display_columns].copy()

    if "principal_or_resource" in display_df.columns:
        display_df["principal_or_resource"] = (
            display_df["principal_or_resource"]
            .apply(mask_email)
        )

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    display_df["_priority"] = (
        display_df["severity"]
        .map(priority_order)
        .fillna(4)
    )

    display_df = (
        display_df
        .sort_values(
            ["_priority", "risk_score"],
            ascending=[True, False],
        )
        .drop(columns="_priority")
    )

    st.dataframe(
        display_df,
        width="stretch",
        hide_index=True,
    )

    csv_data = display_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="📥 Download SOC Alerts CSV",
        data=csv_data,
        file_name="soc_security_alerts.csv",
        mime="text/csv",
    )

else:
    st.info("No SOC alerts available.")

st.divider()

# ==================================================
# 14. INCIDENT RESPONSE TRACKING
# ==================================================

st.subheader("🛡️ Incident Response Tracking")

if not incidents_df.empty:

    incident_columns = [
        column
        for column in [
            "incident_id",
            "severity",
            "risk_score",
            "resource",
            "response_priority",
            "recommended_action",
            "status",
            "execution_mode",
        ]
        if column in incidents_df.columns
    ]

    incident_display_df = incidents_df[
        incident_columns
    ].copy()

    if "resource" in incident_display_df.columns:
        incident_display_df["resource"] = (
            incident_display_df["resource"]
            .apply(mask_email)
        )

    st.dataframe(
        incident_display_df,
        width="stretch",
        hide_index=True,
    )

    incident_csv = incident_display_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="📥 Download Incident Report CSV",
        data=incident_csv,
        file_name="incident_response_report.csv",
        mime="text/csv",
    )

else:
    st.info("No incident report available.")

st.divider()

# ==================================================
# 15. SECURITY SUMMARY
# ==================================================

st.subheader("📋 Security Summary")

summary_col1, summary_col2 = st.columns(2)

with summary_col1:

    st.write("**Alert Severity Breakdown**")

    st.write(f"🔴 Critical: {critical_count}")
    st.write(f"🟠 High: {high_count}")
    st.write(f"🟡 Medium: {medium_count}")
    st.write(f"🟢 Low: {low_count}")

with summary_col2:

    st.write("**Incident Response Status**")

    st.write(f"Total incidents: {total_incidents}")

    st.write(
        f"Pending analyst approval: {pending_incidents}"
    )

    st.write("Execution mode: SIMULATION_ONLY")

# ==================================================
# 16. FOOTER
# ==================================================

st.divider()

if IS_DEMO:
    st.info(
        "Public demonstration using fictional training records. "
        "No live GCP telemetry is connected."
    )
else:
    st.caption(
        "Local environment using locally generated security reports."
    )

st.caption(
    "GCP Cloud Security Lab | "
    "Python | Streamlit | Plotly | Pandas"
)

st.caption(
    "Incident response is simulation-only. "
    "No cloud resources are modified."
)
