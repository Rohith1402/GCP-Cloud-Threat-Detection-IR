
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent

ALERT_FILE = BASE_DIR / "reports" / "consolidated_soc_alerts.json"
INCIDENT_FILE = BASE_DIR / "reports" / "incident_response_log.json"

st.set_page_config(
    page_title="GCP SOC Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ GCP Cloud Security Operations Dashboard")
st.caption("Cloud Threat Detection | SOC Monitoring | Incident Response")

st.sidebar.header("Dashboard Controls")
st.sidebar.write("Local security reports")
if st.sidebar.button("Refresh dashboard"):
    st.rerun()


def load_json(path):
    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return None


def extract_alerts(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("alerts"), list):
        return data["alerts"]
    return []


alert_data = load_json(ALERT_FILE)
incident_data = load_json(INCIDENT_FILE)

if alert_data is None:
    st.error(
        "Consolidated SOC alert report not found. "
        "Run the detection modules and alert classifier first."
    )
    st.stop()

alerts = extract_alerts(alert_data)

if not alerts:
    st.warning("No SOC alerts found in the consolidated report.")

incidents = incident_data if isinstance(incident_data, list) else []

alerts_df = pd.DataFrame(alerts)
incidents_df = pd.DataFrame(incidents)

if not alerts_df.empty:
    alerts_df["severity"] = (
        alerts_df["severity"].fillna("UNKNOWN").astype(str).str.upper()
    )
    alerts_df["risk_score"] = pd.to_numeric(
        alerts_df["risk_score"], errors="coerce"
    ).fillna(0)

severity_counts = (
    alerts_df["severity"].value_counts()
    if not alerts_df.empty
    else pd.Series(dtype=int)
)

critical_count = int(severity_counts.get("CRITICAL", 0))
high_count = int(severity_counts.get("HIGH", 0))
medium_count = int(severity_counts.get("MEDIUM", 0))
low_count = int(severity_counts.get("LOW", 0))

total_alerts = len(alerts_df)
total_incidents = len(incidents_df)

pending_incidents = 0
if not incidents_df.empty and "status" in incidents_df.columns:
    pending_incidents = int(
        incidents_df["status"].astype(str)
        .str.upper()
        .eq("PENDING_ANALYST_APPROVAL")
        .sum()
    )

st.subheader("Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical Alerts", critical_count)
col3.metric("High Alerts", high_count)
col4.metric("Total Incidents", total_incidents)
col5.metric("Pending Approval", pending_incidents)

st.divider()

st.subheader("Alert Severity Distribution")

if not alerts_df.empty:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

    severity_df = (
        alerts_df["severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
        .rename_axis("Severity")
        .reset_index(name="Count")
    )

    chart = px.pie(
        severity_df[severity_df["Count"] > 0],
        names="Severity",
        values="Count",
        hole=0.45,
        title="Alerts by Severity",
    )
    st.plotly_chart(chart, use_container_width=True)
else:
    st.info("No alert severity data available.")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Alerts by Detection Module")

    if not alerts_df.empty and "source_module" in alerts_df.columns:
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
        )
        st.plotly_chart(module_chart, use_container_width=True)
    else:
        st.info("Detection module information unavailable.")

with right:
    st.subheader("Risk Score Distribution")

    if not alerts_df.empty:
        risk_chart = px.histogram(
            alerts_df,
            x="risk_score",
            nbins=10,
            title="Alert Risk Scores",
            labels={"risk_score": "Risk Score"},
        )
        st.plotly_chart(risk_chart, use_container_width=True)
    else:
        st.info("Risk score information unavailable.")

st.divider()

st.subheader("Prioritised SOC Alerts")

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

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    display_df = alerts_df[display_columns].copy()
    display_df["_priority"] = (
        display_df["severity"].map(priority_order).fillna(4)
    )
    display_df = display_df.sort_values(
        ["_priority", "risk_score"],
        ascending=[True, False],
    ).drop(columns="_priority")

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
    )

    csv_data = display_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download SOC Alerts CSV",
        data=csv_data,
        file_name="soc_security_alerts.csv",
        mime="text/csv",
    )
else:
    st.info("No alerts available.")

st.divider()

st.subheader("Incident Response Tracking")

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

    st.dataframe(
        incidents_df[incident_columns],
        use_container_width=True,
        hide_index=True,
    )

    incident_csv = incidents_df[incident_columns].to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="Download Incident Report CSV",
        data=incident_csv,
        file_name="incident_response_report.csv",
        mime="text/csv",
    )
else:
    st.info(
        "No incident report available. Run incident_response.py first."
    )

st.divider()

st.caption(
    "GCP Cloud Security Lab | Local dashboard | "
    "Synthetic training data | Simulation-only incident response"
)
