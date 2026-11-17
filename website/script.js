
const API_URL = "https://script.google.com/macros/s/AKfycbwZlAdGmdj2Ecwk4skUt9mqwxZFlx-f5uxPdVM3uHAKgTKnJyGr7Zx-GD59HB0I7g/exec";

const REFRESH_INTERVAL = 5 * 60 * 1000;

let realAlerts = [];
let severityChart = null;
let lastSuccessfulRefresh = null;
let refreshInProgress = false;

const simulatedAlerts = [
    { id: "SIM-001", detection: "Simulated IAM privilege escalation", source: "SIMULATED", severity: "Critical", status: "Open" },
    { id: "SIM-002", detection: "Simulated service account key creation", source: "SIMULATED", severity: "High", status: "Investigating" },
    { id: "SIM-003", detection: "Simulated suspicious API activity", source: "SIMULATED", severity: "High", status: "Open" },
    { id: "SIM-004", detection: "Simulated unusual IAM activity", source: "SIMULATED", severity: "Medium", status: "Reviewed" },
    { id: "SIM-005", detection: "Simulated abnormal service usage", source: "SIMULATED", severity: "Medium", status: "Open" },
    { id: "SIM-006", detection: "Simulated routine audit activity", source: "SIMULATED", severity: "Low", status: "Reviewed" }
];

function classifyGcpEvent(event, index) {
    const method = (event.method || "").toLowerCase();

    let severity = "Low";

    if (
        method.includes("setiampolicy") ||
        method.includes("createserviceaccountkey")
    ) {
        severity = "High";
    } else if (
        method.includes("deleteserviceaccountkey") ||
        method.includes("createserviceaccount")
    ) {
        severity = "Medium";
    }

    return {
        id: "GCP-" + String(index + 1).padStart(3, "0"),
        detection: event.method || "Unknown GCP activity",
        source: "REAL_GCP",
        severity,
        status: "New",
        timestamp: event.timestamp,
        service: event.service || "Unknown"
    };
}

function getAllAlerts() {
    return [...realAlerts, ...simulatedAlerts];
}

function updateMetrics(alerts) {
    const count = severity =>
        alerts.filter(alert => alert.severity === severity).length;

    const open = alerts.filter(alert =>
        ["Open", "Investigating", "New"].includes(alert.status)
    ).length;

    document.getElementById("totalAlerts").textContent = alerts.length;
    document.getElementById("criticalAlerts").textContent = count("Critical");
    document.getElementById("highAlerts").textContent = count("High");
    document.getElementById("openIncidents").textContent = open;
}

function renderAlertTable(alerts) {
    const table = document.getElementById("alertTable");

    const severityClasses = {
        Critical: "critical-tag",
        High: "high-tag",
        Medium: "medium-tag",
        Low: "low-tag"
    };

    table.replaceChildren();

    alerts.forEach(alert => {
        const row = document.createElement("tr");

        [alert.id, alert.detection, alert.source].forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        const severityCell = document.createElement("td");
        const badge = document.createElement("span");

        badge.className = "severity " +
            (severityClasses[alert.severity] || "low-tag");

        badge.textContent = alert.severity;
        severityCell.appendChild(badge);
        row.appendChild(severityCell);

        const statusCell = document.createElement("td");
        statusCell.textContent = alert.status;
        row.appendChild(statusCell);

        table.appendChild(row);
    });
}

function updateSeverityChart(alerts) {
    const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0
    };

    alerts.forEach(alert => {
        if (Object.hasOwn(counts, alert.severity)) {
            counts[alert.severity]++;
        }
    });

    const canvas = document.getElementById("severityChart");

    if (!canvas) return;

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: Object.keys(counts),
            datasets: [{
                data: Object.values(counts),
                backgroundColor: [
                    "#ff5268",
                    "#ffad42",
                    "#e8d05b",
                    "#27d69a"
                ],
                borderColor: "#111c2e",
                borderWidth: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#8795aa",
                        padding: 18,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

function updateDashboard() {
    const alerts = getAllAlerts();

    updateMetrics(alerts);
    renderAlertTable(alerts);
    updateSeverityChart(alerts);
}

function updateSourceStatus(realData) {
    const statusPanel = document.querySelector(".monitoring-info");

    if (!statusPanel) return;

    statusPanel.replaceChildren();

    const refreshTime = realData.updatedAt
        ? new Date(realData.updatedAt).toLocaleTimeString("en-IN", {
            timeZone: "Asia/Kolkata",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        })
        : "Unavailable";

    const items = [
        ["GCP Audit Logs", "Connected"],
        ["Real GCP Events", realData.eventCount],
        ["Simulated Scenarios", simulatedAlerts.length],
        ["Last Data Refresh", refreshTime]
    ];

    items.forEach(([label, value]) => {
        const row = document.createElement("div");
        const name = document.createElement("span");
        const result = document.createElement("strong");

        name.textContent = label;
        result.textContent = value;

        row.append(name, result);
        statusPanel.appendChild(row);
    });
}

function loadRealGcpData() {
    return new Promise((resolve, reject) => {
        const callbackName = "cyberSocCallback_" +
            Date.now() + "_" + Math.random().toString(36).slice(2);

        const script = document.createElement("script");

        const timeout = setTimeout(() => {
            cleanup();
            reject(new Error("GCP API request timed out"));
        }, 20000);

        function cleanup() {
            clearTimeout(timeout);
            delete window[callbackName];
            script.remove();
        }

        window[callbackName] = function(data) {
            cleanup();

            if (
                !data ||
                data.source !== "REAL_GCP" ||
                !Array.isArray(data.events) ||
                !data.updatedAt
            ) {
                reject(new Error("Invalid GCP API response"));
                return;
            }

            resolve(data);
        };

        script.onerror = function() {
            cleanup();
            reject(new Error("Unable to load GCP API"));
        };

        const separator = API_URL.includes("?") ? "&" : "?";

        script.src =
            API_URL +
            separator +
            "callback=" + encodeURIComponent(callbackName) +
            "&_=" + Date.now();

        document.head.appendChild(script);
    });
}

async function refreshDashboard() {
    if (refreshInProgress) return;

    refreshInProgress = true;

    const notice = document.querySelector(".notice");

    try {
        if (notice) {
            notice.textContent = "Connecting to GCP audit logs...";
        }

        const data = await loadRealGcpData();

        realAlerts = data.events.map((event, index) =>
            classifyGcpEvent(event, index)
        );

        lastSuccessfulRefresh = data.updatedAt;

        updateDashboard();
        updateSourceStatus(data);

        if (notice) {
            notice.innerHTML =
                "<strong>LIVE DATA + SIMULATIONS</strong>" +
                "<span>Real GCP audit events and clearly labelled simulated scenarios.</span>";
        }

        console.log("GCP API updated at:", data.updatedAt);
        console.log("Real GCP events:", realAlerts.length);
        console.log("Simulated scenarios:", simulatedAlerts.length);

    } catch (error) {
        console.error("Dashboard refresh failed:", error);

        if (notice) {
            notice.innerHTML =
                "<strong>GCP DATA UNAVAILABLE</strong>" +
                "<span>Showing simulated scenarios. Last successful refresh: " +
                (lastSuccessfulRefresh
                    ? new Date(lastSuccessfulRefresh).toLocaleTimeString("en-IN", {
                        timeZone: "Asia/Kolkata"
                    })
                    : "None") +
                "</span>";
        }

        updateDashboard();

    } finally {
        refreshInProgress = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();

    setInterval(refreshDashboard, REFRESH_INTERVAL);
});
