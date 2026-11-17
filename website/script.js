
const demoAlerts = [
    {
        id: "DEMO-001",
        detection: "Suspicious IAM activity",
        source: "Simulation",
        severity: "Critical",
        status: "Open"
    },
    {
        id: "DEMO-002",
        detection: "Privilege escalation scenario",
        source: "Simulation",
        severity: "High",
        status: "Investigating"
    },
    {
        id: "DEMO-003",
        detection: "Unusual service account activity",
        source: "Simulation",
        severity: "High",
        status: "Open"
    },
    {
        id: "DEMO-004",
        detection: "Audit log monitoring event",
        source: "Simulation",
        severity: "Medium",
        status: "Reviewed"
    },
    {
        id: "DEMO-005",
        detection: "Suspicious API activity",
        source: "Simulation",
        severity: "Medium",
        status: "Open"
    },
    {
        id: "DEMO-006",
        detection: "Routine administrative activity",
        source: "Simulation",
        severity: "Low",
        status: "Reviewed"
    }
];

function updateMetrics(alerts) {
    const total = alerts.length;

    const critical = alerts.filter(
        alert => alert.severity === "Critical"
    ).length;

    const high = alerts.filter(
        alert => alert.severity === "High"
    ).length;

    const open = alerts.filter(
        alert => alert.status === "Open" ||
                 alert.status === "Investigating"
    ).length;

    document.getElementById("totalAlerts").textContent = total;
    document.getElementById("criticalAlerts").textContent = critical;
    document.getElementById("highAlerts").textContent = high;
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

        const values = [
            alert.id,
            alert.detection,
            alert.source
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        const severityCell = document.createElement("td");
        const severityBadge = document.createElement("span");

        severityBadge.className =
            `severity ${severityClasses[alert.severity] || "low-tag"}`;

        severityBadge.textContent = alert.severity;
        severityCell.appendChild(severityBadge);
        row.appendChild(severityCell);

        const statusCell = document.createElement("td");
        statusCell.textContent = alert.status;
        row.appendChild(statusCell);

        table.appendChild(row);
    });
}

function updateRefreshTime() {
    const now = new Date();

    document.getElementById("lastRefresh").textContent =
        now.toLocaleTimeString();
}

function createSeverityChart(alerts) {
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

    new Chart(canvas, {
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

function initialiseDashboard() {
    updateMetrics(demoAlerts);
    renderAlertTable(demoAlerts);
    updateRefreshTime();
    createSeverityChart(demoAlerts);
}

document.addEventListener("DOMContentLoaded", initialiseDashboard);
