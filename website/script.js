// Detection results published by the Python pipeline
// (detection/publish_website_data.py). Already sanitised.
const DATA_URL = "data/soc_alerts.json";

// Live GCP audit feed (Google Apps Script). Used only to show that the
// live collection is connected; detection happens in the Python pipeline.
const LIVE_FEED_URL = "https://script.google.com/macros/s/AKfycbwZlAdGmdj2Ecwk4skUt9mqwxZFlx-f5uxPdVM3uHAKgTKnJyGr7Zx-GD59HB0I7g/exec";

const REFRESH_INTERVAL = 5 * 60 * 1000;

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const SEVERITY_CLASSES = {
    CRITICAL: "critical-tag",
    HIGH: "high-tag",
    MEDIUM: "medium-tag",
    LOW: "low-tag"
};

const PRIORITY_CLASSES = {
    P1: "critical-tag",
    P2: "high-tag",
    P3: "medium-tag",
    P4: "low-tag"
};

function scoreExplanation(alert) {
    const factors = alert.score_factors || [];
    if (!factors.length) return "";

    return factors
        .map(item => {
            const value = item.factor === "Rule risk score"
                ? String(item.adjustment)
                : (item.adjustment > 0 ? "+" : "") + item.adjustment;
            return `${item.factor}: ${value}`;
        })
        .join("\n") + `\n= ${alert.priority_score}`;
}

const DATA_LABEL_CLASSES = {
    REAL: "real-tag",
    SYNTHETIC: "synthetic-tag",
    SIMULATED: "synthetic-tag",
    MIXED: "mixed-tag"
};

let severityChart = null;
let socData = null;
let liveFeed = { status: "Connecting...", eventCount: null, updatedAt: null };

// ---------- Helpers ----------

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
}

function titleCase(value) {
    const text = String(value || "");
    return text.charAt(0) + text.slice(1).toLowerCase();
}

function formatTime(value) {
    if (!value) return "Unavailable";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unavailable";

    return date.toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function badge(text, className) {
    return el("span", "severity " + className, text);
}

function setNotice(title, message) {
    const notice = document.getElementById("dataNotice");
    if (!notice) return;

    notice.replaceChildren(el("strong", null, title), el("span", null, message));
}

// ---------- Overview ----------

function updateMetrics(data) {
    const severity = data.summary.severity || {};
    const pad = value => String(value || 0).padStart(2, "0");

    document.getElementById("totalAlerts").textContent = pad(data.summary.total_alerts);
    document.getElementById("criticalAlerts").textContent = pad(severity.CRITICAL);
    document.getElementById("highAlerts").textContent = pad(severity.HIGH);
    document.getElementById("behaviourAlerts").textContent = pad(data.summary.behaviour_alerts);
}

function updateSeverityChart(data) {
    const canvas = document.getElementById("severityChart");
    if (!canvas || typeof Chart === "undefined") return;

    const severity = data.summary.severity || {};

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: SEVERITY_ORDER.map(titleCase),
            datasets: [{
                data: SEVERITY_ORDER.map(level => severity[level] || 0),
                backgroundColor: ["#ff5268", "#ffad42", "#e8d05b", "#27d69a"],
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
                    labels: { color: "#8795aa", padding: 18, usePointStyle: true }
                }
            }
        }
    });
}

function updateMonitoringStatus() {
    const panel = document.getElementById("monitoringInfo");
    if (!panel) return;

    const labels = socData ? socData.summary.data_labels || {} : {};
    const rules = socData ? Object.keys(socData.summary.rules || {}).length : 0;

    const items = [
        ["Detection Pipeline", socData ? "Published " + formatTime(socData.generated_at) : "Unavailable"],
        ["Rules Triggered", socData ? String(rules) : "-"],
        ["Real GCP / Synthetic Alerts", socData ? `${labels.REAL || 0} / ${(labels.SYNTHETIC || 0) + (labels.SIMULATED || 0)}` : "-"],
        ["Live GCP Audit Feed", liveFeed.status],
        ["Live Feed Refresh", liveFeed.updatedAt ? formatTime(liveFeed.updatedAt) : "-"]
    ];

    panel.replaceChildren();

    items.forEach(([label, value]) => {
        const row = el("div");
        const isProblem = /unavailable/i.test(String(value));
        row.append(el("span", null, label), el("strong", isProblem ? "warn" : null, value));
        panel.appendChild(row);
    });
}

// ---------- Alert table ----------

function renderAlertTable(data) {
    const table = document.getElementById("alertTable");
    table.replaceChildren();

    if (!data.alerts.length) {
        const row = el("tr");
        const cell = el("td", null, "No alerts in the latest pipeline run.");
        cell.colSpan = 7;
        row.appendChild(cell);
        table.appendChild(row);
        return;
    }

    data.alerts.forEach(alert => {
        const row = el("tr");

        const priorityCell = el("td");
        if (alert.priority) {
            const priorityBadge = badge(alert.priority, PRIORITY_CLASSES[alert.priority] || "low-tag");
            priorityBadge.classList.add("priority-badge");
            priorityBadge.title = scoreExplanation(alert);
            priorityCell.appendChild(priorityBadge);
        } else {
            priorityCell.textContent = "-";
        }
        row.appendChild(priorityCell);

        row.appendChild(el("td", "mono", alert.alert_id));

        const detection = el("td");
        detection.append(
            el("div", "rule-id", alert.rule_id || "GENERAL"),
            el("div", "muted", alert.rule_name || alert.description || "")
        );
        row.appendChild(detection);

        const dataCell = el("td");
        dataCell.appendChild(badge(alert.data_label, DATA_LABEL_CLASSES[alert.data_label] || "synthetic-tag"));
        row.appendChild(dataCell);

        const severityCell = el("td");
        severityCell.appendChild(badge(titleCase(alert.severity), SEVERITY_CLASSES[alert.severity] || "low-tag"));
        row.appendChild(severityCell);

        const scoreCell = el("td");
        const changed = alert.priority_score !== undefined && alert.priority_score !== alert.risk_score;
        scoreCell.textContent = changed
            ? `${alert.risk_score} → ${alert.priority_score}`
            : String(alert.risk_score);
        if (changed) scoreCell.title = scoreExplanation(alert);
        row.appendChild(scoreCell);
        row.appendChild(el("td", "muted", alert.mitre_technique_id
            ? `${alert.mitre_technique_id} ${alert.mitre_technique_name || ""}`
            : "-"));

        table.appendChild(row);
    });
}

// ---------- Behaviour detection ----------

function renderBehaviourRules(data) {
    const container = document.getElementById("behaviourRules");
    container.replaceChildren();

    const fired = data.summary.rules || {};

    (data.behaviour_rules || []).forEach(rule => {
        const card = el("article", "rule-card" + (fired[rule.rule_id] ? " fired" : ""));

        const header = el("div", "rule-card-header");
        header.append(
            el("span", "rule-id", rule.rule_id),
            el("span", "rule-count", fired[rule.rule_id]
                ? `${fired[rule.rule_id]} fired`
                : "Not triggered")
        );

        const facts = el("dl", "rule-facts");
        [
            ["Window", `${rule.window_minutes} min`],
            ["Min. events", rule.threshold],
            ["Risk", rule.risk_score],
            ["Confidence", titleCase(rule.confidence)],
            ["MITRE", rule.mitre_technique ? `${rule.mitre_technique} ${rule.mitre_name}` : "-"]
        ].forEach(([term, value]) => {
            facts.append(el("dt", null, term), el("dd", null, String(value)));
        });

        card.append(
            header,
            el("h4", null, rule.name),
            el("p", "muted", rule.description),
            facts
        );

        container.appendChild(card);
    });
}

function renderBehaviourAlerts(data) {
    const container = document.getElementById("behaviourAlerts-list");
    container.replaceChildren();

    const alerts = data.alerts.filter(alert => alert.source_module === "gcp_behaviour_alerts");

    if (!alerts.length) {
        container.appendChild(el("p", "empty-state", "No behaviour rules triggered in the latest pipeline run."));
        return;
    }

    alerts.forEach(alert => {
        const evidence = alert.evidence || { events: [] };
        const details = el("details", "behaviour-alert");

        const summary = el("summary");
        summary.append(
            el("span", "rule-id", alert.rule_id),
            el("span", null, alert.rule_name),
            badge(titleCase(alert.severity), SEVERITY_CLASSES[alert.severity] || "low-tag"),
            badge(alert.data_label, DATA_LABEL_CLASSES[alert.data_label] || "synthetic-tag"),
            el("span", "muted", `${evidence.event_count || 0} events · ${alert.principal || "unknown"} · ${formatTime(evidence.first_seen)}`)
        );
        details.appendChild(summary);

        details.appendChild(el("p", "muted recommendation", alert.recommendation || ""));

        const table = el("table", "evidence-table");
        const head = el("tr");
        ["Event ID", "Timestamp", "Method", "Service"].forEach(text => head.appendChild(el("th", null, text)));
        table.appendChild(el("thead")).appendChild(head);

        const body = el("tbody");
        (evidence.events || []).forEach(event => {
            const row = el("tr");
            [event.event_id, event.timestamp, event.method_name, event.service_name || "-"]
                .forEach(value => row.appendChild(el("td", "mono", value)));
            body.appendChild(row);
        });
        table.appendChild(body);

        const wrapper = el("div", "table-wrapper");
        wrapper.appendChild(table);
        details.appendChild(wrapper);

        container.appendChild(details);
    });
}

// ---------- MITRE ATT&CK coverage ----------

function renderCoverage(data) {
    const coverage = data.mitre_coverage;
    const grid = document.getElementById("tacticGrid");
    const unmapped = document.getElementById("unmappedList");
    const summary = document.getElementById("coverageSummary");

    if (!grid || !unmapped || !summary) return;

    grid.replaceChildren();
    unmapped.replaceChildren();

    if (!coverage || !Array.isArray(coverage.tactics)) {
        summary.textContent = "UNAVAILABLE";
        grid.appendChild(el("p", "empty-state", "Coverage data is not available."));
        return;
    }

    summary.textContent =
        `${coverage.covered_tactics}/${coverage.total_tactics} TACTICS · ` +
        `${coverage.mapped_rules}/${coverage.total_rules} RULES`;

    coverage.tactics.forEach(tactic => {
        const state = tactic.active ? "active" : tactic.covered ? "covered" : "gap";
        const tile = el("article", "tactic-tile " + state);

        tile.append(
            el("span", "tactic-id", tactic.tactic_id),
            el("h4", null, tactic.tactic_name)
        );

        if (!tactic.techniques.length) {
            tile.appendChild(el("p", "muted", "No coverage yet"));
        } else {
            const list = el("ul", "technique-list");

            tactic.techniques.forEach(technique => {
                const item = el("li", technique.active ? "technique active" : "technique");
                item.title = "Rules: " + technique.rules.join(", ");
                item.append(
                    el("span", "technique-id", technique.technique_id),
                    el("span", null, technique.technique_name)
                );
                list.appendChild(item);
            });

            tile.append(list, el("p", "tactic-rules", `${tactic.rule_count} rule mapping${tactic.rule_count === 1 ? "" : "s"}`));
        }

        grid.appendChild(tile);
    });

    (coverage.unmapped_rules || []).forEach(rule => {
        const item = el("li");
        item.append(el("span", "rule-id", rule.rule_id), el("span", "muted", rule.reason));
        unmapped.appendChild(item);
    });
}

// ---------- Live GCP activity ----------

const LIVE_TABLE_LIMIT = 10;

function formatEventTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "-";

    return date.toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}

function shortMethod(method) {
    const text = String(method || "Unknown");
    return text.split(".").pop() || text;
}

function renderLiveTable(events, message) {
    const table = document.getElementById("liveTable");
    if (!table) return;

    table.replaceChildren();

    if (!events || !events.length) {
        const row = el("tr");
        const cell = el("td", "muted", message || "No Admin Activity events in the current collection window.");
        cell.colSpan = 5;
        row.appendChild(cell);
        table.appendChild(row);
        return;
    }

    [...events]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, LIVE_TABLE_LIMIT)
        .forEach(event => {
            const row = el("tr");

            row.appendChild(el("td", "mono", formatEventTime(event.timestamp)));

            const method = el("td", "mono", shortMethod(event.method));
            method.title = String(event.method || "");
            row.appendChild(method);

            row.appendChild(el("td", "muted", event.service || "-"));
            row.appendChild(el("td", null, event.severity || "-"));

            const code = event.statusCode;
            const ok = code === undefined || code === null || code === "" ||
                Number(code) === 0 || String(code).toUpperCase() === "OK";
            const result = el("td");
            result.appendChild(badge(ok ? "Success" : `Error ${code}`, ok ? "low-tag" : "critical-tag"));
            row.appendChild(result);

            table.appendChild(row);
        });
}

// ---------- Data loading ----------

async function loadSocData() {
    const response = await fetch(DATA_URL + "?_=" + Date.now(), { cache: "no-store" });

    if (!response.ok) {
        throw new Error("Detection data request failed: " + response.status);
    }

    const data = await response.json();

    if (!data || data.source !== "PYTHON_DETECTION_PIPELINE" || !Array.isArray(data.alerts)) {
        throw new Error("Invalid detection data");
    }

    return data;
}

function loadLiveFeed() {
    return new Promise((resolve, reject) => {
        const callbackName = "cyberSocCallback_" + Date.now() + "_" + Math.random().toString(36).slice(2);
        const script = document.createElement("script");

        const timeout = setTimeout(() => {
            cleanup();
            reject(new Error("Live feed request timed out"));
        }, 20000);

        function cleanup() {
            clearTimeout(timeout);
            delete window[callbackName];
            script.remove();
        }

        window[callbackName] = function(data) {
            cleanup();

            if (!data || data.source !== "REAL_GCP" || !Array.isArray(data.events) || !data.updatedAt) {
                reject(new Error("Invalid live feed response"));
                return;
            }

            resolve(data);
        };

        script.onerror = function() {
            cleanup();
            reject(new Error("Unable to load live feed"));
        };

        const separator = LIVE_FEED_URL.includes("?") ? "&" : "?";
        script.src = LIVE_FEED_URL + separator + "callback=" + encodeURIComponent(callbackName) + "&_=" + Date.now();

        document.head.appendChild(script);
    });
}

async function refreshLiveFeed() {
    try {
        const data = await loadLiveFeed();
        liveFeed = {
            status: `Connected · ${data.events.length} events`,
            eventCount: data.events.length,
            updatedAt: data.updatedAt
        };
        renderLiveTable(data.events);
    } catch (error) {
        console.error("Live feed refresh failed:", error);
        liveFeed = { ...liveFeed, status: "Unavailable" };
        if (liveFeed.eventCount === null) {
            renderLiveTable([], "Live feed unavailable. Pipeline results below are unaffected.");
        }
    }

    updateMonitoringStatus();
}

async function refreshDashboard() {
    try {
        socData = await loadSocData();

        updateMetrics(socData);
        updateSeverityChart(socData);
        renderAlertTable(socData);
        renderBehaviourRules(socData);
        renderBehaviourAlerts(socData);
        renderCoverage(socData);

        setNotice(
            "PIPELINE RESULTS",
            `Detections from the Python pipeline, published ${formatTime(socData.generated_at)}. ` +
            "REAL = this project's GCP data. SYNTHETIC = labelled training scenarios. Identities are masked."
        );
    } catch (error) {
        console.error("Detection data refresh failed:", error);
        setNotice("DATA UNAVAILABLE", "Detection results could not be loaded. Please try again later.");
    }

    updateMonitoringStatus();
}

document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();
    refreshLiveFeed();

    setInterval(() => {
        refreshDashboard();
        refreshLiveFeed();
    }, REFRESH_INTERVAL);
});
