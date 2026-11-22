#!/bin/bash
# Cyber SOC daily update.
#
# Runs the full pipeline locally, runs the test suite, publishes the
# sanitised website data (leak-checked) and pushes ONLY
# website/data/soc_alerts.json, and only when its content changed.
# Raw data and logs stay on this Mac (reports/ is gitignored).
#
# Usage:
#   scripts/daily_update.sh            # full run: commit and push
#   DRY_RUN=1 scripts/daily_update.sh  # everything except commit and push
#
# Scheduled by launchd (see scripts/com.cybersoc.daily-update.plist) at
# 09:00 and at login. Scheduled runs skip if today's update already
# succeeded or if it is before 09:00, so a day the Mac was switched off at
# 09:00 is caught up at the next login. Runs from a terminal always run.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR" || exit 1

PY="$PROJECT_DIR/.venv/bin/python"
DATA_FILE="website/data/soc_alerts.json"
LOG_FILE="reports/daily_update.log"
LOCK_DIR="reports/.daily_update.lock"
LAST_RUN_FILE="reports/.last_successful_run"
SCHEDULE_HOUR=9
DRY_RUN="${DRY_RUN:-0}"
TODAY="$(date '+%Y-%m-%d')"

mkdir -p reports

# In scheduled runs, write everything to the private log file.
SCHEDULED=0
if [ ! -t 1 ]; then
    SCHEDULED=1
    exec >>"$LOG_FILE" 2>&1
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
fail() { log "FAILED: $*"; exit 1; }
mark_done() { [ "$DRY_RUN" = "1" ] || echo "$TODAY" >"$LAST_RUN_FILE"; }

if [ "$SCHEDULED" = "1" ]; then
    if [ "$(cat "$LAST_RUN_FILE" 2>/dev/null)" = "$TODAY" ]; then
        log "Skipped: today's update already completed."
        exit 0
    fi
    if [ "$((10#$(date '+%H')))" -lt "$SCHEDULE_HOUR" ]; then
        log "Skipped: before 09:00; the 09:00 run will handle today."
        exit 0
    fi
fi

log "===== Daily update started (dry run: $DRY_RUN)"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "Another update is already running; exiting."
    exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT

[ -x "$PY" ] || fail "project virtual environment not found at .venv"
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || fail "not on branch main"
git diff --cached --quiet || fail "other changes are already staged; not touching git"

# Right after login the network may not be ready yet: wait up to 2 minutes.
for attempt in $(seq 1 12); do
    curl -s -o /dev/null --max-time 5 https://logging.googleapis.com && break
    [ "$attempt" -eq 12 ] && fail "no network after 2 minutes"
    sleep 10
done

run() {
    local name="$1"; shift
    log "Running $name"
    "$@" </dev/null || fail "$name"
}

run "collector"            "$PY" detection/gcp_audit_log_collector.py --hours 72
for module in iam_misconfiguration iam_privilege_escalation audit_log_monitor service_account_monitor scc_findings_analyzer; do
    run "$module"          "$PY" "detection/$module.py"
done
run "event correlation"    "$PY" detection/event_correlation.py
run "behaviour detection"  "$PY" detection/behaviour_alert_integration.py
run "alert classifier"     "$PY" detection/alert_classifier.py
run "incident response"    "$PY" detection/incident_response.py

log "Running AI triage (optional)"
"$PY" detection/ai_triage.py </dev/null || log "AI triage unavailable; continuing without new notes"

run "test suite"           "$PY" -m pytest -q
run "publish + leak check" "$PY" detection/publish_website_data.py

# Ignore runs where only timestamps changed: the report's generation time
# and per-alert timestamps (posture scanners stamp findings with the scan
# time). Real changes always alter other fields (IDs, rules, scores, status).
if "$PY" - "$DATA_FILE" <<'PYEOF'
import json, subprocess, sys
path = sys.argv[1]
try:
    old = json.loads(subprocess.run(
        ["git", "show", f"HEAD:{path}"], capture_output=True, text=True, check=True
    ).stdout)
except Exception:
    sys.exit(1)
new = json.load(open(path, encoding="utf-8"))
def normalise(report):
    report.pop("generated_at", None)
    for alert in report.get("alerts", []):
        if isinstance(alert, dict):
            alert.pop("timestamp", None)
    return report
old = normalise(old)
new = normalise(new)
sys.exit(0 if old == new else 1)
PYEOF
then
    log "No content change in website data; restoring committed file."
    git checkout -- "$DATA_FILE"
    mark_done
    log "===== Done (nothing to publish)"
    exit 0
fi

if [ "$DRY_RUN" = "1" ]; then
    log "Dry run: website data changed, but not committing or pushing."
    git --no-pager diff --stat -- "$DATA_FILE"
    log "===== Done (dry run)"
    exit 0
fi

git add "$DATA_FILE" || fail "git add"
git commit -m "Automated daily SOC data update ($(date '+%Y-%m-%d'))" || fail "git commit"
git push origin main || fail "git push"

mark_done
log "===== Done (published)"
