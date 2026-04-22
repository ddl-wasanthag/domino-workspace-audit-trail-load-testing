#!/bin/bash
# Domino Pre-Run Script — Workspace File Access Audit Trail Loadgen v4
# Downloads and runs the burst-profile load test as part of workspace startup.
# Output is captured in the Domino workspace launch log.

GITHUB_RAW_URL="https://raw.githubusercontent.com/ddl-wasanthag/domino-workspace-audit-trail-load-testing/main/domino_audit_trail_load_test_v4.py"
SCRIPT_PATH="/tmp/domino_audit_trail_load_test_v4.py"
DATASET_PATH="/domino/datasets/local/$DOMINO_PROJECT_NAME"

# --- Tune these for your load profile ----------------------------------------
DURATION_MIN=15          # Active session length in minutes. Auto-clamped by
                         # the script to leave a 2-min safety buffer before the
                         # Loadgen tool's 20-min kill switch (max 18 min).
FILE_SIZE_KB=64          # File size per operation (KB).
DEDUP_READS=0            # Set > 0 on a subset of workspaces to validate dedup.

# --- Optional: upload per-workspace summary + log to a safe Domino project ---
# Leave RESULTS_PROJECT empty to disable upload.
# DOMINO_USER_API_KEY is supplied automatically by the Domino workspace env.
#
# IMPORTANT:
#   * RESULTS_PROJECT must already exist AND the loadgen user must be a
#     collaborator with write access. If either is missing, the PUT returns
#     HTTP 404 with Domino's generic "Not Found" HTML page (Domino returns
#     404 for both missing-project and forbidden to avoid leaking existence).
#   * Use owner_username/project_name exactly as it appears in the URL bar,
#     e.g. integration-test/loadgen_logs - NOT display names.
RESULTS_PROJECT=""                 # e.g. integration-test/loadgen_logs
RESULTS_DIR="falco_logs"
DOMINO_URL=""                      # Optional. Falls back to $DOMINO_API_HOST
                                   # if empty. Do NOT use the internal
                                   # nucleus-frontend URL.
# -----------------------------------------------------------------------------

echo "[audit-loadgen] Project       : $DOMINO_PROJECT_NAME"
echo "[audit-loadgen] Dataset path  : $DATASET_PATH"
echo "[audit-loadgen] Duration      : ${DURATION_MIN} min"
echo "[audit-loadgen] File size     : ${FILE_SIZE_KB} KB"
echo "[audit-loadgen] Dedup reads   : ${DEDUP_READS}"
if [ -n "$RESULTS_PROJECT" ]; then
    echo "[audit-loadgen] Upload target : ${RESULTS_PROJECT}/${RESULTS_DIR}/"
else
    echo "[audit-loadgen] Upload        : disabled"
fi

echo "[audit-loadgen] Downloading test script..."
curl --silent --show-error --fail --location "$GITHUB_RAW_URL" -o "$SCRIPT_PATH" || {
    echo "[audit-loadgen] WARNING: download failed — skipping load test"
    exit 0
}
chmod +x "$SCRIPT_PATH"

# Make sure `requests` is available if we plan to upload. Best-effort only.
if [ -n "$RESULTS_PROJECT" ]; then
    python -c "import requests" 2>/dev/null || {
        echo "[audit-loadgen] Installing 'requests' for safe-project upload..."
        pip install --quiet requests || \
            echo "[audit-loadgen] WARNING: pip install requests failed — upload will be skipped"
    }
fi

echo "[audit-loadgen] Running load test..."
UPLOAD_FLAGS=()
if [ -n "$RESULTS_PROJECT" ]; then
    UPLOAD_FLAGS+=( --results-project "$RESULTS_PROJECT" --results-dir "$RESULTS_DIR" )
    [ -n "$DOMINO_URL" ] && UPLOAD_FLAGS+=( --domino-url "$DOMINO_URL" )
fi

python "$SCRIPT_PATH" \
    --dataset-path  "$DATASET_PATH" \
    --duration-min  "$DURATION_MIN" \
    --file-size-kb  "$FILE_SIZE_KB" \
    --dedup-reads   "$DEDUP_READS" \
    "${UPLOAD_FLAGS[@]}"

# Always exit 0 so a test failure does not prevent the workspace from starting.
# Loadgen uses workspace startup success as the signal that ramp-up is
# progressing; a failed load test should not stall the fleet.
exit 0
