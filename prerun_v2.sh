#!/bin/bash
# Domino Pre-Run Script — Workspace File Access Audit Trail Loadgen v2
# Downloads and runs the load test script as part of workspace startup.
# Output is captured in the Domino workspace launch log.

GITHUB_RAW_URL="https://raw.githubusercontent.com/ddl-wasanthag/domino-workspace-audit-trail-load-testing/main/domino_audit_trail_load_test_v2.py"
SCRIPT_PATH="/tmp/domino_audit_trail_load_test_v2.py"
DATASET_PATH="/domino/datasets/local/loadgen-audittrail"

# --- Tune these for your load profile ---
LIFECYCLES=1000    # complete file lifecycles per workspace
WORKERS=4          # parallel threads
FILE_SIZE_KB=64    # file size per operation
DEDUP_READS=0      # set > 0 on a subset of workspaces to validate dedup
# ----------------------------------------

echo "[audit-loadgen] Installing dependencies..."
pip install --quiet psutil || echo "[audit-loadgen] WARNING: pip install failed"

echo "[audit-loadgen] Downloading test script..."
curl --silent --show-error --fail --location "$GITHUB_RAW_URL" -o "$SCRIPT_PATH" || {
    echo "[audit-loadgen] WARNING: download failed — skipping load test"
    exit 0
}
chmod +x "$SCRIPT_PATH"

echo "[audit-loadgen] Running load test..."
python "$SCRIPT_PATH" \
    --dataset-path  "$DATASET_PATH" \
    --lifecycles    "$LIFECYCLES" \
    --workers       "$WORKERS" \
    --file-size-kb  "$FILE_SIZE_KB" \
    --dedup-reads   "$DEDUP_READS"

# Always exit 0 so a test failure does not prevent the workspace from starting
exit 0
