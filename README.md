# Domino Workspace File Access Audit Trail — Load & Impact Test

A diagnostic script for measuring the performance overhead and operational
impact of enabling **Workspace File Access Auditing** on a Domino deployment.
It targets the Falco-based audit pipeline that tracks file-level activity on
Domino Datasets and NetApp Volumes.

> **Feature availability:** Workspace File Access Auditing was introduced in
> **Domino 6.2.0**.

---

## How the audit pipeline works

Understanding the architecture helps interpret test results correctly.

1. **Event Capture** — A Falco DaemonSet runs in the dataplane alongside each
   workspace pod and intercepts kernel-level filesystem syscalls (open, read,
   write, rename, unlink) for files under Dataset and NetApp Volume mount paths.
   Falco Sidekick forwards captured events to cloud object storage.

2. **Working Storage** — Raw Falco events land in a `raw-events/` folder in a
   dedicated *working bucket* (one subfolder per day). Processed output is
   stored under `output/events_MM_YYYY.parquet` — **one Parquet file per
   calendar month** that grows throughout the month.

3. **Event Processor Service** — A control-plane service that runs periodically
   (default: every **60 minutes**) to clean, deduplicate, and convert raw JSON
   events into Parquet. This is a **rolling interval timer, not a fixed
   top-of-the-hour cron**. Worst-case lag is therefore close to **2× the
   configured interval** — an event generated just after a batch completes must
   wait for the next full cycle. The processor is **not horizontally scalable**;
   only one ingestion process should run at a time.

4. **Backup Storage** — Processed raw events are archived to a separate
   *backup bucket* under `success/` or `failure/` subfolders, retained for
   up to 30 years.

5. **Query Interface** — The official
   [Workspace-File-Audit-Application](https://github.com/dominodatalab/Workspace-File-Audit-Application)
   is a Domino App (Flask + DuckDB) that fetches pre-signed Parquet download
   URLs from the audit API and queries them locally. It requires **Domino admin
   access** — all audit API endpoints enforce admin-only authorisation.

---

## What the script tests

The test runs four sequential phases and produces a final report.

### Phase 1 — Baseline Resource Snapshot

Samples CPU and RSS memory every 0.5 seconds for 5 seconds at idle, before any
file I/O begins. This establishes the starting point against which all
subsequent overhead is measured as a delta.

**Why it matters:** Without an idle snapshot you cannot distinguish
audit-attributable overhead from pre-existing workspace resource consumption.

**Caveat:** All measurements reflect the **test process only**. The Falco
sidecar daemon runs as a separate pod-level process. For its true resource
footprint, compare `/grafana-workload` metrics taken with auditing OFF versus ON
under equivalent workload conditions. Falco dropping more than **5% of events**
is the threshold at which Domino considers it a health concern.

### Phase 2 — High-Frequency Mixed File I/O Stress Test

Launches N parallel worker threads, each running a tight loop of all five
Domino-audited file operation types against a temporary subdirectory inside the
target Dataset or NetApp Volume:

| Operation | Frequency |
|-----------|-----------|
| Create    | Every iteration |
| Write     | Every iteration (overwrite a random existing file) |
| Read      | Every iteration (read a random existing file) |
| Rename    | ~20% of iterations |
| Delete    | When per-worker file pool exceeds 50 files |

CPU and memory are sampled every second. Ops/sec throughput and filesystem
errors are tracked. All five operations are included because each maps to a
distinct Falco rule with its own capture cost — a read-only workload would miss
write and rename overhead entirely.

**Pass/fail thresholds:**

| Metric | Threshold | Basis |
|--------|-----------|-------|
| CPU overhead (delta vs baseline) | ≤ 20% | Domino publishes ~15%; we add 5% margin |
| Memory overhead (delta vs baseline) | ≤ 15 MB | Relative process-level margin |
| I/O error rate | < 1% | Zero tolerance for filesystem contention |

### Phase 3 — Deduplication Window Validation

Reads a single marker file as fast as possible (every 100 ms) for a
configurable window (default: 30 seconds), generating hundreds of read events
against the same path. The filename is printed during the run so you can search
for it in the Audit App later.

Domino deduplicates audit events — repeated access to the same file by the same
user within a configurable window is collapsed to a single event. Read and write
dedup windows are configured **independently**:

| Config key | Default | Controls |
|------------|---------|---------|
| `com.cerebro.domino.workspaceFileAudit.UniqueReadEventPeriodInMinutes` | 60 min | Read event dedup window |
| `com.cerebro.domino.workspaceFileAudit.UniqueWriteEventPeriodInMinutes` | 60 min | Write event dedup window |

Both default to **60 minutes**, meaning a file read hundreds of times within an
hour produces only one audit event. This is critical for ML training loops and
ETL pipelines that read the same dataset file in a tight loop.

**Verification (manual, post-run):** After the pipeline processing window has
elapsed, ask a Domino admin to open the Workspace File Audit App and search for
the `dedup_test_*.txt` filename printed during the run. Expect **1 event**. A
large count means deduplication is not working as expected.

### Phase 4 — Audit API: Processing, Status & Event File Verification

Uses the three real Workspace File Audit Trail API endpoints to verify that the
pipeline processed Phase 2 events and that output Parquet files are accessible.

#### Important: admin-only access

**All audit API endpoints require Domino admin permissions.** This is by design
and enforced at the API level — the official Audit App runs with admin-level
credentials via Domino's app infrastructure. A regular user API key will receive
a **403 Forbidden**, which the script handles gracefully as a `SKIP` (not a
failure).

If you are not a Domino admin, skip Phase 4 and verify events via the Audit App
instead (see [Verifying events without admin access](#verifying-events-without-admin-access)).

#### The three real API endpoints

Confirmed from the [Workspace-File-Audit-Application](https://github.com/dominodatalab/Workspace-File-Audit-Application)
source code. All paths are relative to the external Domino URL:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/workspace-audit/v1/process` | Trigger an immediate processing run |
| `GET`  | `/api/workspace-audit/v1/process/latest` | Status of the most recent run |
| `GET`  | `/api/workspace-audit/v1/events/download-urls` | Pre-signed URLs for Parquet output files |

Key details discovered from the app source:

- The base path is `/api/workspace-audit` — **not** `/workspace-file-audit` and
  **not** proxied through `nucleus-frontend`
- The download-urls endpoint takes **nanosecond** Unix timestamps:
  `?startTimestamp=<epoch_ns>&endTimestamp=<epoch_ns>`
- The response is a **plain list of pre-signed URL strings**, not objects
- Authentication uses the `Authorization` header in the app, but
  `X-Domino-Api-Key` also works from scripts
- The URL must be the **external Domino hostname** (same as your browser) —
  `DOMINO_API_HOST` resolves to `nucleus-frontend` internally which cannot
  route audit traffic

#### Phase 4 steps

1. **Trigger processing** (optional) — `POST /api/workspace-audit/v1/process`
   to run a batch immediately instead of waiting for the scheduled 60-minute
   interval. Requires admin access.
2. **Poll status** — `GET /api/workspace-audit/v1/process/latest` until
   processing reports completion (or timeout after 10 minutes).
3. **Fetch download URLs** — `GET /api/workspace-audit/v1/events/download-urls`
   called three times to measure API latency variance.
4. **Download and count Parquet rows** — downloads the most recent Parquet file
   and counts event rows using `pyarrow` or `pandas` (whichever is installed).

**Pass/fail thresholds:**

| Metric | Threshold |
|--------|-----------|
| Download-URL API avg latency | ≤ 5000 ms |
| Parquet event rows | > 0 |

### Phase 5 — Final Report

Collates all measurements into a tabulated summary with pass/fail results, an
interpretation section, and sizing recommendations. Results are saved to
`audit_trail_test_results.json`.

---

## Requirements

- Python 3.8+
- Run **inside a Domino Workspace** with a Dataset or NetApp Volume mounted
- Workspace file access auditing must be **enabled** in admin settings before
  running — the script measures the overhead of an active pipeline
- **Domino 6.2.0 or later** — this feature does not exist in earlier versions
- Phase 4 requires a **Domino admin API key** — a regular user key will get 403

### Python dependencies

```bash
pip install psutil requests tabulate

# Optional but recommended for Phase 4 Parquet row counting
pip install pyarrow
```

---

## Usage

### Minimal run — I/O stress only (Phases 1–3)

Suitable for non-admin users. Generates all resource overhead measurements and
the dedup validation file. Verify events in the Audit App afterwards.

```bash
python domino_audit_trail_load_test.py \
    --dataset-path /domino/datasets/local/my_dataset
```

### Full run with immediate processing trigger (admin only)

Triggers the pipeline immediately after Phase 2 instead of waiting 60 minutes.
Results in end-to-end validation within minutes.

```bash
python domino_audit_trail_load_test.py \
    --dataset-path   /domino/datasets/local/my_dataset \
    --domino-url     https://domino-dev.myorg.com \
    --api-key        $DOMINO_USER_API_KEY \
    --trigger-processing
```

### Full run with scheduled-batch wait (admin only)

Waits for the next scheduled pipeline batch (65 minutes) then queries the API.

```bash
python domino_audit_trail_load_test.py \
    --dataset-path         /domino/datasets/local/my_dataset \
    --domino-url           https://domino-dev.myorg.com \
    --api-key              $DOMINO_USER_API_KEY \
    --check-api-lag-minutes 65
```

### Higher load simulation

```bash
python domino_audit_trail_load_test.py \
    --dataset-path /domino/datasets/local/my_dataset \
    --workers      16 \
    --duration     600 \
    --file-size-kb 512
```

---

## CLI Reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--dataset-path` | Yes | — | Path to a mounted Domino Dataset or NetApp Volume |
| `--domino-url` | No | — | **External** Domino URL (e.g. `https://domino-dev.myorg.com`). Do NOT use `$DOMINO_API_HOST` — it resolves to `nucleus-frontend` internally which cannot route audit API traffic |
| `--api-key` | No | `$DOMINO_USER_API_KEY` | Domino API key. **Must be an admin key** for Phase 4; a regular key will receive 403 |
| `--duration` | No | `300` | Duration of the Phase 2 I/O stress test (seconds) |
| `--workers` | No | `4` | Number of parallel I/O worker threads |
| `--file-size-kb` | No | `64` | Size of each test file (KB) |
| `--dedup-window-seconds` | No | `30` | Duration of the Phase 3 repeated-read window (seconds) |
| `--trigger-processing` | No | off | Immediately trigger pipeline processing via `POST /api/workspace-audit/v1/process` after Phase 2, instead of waiting for the scheduled batch. Admin key required. |
| `--check-api-lag-minutes` | No | `0` (skip) | Wait N minutes for the scheduled batch before querying the API. Ignored if `--trigger-processing` is set. |

---

## Central Config reference

All settings are managed via Domino Central Config:

| Key | Default | Description |
|-----|---------|-------------|
| `com.cerebro.domino.workspaceFileAudit.eventProcessingInMinutes` | 60 | Batch processing interval in minutes (rolling timer, min 60, max 360) |
| `com.cerebro.domino.workspaceFileAudit.UniqueReadEventPeriodInMinutes` | 60 | Read event deduplication window (minutes) |
| `com.cerebro.domino.workspaceFileAudit.UniqueWriteEventPeriodInMinutes` | 60 | Write event deduplication window (minutes) |
| `com.cerebro.domino.workspaceFileAudit.TrackedEventTypes` | `Create,Read,Write,Delete,Rename` | Event types to capture (comma-separated) |

---

## Understanding event lag

The pipeline processing interval is a **rolling timer**, not a top-of-the-hour
cron. This means:

- **Best case** — event generated just before a batch runs → visible within
  minutes of the batch completing
- **Worst case** — event generated just after a batch completes → waits a full
  cycle before it is processed

**In practice, worst-case lag is close to 2× the configured interval.** At the
default 60-minute setting, events can take up to ~2 hours to appear. This is
important to communicate clearly to compliance and security teams — this feature
is designed for **retrospective audit and governance**, not real-time monitoring
or SOC alerting.

---

## Verifying events without admin access

If you are not a Domino admin, Phase 4 API calls will return 403 (expected).
Use this workflow instead:

1. Run the script normally — Phases 1–3 complete without admin rights and
   generate all the auditable file events.
2. Note the `io_start_wall` timestamp and the `dedup_test_*.txt` filename from
   the console output (both are also saved in `audit_trail_test_results.json`).
3. After the 60-minute pipeline processing window, ask a Domino admin to:
   - Open the **Workspace File Audit App**
   - Filter by the `dedup_test_*.txt` filename — expect **1 event**
   - Filter by time range starting from `io_start_wall` — expect audit events
     for `audit_test_*.bin` files from Phase 2
4. Alternatively, ask the admin to trigger processing immediately via the
   **Sync** button in the Audit App (or `POST /api/workspace-audit/v1/process`)
   so you don't have to wait the full 60 minutes.

---

## Outputs

### Console output

The script prints a structured log throughout each phase explaining what is
being measured and why, with a live ticker during Phase 2 showing elapsed time,
cumulative ops, instantaneous ops/sec, CPU, memory, and error count.

### audit_trail_test_results.json

Written to the working directory on completion:

```json
{
  "baseline":     { "cpu_avg_pct": ..., "mem_avg_mb": ... },
  "io_result":    { "cpu_avg_pct": ..., "ops": {...}, "errors": [...],
                    "io_start_wall": "2026-04-14T09:00:00+00:00",
                    "io_end_wall":   "2026-04-14T09:05:00+00:00" },
  "dedup_result": { "file_reads": ..., "expected_events": 1,
                    "test_file_name": "dedup_test_xxxxxxxx.txt" },
  "api_result":   { "processing_status": ..., "avg_url_latency_ms": ...,
                    "parquet_row_count": ..., "admin_required": false },
  "summary":      { "cpu_overhead_pct": ..., "error_rate_pct": ..., ... }
}
```

Key fields to share with a Domino admin or Support:

- `io_start_wall` / `io_end_wall` — UTC timestamps of the Phase 2 window; use
  as the time range filter in the Audit App or provide to Support if events are
  missing
- `dedup_result.test_file_name` — filename to search for in the Audit App to
  verify deduplication
- `api_result.admin_required` — `true` if Phase 4 was blocked by 403

---

## Sizing guidance

- **Plan for one hardware tier step up** per workspace when auditing is enabled
  (e.g. small → medium). Domino's published overhead estimates are ~15% CPU and
  ~10% memory per workspace pod. Heavy I/O workloads (ML data ingestion, ETL,
  large Parquet reads) will sit toward the upper end.
- **Scale `--workers`** to match your expected concurrent-workspace count. Start
  with `--workers 4` for interactive workloads; increase toward `--workers 16`
  for data-intensive teams.
- **Adjust `--file-size-kb`** to match typical file sizes. The default 64 KB
  stresses high-syscall-rate small-file overhead. For workloads with large model
  checkpoints or multi-GB datasets, use 512 KB–4 MB.

---

## Troubleshooting

**Phase 2 reports I/O errors**
The filesystem experienced contention. This may be caused by Falco consuming
enough resources under high event rates to slow write throughput. Reduce
`--workers` or upgrade the hardware tier and re-run.

**Phase 4 returns 403 Forbidden**
Expected for non-admin users. All audit API endpoints require Domino admin
permissions. See [Verifying events without admin access](#verifying-events-without-admin-access).

**Phase 4 returns 404**
The most common cause is using `$DOMINO_API_HOST` as the URL, which resolves to
`nucleus-frontend.domino-platform` internally. The audit service is not proxied
through nucleus-frontend. Always pass the **external Domino URL** explicitly:
`--domino-url https://domino-dev.myorg.com`.

**Phase 4 shows zero rows in Parquet after triggering processing**
Possible causes:
1. Processing completed before Phase 2 events were staged — trigger again after
   a short wait
2. Audit Trail was not enabled before the test ran — check admin settings
3. The time range filter in `download-urls` did not overlap with event
   timestamps — check `io_start_wall` in the JSON output

**Phase 4 download-URL latency exceeds 5000 ms**
The Parquet files are monthly aggregates that grow throughout the month. Query
performance may degrade toward month-end on high-activity deployments.

**Baseline CPU is already above 10%**
Another process is consuming resources. Close other notebooks, terminals, or
background jobs and re-run for cleaner overhead measurements.

**Grafana shows Falco dropping events (> 5% drop rate)**
Two patterns to distinguish:
- *Sudden spike, processing drops to zero* — likely a service crash. Restart
  Falco and Falco Sidekick in the `domino-platform` namespace and monitor.
- *Sustained elevated drops during peak activity* — likely buffer overflow.
  Restart as a quick mitigation. If drops persist, coordinate with Domino
  Engineering to increase the Falco buffer size via ConfigMap. Do not reduce
  `TrackedEventTypes` without compliance team approval.

---

## Monitoring during a production rollout

- **`/grafana-workload`** — per-pod CPU and memory trends; the most reliable
  place to see Falco sidecar overhead alongside the workspace process. Watch the
  `dropped_events` rate — alert threshold is > 5%.
- **Workspace File Audit App** — primary interface for browsing and verifying
  captured events. Requires Domino admin access. Supports filtering by user,
  project, dataset/volume, file path, event type, date range, and workspace.
- **Domino Support** — if events are missing or significantly delayed beyond the
  expected processing window, provide the `io_start_wall` and `io_end_wall`
  timestamps from the JSON output and the affected workspace details.
- In **Domino Cloud deployments**, Domino's platform team monitors the audit
  pipeline infrastructure and manages all underlying alerts automatically.

---

## Related documentation

- [Workspace File Access Events (User Guide)](https://docs.dominodatalab.com/en/cloud/user_guide/4fef7e/workspace-file-access-events/)
- [Use the Workspace File Audit App (Admin Guide)](https://docs.dominodatalab.com/en/latest/admin_guide/f3cc84/use-the-workspace-file-audit-app/)
- [Enable Workspace File Audits (User Guide)](https://docs.dominodatalab.com/en/cloud/user_guide/45577e/enable-workspace-file-audits/)
- [Domino Audit Trail (User Guide)](https://docs.dominodatalab.com/en/cloud/user_guide/85fbb1/domino-audit-trail/)
- [Workspace File Audit Trail API (API Guide)](https://docs.dominodatalab.com/en/cloud/api_guide/22d1e2/workspace-file-audit-trail-api/)
- [Provision Terraform Infrastructure (Admin Guide)](https://docs.dominodatalab.com/en/latest/admin_guide/e0f2ff/provision-terraform-infrastructure-and-runtime-environment/)
- [Configuration Records / Central Config (Admin Guide)](https://docs.dominodatalab.com/en/latest/admin_guide/71d6ad/configuration-records/)
- [Workspace-File-Audit-Application (GitHub)](https://github.com/dominodatalab/Workspace-File-Audit-Application)
