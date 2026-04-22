# Domino Workspace File Access Audit Trail — Load & Impact Test

A toolkit for exercising the **Workspace File Access Auditing** pipeline on a
Domino deployment. It targets the Falco-based audit pipeline that tracks
file-level activity on Domino Datasets and NetApp Volumes.

The repo ships three generations of the load-test script, each tuned for a
different purpose. Pick the one that matches your job:

| Script | Profile | Use for |
|---|---|---|
| `domino_audit_trail_load_test.py` (v1) | Single-workspace diagnostic: idle baseline + heavy I/O + dedup + Audit API verification + Parquet row count | Measuring per-pod Falco overhead and verifying the full pipeline end-to-end from one workspace |
| `domino_audit_trail_load_test_v2.py` (v2) | Fleet-oriented: fast file lifecycles with N parallel workers | Saturating the pipeline with raw event volume |
| **`domino_audit_trail_load_test_v4.py` (v4, recommended)** | **Fleet-oriented: statistical-programmer burst simulation with realistic idle gaps and read/write/stat/delete mix** | **Fleet-scale load tests launched inside up to several hundred concurrent workspaces via the Loadgen tool, to approximate production audit traffic without the hammering signature of v2** |

> **Feature availability:** Workspace File Access Auditing was introduced in
> **Domino 6.2.0**.

The bulk of this README covers v4 because it is the script that drives current
fleet-scale testing. The v1 and v2 scripts remain in the repo for their
original use cases. For v1's Phase 4 API verification, per-workspace resource
sampling, and `--trigger-processing` flow, see the header docstring inside
`domino_audit_trail_load_test.py` directly.

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

## What v4 does

The v4 script simulates the dataset I/O footprint of one statistical compute
(SCE) programmer working on a clinical study for ~15 minutes, then cleans up.
It is designed to run inside each of many concurrent workspaces launched by
the Loadgen tool. Aggregated across the fleet, the event stream approximates
production audit traffic without the unrealistic all-at-once saturation
signature of the v2 stress test.

### Session timeline per workspace

```
[ 0s    – ~30s ]  SESSION START — "morning load" of SDTM-style reads
[ ~30s  – ~15m ]  WORKING       — Poisson bursts of program runs
                                   (reads → writes → stat/delete)
[ ~15m  – ~16m ]  WIND-DOWN     — final small burst
[ ~16m  – ~18m ]  CLEANUP       — delete any remaining session files
[ ~18m  – ~20m ]  idle          — safety buffer before the Loadgen tool's
                                   20-minute kill switch fires
```

A hard deadline guard inside the script ensures the session never runs past
`--duration-min` minutes, and `--duration-min` is auto-clamped to leave a
2-minute buffer before the 20-minute kill switch.

### Statistical profile (defaults)

| Parameter | Distribution | Default |
|---|---|---|
| Morning-load reads | Uniform | 8–15 |
| Pre-created input files | Fixed | 8 |
| Morning pause before work begins | Uniform | 5–30 s |
| Number of working bursts | Poisson | λ = 12 |
| Burst size | Log-normal (clamped 3–20) | mean ~7.4 ops |
| Inter-burst idle gap | Exponential | mean 75 s |
| Intra-burst op spacing | Exponential | mean 0.3 s |
| Op mix within a burst | Weighted | 60% read / 25% write / 15% stat+delete |
| Overwrite probability on write | Bernoulli | 0.5 |
| Wind-down burst size | Uniform | 3–8 ops |
| Max files resident in the session pool | Hard cap | 50 |

### Per-workspace volume

Expected total ops per workspace at the defaults: **~130–150 events**, broken
down roughly as:

```
~25 ops  morning load     (8 creates + 8–15 reads)
~96 ops  working phase    (12 bursts × ~8 ops)
~5  ops  wind-down
~5–15    cleanup deletes  (whatever remains in the pool)
─────────────────────────────────────────────────
~130–150 events / workspace
```

### Fleet-level budget

For *N* workspaces all running v4 concurrently:

```
Total Falco events ≈ N × (~135 + dedup_reads + 2)
```

A concrete example matching the observed prod peak:

- 200 concurrent workspaces × ~135 events = **~27,000 events per 20-minute cohort**
- Sustained at a 200-concurrent plateau: **~80,000 events/hour**
- Sustained event rate: **~22–25 events/sec** fleet-wide, with short bursts
  into the hundreds of events/sec when program runs happen to line up

### Optional Phase 2 — dedup validation

Unchanged from v2/v3. Reads a single file `--dedup-reads` times to verify the
pipeline deduplicates repeated reads within `UniqueReadEventPeriodInMinutes`.
The pipeline should collapse N reads into **1 event**. The filename is printed
so you can search for it in the Audit App post-run.

### Session artefacts and cleanup

Each run:

- Creates a per-run subdirectory `audit_loadgen_<rand>/` inside `--dataset-path`
- Tracks every file it creates in an in-memory pool
- Deletes every tracked file at the end (including any that survived because of
  an error) so the dataset is left clean
- Removes the per-run subdirectory after cleanup

Nothing is written outside the configured dataset path.

---

## Requirements

- Python 3.8+
- Run **inside a Domino Workspace** with a Dataset or NetApp Volume mounted
- Workspace file access auditing must be **enabled** in admin settings before
  running — v4 measures aggregate load against an active pipeline
- **Domino 6.2.0 or later**

### Python dependencies

```bash
pip install requests     # only needed when --results-project is set
```

No other third-party packages are required for v4. (`psutil`, `tabulate`,
`pyarrow` etc. are only used by the v1 diagnostic.)

---

## Usage

### Minimal run (no upload, no dedup phase)

```bash
python domino_audit_trail_load_test_v4.py \
    --dataset-path /domino/datasets/local/my_dataset \
    --duration-min 15
```

### Typical fleet run — uploads summary + log to a safe project

Recommended pattern when launched by the Loadgen tool: every workspace writes
its per-run artefacts to a dedicated Domino project that survives after
Loadgen cleans up the test workspace and project.

```bash
python domino_audit_trail_load_test_v4.py \
    --dataset-path      /domino/datasets/local/my_dataset \
    --duration-min      15 \
    --dedup-reads       200 \
    --results-project   admin/audit-loadtest-results \
    --results-dir       falco_logs \
    --domino-url        https://domino-dev.myorg.com \
    --api-key           $DOMINO_USER_API_KEY
```

### Launched during workspace startup by the Loadgen tool

Use the provided `prerun_v4.sh` as the Domino pre-run script. It downloads
the latest version of `domino_audit_trail_load_test_v4.py` from GitHub and
invokes it with the configured flags. See the
[Pre-run integration with the Loadgen tool](#pre-run-integration-with-the-loadgen-tool)
section below.

---

## CLI Reference (v4)

| Flag | Required | Default | Description |
|---|---|---|---|
| `--dataset-path` | Yes | — | Path to a mounted Domino Dataset or NetApp Volume |
| `--duration-min` | No | `15` | Target active session length in minutes. Auto-clamped to leave a 2-min safety buffer before the Loadgen kill switch (≤18 min for the default 20-min switch) |
| `--file-size-kb` | No | `64` | Size of each test file (KB) |
| `--dedup-reads` | No | `0` | Number of repeated reads on a single file for dedup validation (`0` disables Phase 2) |
| `--results-project` | No | — | Safe Domino project for uploading run artefacts in the form `owner/projectName`. If unset, no upload is performed |
| `--results-dir` | No | `falco_logs` | Subdirectory within the safe project where artefacts are written |
| `--domino-url` | No | `$DOMINO_API_HOST` | **External** Domino URL. Do NOT use the internal `nucleus-frontend` address — Files API traffic is not proxied through it |
| `--api-key` | No | `$DOMINO_USER_API_KEY` | Domino API key used for the safe-project upload |

The v1 flags `--workers`, `--duration`, `--trigger-processing`,
`--check-api-lag-minutes`, and `--dedup-window-seconds` are not used by v4.

---

## Pre-run integration with the Loadgen tool

The [Loadgen tool](https://github.com/ddl-wasanthag/loadgen) launches many
Domino workspaces in parallel. Each workspace can be configured to run a
pre-run script at startup; this is how v4 is exercised at fleet scale.

### prerun_v4.sh

Located at the repo root. Downloads the latest v4 script from GitHub and
runs it with Loadgen-friendly defaults. All tunables are shell variables at
the top of the file:

```bash
DURATION_MIN=15            # Active session length
FILE_SIZE_KB=64            # File size per op
DEDUP_READS=0              # Enable dedup validation on a subset of workspaces

# Optional upload config — leave RESULTS_PROJECT empty to skip upload
RESULTS_PROJECT=""         # e.g. admin/audit-loadtest-results
RESULTS_DIR="falco_logs"
DOMINO_URL=""              # External Domino URL (same one you use in the browser)
```

`DOMINO_USER_API_KEY` is supplied automatically by the Domino workspace
environment.

The script always `exit 0`s at the end — a load-test failure will never prevent
the workspace itself from starting, which matters because Loadgen uses
workspace startup success as the signal that ramp-up is progressing.

### Recommended fleet configuration

Matching the current `full.conf` settings in the Loadgen Helm chart:

| Loadgen setting | Value | Why |
|---|---|---|
| `ramp-up.max-workspaces` | 500 (or higher) | Total workspaces over the run |
| `ramp-up.interval` | 6 s | Gives ~200 concurrent at steady state (= kill_switch / interval) |
| `soak.duration` | 30–60 min | Hold 200 concurrent through the soak |
| `shutdown.kill-switch-delay` | 1200 s (20 min) | Per-workspace lifetime cap |
| `shutdown.grace-period` | 30 min | Time for all workspaces to shut down after soak |

At those settings, each workspace runs v4 for ~15 minutes of active audit
activity and sits idle for ~5 minutes before the kill switch fires, producing
a realistic burst pattern across the fleet.

---

## Central Config reference

All audit-pipeline settings are managed via Domino Central Config:

| Key | Default | Description |
|---|---|---|
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
default 60-minute setting, events can take up to ~2 hours to appear. Communicate
this clearly to compliance and security teams — this feature is designed for
**retrospective audit and governance**, not real-time monitoring or SOC alerting.

---

## Verifying events without admin access

If you are not a Domino admin, the Audit API endpoints (and therefore the v1
Phase 4 verification) will return 403. Use this workflow for v4 runs instead:

1. Run v4 normally — it generates all the auditable file events and either
   prints a `JSON_SUMMARY: …` line to stdout or uploads the summary to the safe
   project set by `--results-project`.
2. Note the `start_wall` timestamp and, if enabled, the dedup `test_file_name`
   from the summary.
3. After the pipeline processing window has elapsed, ask a Domino admin to:
   - Open the **Workspace File Audit App**
   - Filter by the dedup filename — expect **1 event**
   - Filter by the session time range — expect bursts of events for
     `sdtm_*.bin`, `adam_*.bin`, and `bootstrap_*.bin` files
4. Alternatively, ask the admin to trigger processing immediately via the
   **Sync** button in the Audit App (or `POST /api/workspace-audit/v1/process`)
   so you do not have to wait the full 60 minutes.

---

## Outputs

### Console output

Every run prints a structured, timestamped log of each phase plus a progress
ticker every 10 seconds with cumulative ops, instantaneous ops/sec, pool size,
and elapsed time.

### `JSON_SUMMARY` stdout line

At the end of every run, v4 prints a single-line JSON summary prefixed with
`JSON_SUMMARY: ` (and, when upload is enabled, `UPLOAD_RESULT: `). Example:

```json
{
  "workspace_id":    "run-a1b2c3d4",
  "dataset_path":    "/domino/datasets/local/my_dataset",
  "duration_min":    15,
  "burst_count":     13,
  "total_ops":       142,
  "ops_per_sec":     0.16,
  "duration_s":      893.4,
  "error_count":     0,
  "ops":             { "read": 84, "write": 35, "stat": 9, "delete": 14, "rename": 0 },
  "start_wall":      "2026-04-22T09:00:00+00:00",
  "end_wall":        "2026-04-22T09:14:53+00:00",
  "falco_events_est": 142,
  "dedup":           null,
  "profile_version": "v4-burst"
}
```

Key fields to share with a Domino admin or Support:

- `start_wall` / `end_wall` — UTC timestamps of the session window; use as the
  time range filter in the Audit App or provide to Support if events are missing
- `dedup.test_file_name` — filename to search for in the Audit App to verify
  deduplication (only present when `--dedup-reads > 0`)

### Safe-project upload (optional)

When `--results-project owner/projectName` is set, v4 uploads two files into
`<project>/<results-dir>/` before exiting:

- `audit_loadgen_<DOMINO_RUN_ID>_<UTC_ts>.json` — run summary
- `audit_loadgen_<DOMINO_RUN_ID>_<UTC_ts>.log`  — full console trace

The upload uses `PUT /v1/projects/{owner}/{name}/files/{path}` with the
`X-Domino-Api-Key` header. If the upload fails it is logged as a warning but
never fails the run.

---

## Sizing guidance

- **Plan for one hardware tier step up** per workspace when auditing is enabled
  (e.g. small → medium). Domino's published overhead estimates are ~15% CPU and
  ~10% memory per workspace pod. Heavy I/O workloads (ML data ingestion, ETL,
  large Parquet reads) will sit toward the upper end.
- **For fleet load testing, use v4's `--duration-min` rather than `--workers`.**
  v4 models one workspace as one simulated programmer (single-threaded), which
  matches how the audit pipeline sees real user activity. Parallelism comes
  from running many workspaces via the Loadgen tool, not from threads inside
  one workspace.
- **Adjust `--file-size-kb`** to match typical file sizes. The default 64 KB
  stresses high-syscall-rate small-file overhead. For workloads with large
  model checkpoints or multi-GB datasets, use 512 KB – 4 MB.

---

## Troubleshooting

**The script reports I/O errors**
The filesystem experienced contention. This may be caused by Falco consuming
enough resources under high event rates to slow write throughput. Reduce the
fleet concurrency (increase `ramp-up.interval` in the Loadgen chart) or
upgrade the hardware tier and re-run.

**The working phase fires 0 bursts in the logs**
This happens when `--duration-min` is set too short (≤ ~1 min). The morning
pause and the wind-down reserve leave no time for the working phase. Use
`--duration-min 15` (the default) for production runs; short-duration smoke
tests will correctly skip straight from morning load to cleanup.

**Upload returns HTTP 404**
The most common cause is using `$DOMINO_API_HOST` as the URL, which resolves
to `nucleus-frontend.domino-platform` internally. The Files API is not proxied
through nucleus-frontend. Always pass the **external Domino URL** explicitly
via `--domino-url https://domino-dev.myorg.com`.

**Upload returns HTTP 403**
The API key lacks write permission to the safe project. Confirm the key
belongs to a user who owns or is a contributor on `owner/projectName`.

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
  expected processing window, provide the `start_wall` and `end_wall`
  timestamps from the JSON summary and the affected workspace details.
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
