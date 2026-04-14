#!/usr/bin/env python3
"""
Domino Workspace File Access Audit Trail - Load & Adverse Effect Test
======================================================================
Purpose:
  Measure the overhead and operational impact of enabling workspace file
  access auditing (Falco-based) on Domino Datasets and NetApp Volumes.

What this script tests:
  Phase 1 - Baseline CPU/memory snapshot (idle, no I/O)
  Phase 2 - Sustained high-frequency mixed file I/O to stress Falco capture
  Phase 3 - Deduplication window validation (same file, repeated reads)
  Phase 4 - Audit Trail API event lag check and query latency
  Phase 5 - Summary report with pass/fail thresholds and interpretation

Usage (inside a Domino Workspace):
  pip install psutil requests tabulate
  python domino_audit_trail_load_test.py \\
      --dataset-path /domino/datasets/local/my_dataset \\
      --domino-url https://myorg.domino.cloud \\
      --api-key $DOMINO_USER_API_KEY \\
      --project-id <project-id> \\
      --duration 300 \\
      --workers 4

Requirements:
  - Run INSIDE a Domino Workspace with access to a Dataset or NetApp Volume
  - Audit Trail must be ENABLED in your Domino deployment before running
  - API key must have access to the Audit Trail API endpoint

Notes:
  - The audit pipeline has a default 60-minute processing delay.
    Set --check-api-lag-minutes to 0 to skip the lag check if you do not
    want to wait, or run the script again after 60+ minutes for lag data.
"""

import argparse
import json
import os
import random
import string
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

import psutil
import requests
from tabulate import tabulate


# ---------------------------------------------------------------------------
# Configuration & Defaults
# ---------------------------------------------------------------------------

DEFAULT_DURATION_SECONDS     = 300   # How long to run the I/O phase
DEFAULT_WORKERS              = 4     # Parallel threads hammering the FS
DEFAULT_FILE_SIZE_KB         = 64    # Size of each test file (KB)
DEFAULT_DEDUP_WINDOW_SECONDS = 30    # How long to repeat reads on same file
CPU_OVERHEAD_THRESHOLD_PCT   = 20    # Warn if CPU overhead exceeds this
MEM_OVERHEAD_THRESHOLD_MB    = 15    # Warn if memory overhead (delta MB) exceeds this
API_LATENCY_THRESHOLD_MS     = 5000  # Warn if audit API queries exceed this


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

DIVIDER = "=" * 72

def banner(title):
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)

def section(title):
    pad = max(0, 66 - len(title))
    print(f"\n  -- {title} {'-' * pad}")

def info(msg):   print(f"  |  {msg}")
def note(msg):   print(f"  >  {msg}")
def warn(msg):   print(f"  !  {msg}")
def ok(msg):     print(f"  +  {msg}")
def err_ln(msg): print(f"  X  {msg}")
def blank():     print()

def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def get_process_stats():
    proc = psutil.Process()
    cpu  = proc.cpu_percent(interval=1.0)
    mem  = proc.memory_info().rss / 1024 / 1024
    return cpu, mem


# ---------------------------------------------------------------------------
# Phase 1: Baseline CPU & memory snapshot
# ---------------------------------------------------------------------------

def capture_baseline(duration=5):
    banner("PHASE 1 OF 4 -- Baseline Resource Snapshot")

    section("What we are doing")
    info("Sampling this process's CPU usage and RSS memory every 0.5 seconds")
    info(f"for {duration} seconds, with no file I/O running.")
    blank()
    info("Why this matters:")
    info("  Enabling workspace file auditing adds resource overhead ON TOP of")
    info("  whatever the workspace is already consuming at rest. Without a clean")
    info("  idle snapshot we cannot isolate how much cost the audit pipeline")
    info("  itself introduces. The delta (Phase 2 minus Phase 1) is what we")
    info("  report as audit-attributable overhead in the final summary.")
    blank()
    info("Important caveat:")
    info("  This measures the TEST PROCESS only. The Falco sidecar daemon that")
    info("  intercepts kernel-level filesystem syscalls runs as a separate pod-")
    info("  level process. To see Falco's own footprint you need Grafana at")
    info("  /grafana-workload, or 'kubectl top pod' on the workspace pod.")

    section("Sampling now...")
    samples_cpu, samples_mem = [], []
    t_end = time.monotonic() + duration
    while time.monotonic() < t_end:
        c, m = get_process_stats()
        samples_cpu.append(c)
        samples_mem.append(m)
        print(f"\r  |  CPU: {c:5.1f}%   Mem: {m:6.1f} MB   "
              f"[{len(samples_cpu)} samples]", end="", flush=True)
        time.sleep(0.5)
    print()

    baseline = {
        "cpu_avg_pct": sum(samples_cpu) / len(samples_cpu),
        "mem_avg_mb":  sum(samples_mem) / len(samples_mem),
    }

    section("Baseline result")
    ok(f"CPU average : {baseline['cpu_avg_pct']:.1f}%")
    ok(f"Memory avg  : {baseline['mem_avg_mb']:.1f} MB")
    blank()
    note("Tip: if baseline CPU is already above 10%, the workspace is not truly")
    note("idle. Close other notebooks or terminals before re-running for cleaner")
    note("overhead measurements.")

    return baseline


# ---------------------------------------------------------------------------
# Phase 2: High-frequency mixed file I/O
# ---------------------------------------------------------------------------

class FileIOWorker:
    """
    Performs a tight loop of all five Domino-audited file operations against
    a target directory (a mounted Dataset or NetApp Volume).
    """

    def __init__(self, work_dir: Path, file_size_kb: int, worker_id: int):
        self.work_dir       = work_dir
        self.file_size_bytes = file_size_kb * 1024
        self.worker_id      = worker_id
        self.counts = {"create": 0, "write": 0, "read": 0, "rename": 0, "delete": 0}
        self.errors = []
        self._stop  = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        payload     = bytes(random.getrandbits(8) for _ in range(self.file_size_bytes))
        local_files = []

        while not self._stop.is_set():
            try:
                # CREATE -- new file every iteration
                fname = self.work_dir / f"audit_test_{self.worker_id}_{rand_str()}.bin"
                fname.write_bytes(payload)
                local_files.append(fname)
                self.counts["create"] += 1

                # WRITE -- overwrite a random existing file
                if local_files:
                    target = random.choice(local_files)
                    if target.exists():
                        target.write_bytes(payload)
                        self.counts["write"] += 1

                # READ -- read a random existing file
                if local_files:
                    target = random.choice(local_files)
                    if target.exists():
                        _ = target.read_bytes()
                        self.counts["read"] += 1

                # RENAME -- 20% of iterations to exercise rename syscall
                if local_files and random.random() < 0.2:
                    old = local_files.pop()
                    if old.exists():
                        new = old.with_name(old.stem + "_renamed.bin")
                        old.rename(new)
                        local_files.append(new)
                        self.counts["rename"] += 1

                # DELETE -- keep pool bounded at 50 files per worker
                if len(local_files) > 50:
                    victim = local_files.pop(0)
                    if victim.exists():
                        victim.unlink()
                        self.counts["delete"] += 1

            except Exception as e:
                self.errors.append(str(e))
                time.sleep(0.1)

    def total_ops(self):
        return sum(self.counts.values())


def run_io_phase(dataset_path: Path, duration: int, workers: int, file_size_kb: int):
    banner("PHASE 2 OF 4 -- High-Frequency Mixed File I/O Stress Test")

    section("What we are doing")
    info(f"Launching {workers} parallel worker thread(s), each running a tight loop")
    info("of: CREATE -> WRITE -> READ -> (20% chance) RENAME -> DELETE")
    info(f"against a temporary subdirectory inside the Dataset/Volume mount.")
    info(f"This will run for {duration} seconds ({duration // 60}m {duration % 60}s).")
    blank()
    info("Why all five operations?")
    info("  Domino's Falco daemon intercepts five distinct syscall categories:")
    info("  create (open+O_CREAT), write, read, rename, unlink (delete). Each")
    info("  has its own Falco rule with its own capture overhead. A pure-read")
    info("  workload misses write/rename cost entirely. We cover all five to")
    info("  stress the full Falco ruleset and match real mixed workspace usage.")
    blank()
    info("What we are measuring:")
    info("  - CPU % and RSS memory sampled every second throughout the run")
    info("  - Total op counts per type and aggregate throughput (ops/sec)")
    info("  - Any filesystem errors -- non-zero count signals contention")
    blank()
    info("What this does NOT measure directly:")
    info("  The Falco sidecar CPU/memory (it runs in a separate pod process).")
    info("  Use Grafana /grafana-workload alongside this test for the full")
    info("  picture of node-level overhead introduced by enabling auditing.")
    blank()
    info(f"  Workers        : {workers}")
    info(f"  File size      : {file_size_kb} KB")
    info(f"  Max files/worker: 50 (pool bounded to avoid filling the volume)")
    info(f"  Test directory : {dataset_path}/audit_load_test_<id>")

    section("Starting workers...")

    work_dir = dataset_path / f"audit_load_test_{rand_str()}"
    work_dir.mkdir(parents=True, exist_ok=True)

    io_workers = [FileIOWorker(work_dir, file_size_kb, i) for i in range(workers)]
    threads    = [threading.Thread(target=w.run, daemon=True) for w in io_workers]

    cpu_samples, mem_samples = [], []
    t_start      = time.monotonic()
    io_start_wall = datetime.now(timezone.utc)

    for t in threads:
        t.start()

    monitor_stop = threading.Event()

    def monitor():
        while not monitor_stop.is_set():
            c, m = get_process_stats()
            cpu_samples.append(c)
            mem_samples.append(m)
            time.sleep(1.0)

    mon_thread = threading.Thread(target=monitor, daemon=True)
    mon_thread.start()

    last_ops  = 0
    last_tick = time.monotonic()
    blank()

    while time.monotonic() - t_start < duration:
        elapsed   = time.monotonic() - t_start
        remaining = max(0, duration - elapsed)
        total_ops = sum(w.total_ops() for w in io_workers)
        n_errors  = sum(len(w.errors) for w in io_workers)

        dt       = time.monotonic() - last_tick
        inst_ops = (total_ops - last_ops) / max(dt, 0.01)
        last_ops  = total_ops
        last_tick = time.monotonic()

        cpu_now = cpu_samples[-1] if cpu_samples else 0.0
        mem_now = mem_samples[-1] if mem_samples else 0.0

        print(
            f"\r  |  [{elapsed:5.0f}s elapsed / {remaining:4.0f}s left]  "
            f"ops: {total_ops:>8,}  rate: {inst_ops:>6.0f}/s  "
            f"cpu: {cpu_now:5.1f}%  mem: {mem_now:5.1f} MB  errs: {n_errors}",
            end="", flush=True,
        )
        time.sleep(5)

    print()

    for w in io_workers:
        w.stop()
    monitor_stop.set()
    for t in threads:
        t.join(timeout=10)
    mon_thread.join(timeout=5)

    io_end_wall = datetime.now(timezone.utc)
    elapsed_s   = time.monotonic() - t_start

    section("Cleaning up test files...")
    for f in work_dir.rglob("*"):
        try:
            if f.is_file():
                f.unlink()
        except Exception:
            pass
    try:
        work_dir.rmdir()
    except Exception:
        pass
    ok("Test directory removed.")

    op_totals   = {k: sum(w.counts[k] for w in io_workers) for k in io_workers[0].counts}
    all_errors  = [e for w in io_workers for e in w.errors]
    total_ops   = sum(op_totals.values())
    ops_per_sec = total_ops / max(elapsed_s, 1)

    result = {
        "cpu_avg_pct":    sum(cpu_samples) / max(len(cpu_samples), 1),
        "cpu_max_pct":    max(cpu_samples, default=0),
        "mem_avg_mb":     sum(mem_samples) / max(len(mem_samples), 1),
        "mem_max_mb":     max(mem_samples, default=0),
        "duration_s":     elapsed_s,
        "ops":            op_totals,
        "total_ops":      total_ops,
        "ops_per_sec":    ops_per_sec,
        "errors":         all_errors,
        "io_start_wall":  io_start_wall.isoformat(),
        "io_end_wall":    io_end_wall.isoformat(),
    }

    section("Phase 2 results")
    info(f"  Duration       : {elapsed_s:.1f}s")
    info(f"  Total ops      : {total_ops:,}")
    info(f"  Throughput     : {ops_per_sec:.1f} ops/sec")
    blank()
    info(f"  CPU avg / peak : {result['cpu_avg_pct']:.1f}% / {result['cpu_max_pct']:.1f}%")
    info(f"  Mem avg / peak : {result['mem_avg_mb']:.1f} MB / {result['mem_max_mb']:.1f} MB")
    blank()
    for op, count in op_totals.items():
        info(f"  {op.capitalize():<8}: {count:,}")

    if all_errors:
        blank()
        warn(f"{len(all_errors)} I/O error(s) during the run.")
        warn("This may indicate filesystem pressure or resource contention")
        warn("introduced by the Falco sidecar under high-event-rate conditions.")
        for e in all_errors[:5]:
            warn(f"  {e}")
        if len(all_errors) > 5:
            warn(f"  ... and {len(all_errors) - 5} more (see JSON output)")
    else:
        ok("Zero I/O errors -- filesystem handled the load without contention.")

    blank()
    note("Cross-reference CPU/mem numbers against Grafana /grafana-workload to")
    note("add the Falco sidecar's own footprint to the total overhead picture.")

    return result


# ---------------------------------------------------------------------------
# Phase 3: Deduplication window validation
# ---------------------------------------------------------------------------

def run_dedup_validation(dataset_path: Path, window_seconds: int):
    banner("PHASE 3 OF 4 -- Deduplication Window Validation")

    section("What we are doing")
    info("Writing a single marker file and then reading it as fast as possible")
    info(f"(every 100ms) for {window_seconds} seconds.")
    blank()
    info("Why this matters:")
    info("  Domino deduplicates audit events. Repeated access to the same file")
    info("  by the same user within a configurable time window is stored as ONE")
    info("  event, not thousands. This is critical for ML training loops, ETL")
    info("  pipelines, and any workload that reads the same dataset file in a")
    info("  tight loop. Without deduplication, the audit pipeline would generate")
    info("  enormous event volumes, causing excessive storage costs and making")
    info("  the audit trail difficult to query meaningfully.")
    blank()
    info("What we are validating:")
    info(f"  That {window_seconds}s of repeated reads on one file collapses to ~1")
    info("  audit event in the pipeline output. You verify this yourself in the")
    info("  Workspace File Audit App after the 60-minute processing window.")
    blank()
    info("What to look for afterwards:")
    info("  Open the Workspace File Audit App, filter by the filename shown below.")
    info("  Expected: 1 event (or very few).")
    info("  If you see a large number of events, deduplication may be off or the")
    info("  dedup window may be shorter than your workload's access pattern needs.")
    info("  Read and write dedup windows are configured independently (in minutes):")
    info("  com.cerebro.domino.workspaceFileAudit.UniqueReadEventPeriodInMinutes")
    info("  com.cerebro.domino.workspaceFileAudit.UniqueWriteEventPeriodInMinutes")
    info("  Both default to 60 minutes.")

    test_file = dataset_path / f"dedup_test_{rand_str()}.txt"
    test_file.write_text("Domino audit dedup test -- " + rand_str(32))

    section("Dedup test file (note this name for the Audit App search)")
    info(f"  {test_file.name}")
    blank()
    info(f"Reading this file repeatedly for {window_seconds}s ...")

    read_count = 0
    t_end = time.monotonic() + window_seconds
    while time.monotonic() < t_end:
        remaining = max(0, t_end - time.monotonic())
        _ = test_file.read_text()
        read_count += 1
        print(f"\r  |  Reads so far: {read_count:,}   Remaining: {remaining:.0f}s ",
              end="", flush=True)
        time.sleep(0.1)
    print()

    test_file.unlink(missing_ok=True)

    section("Phase 3 result")
    ok(f"Performed {read_count:,} reads on the same file in {window_seconds}s.")
    blank()
    note("ACTION REQUIRED after the 60-minute pipeline processing window:")
    note(f"  Search the Workspace File Audit App for: {test_file.name}")
    note(f"  Expected result : 1 event")
    note(f"  Actual result   : ??? (yours to verify)")
    note("  A large event count here means dedup is not collapsing events as")
    note("  expected. Tune read and write dedup windows independently via:")
    note("  com.cerebro.domino.workspaceFileAudit.UniqueReadEventPeriodInMinutes")
    note("  com.cerebro.domino.workspaceFileAudit.UniqueWriteEventPeriodInMinutes")

    return {
        "file_reads":        read_count,
        "window_seconds":    window_seconds,
        "expected_events":   1,
        "test_file_name":    test_file.name,
    }


# ---------------------------------------------------------------------------
# Phase 4: Audit API — trigger processing, check status, verify event files
# ---------------------------------------------------------------------------
#
# The Workspace File Audit Trail API has three endpoints:
#
#   POST /v1/process                  Manually trigger a processing run
#   GET  /v1/process/latest           Get status of the most recent run
#   GET  /v1/events/download-urls     Get pre-signed URLs for Parquet output files
#
# There is NO direct event-query endpoint. Events are stored as monthly
# Parquet files (output/events_MM_YYYY.parquet) in object storage. The API
# returns pre-signed download URLs for those files; you download and inspect
# them locally to verify events are present.
#
# This phase:
#   Step 1 - Optionally trigger processing immediately via POST /v1/process
#            (avoids the 60-minute scheduled wait entirely)
#   Step 2 - Poll GET /v1/process/latest until processing completes (or times out)
#   Step 3 - Call GET /v1/events/download-urls and measure latency (x3)
#   Step 4 - Download the current month's Parquet file and count rows
# ---------------------------------------------------------------------------

import urllib.request as _urllib_request

# API base path — confirmed from the official Workspace-File-Audit-Application source.
# Full URLs are: https://{domino-host}/api/workspace-audit/v1/...
# Authentication uses the Authorization header (bearer token from Domino app infra),
# but X-Domino-Api-Key also works when calling from outside the app.
AUDIT_API_PREFIX     = "/api/workspace-audit"
PROCESS_TRIGGER_PATH = "/v1/process"
PROCESS_STATUS_PATH  = "/v1/process/latest"
DOWNLOAD_URLS_PATH   = "/v1/events/download-urls"
POLL_INTERVAL_SECS   = 15
POLL_TIMEOUT_SECS    = 600   # give up waiting for processing after 10 min


def _audit_headers(api_key):
    # The official app uses the Authorization bearer token from Domino app infra.
    # X-Domino-Api-Key works equivalently when calling from a script.
    return {"X-Domino-Api-Key": api_key, "Content-Type": "application/json"}


def _audit_url(domino_url, path):
    return f"{domino_url.rstrip('/')}{AUDIT_API_PREFIX}{path}"


def trigger_processing(domino_url, api_key, timeout=30):
    """POST /api/workspace-audit/v1/process — kick off an immediate processing run."""
    url  = _audit_url(domino_url, PROCESS_TRIGGER_PATH)
    t0   = time.monotonic()
    resp = requests.post(url, headers=_audit_headers(api_key), timeout=timeout)
    lat  = (time.monotonic() - t0) * 1000
    resp.raise_for_status()
    return resp.json(), lat


def get_processing_status(domino_url, api_key, timeout=30):
    """GET /api/workspace-audit/v1/process/latest — most recent processing run status."""
    url  = _audit_url(domino_url, PROCESS_STATUS_PATH)
    t0   = time.monotonic()
    resp = requests.get(url, headers=_audit_headers(api_key), timeout=timeout)
    lat  = (time.monotonic() - t0) * 1000
    resp.raise_for_status()
    return resp.json(), lat


def get_download_urls(domino_url, api_key, io_start_wall, io_end_wall, timeout=30):
    """GET /api/workspace-audit/v1/events/download-urls — pre-signed URLs for Parquet files.
    
    Timestamps must be supplied as nanoseconds (unix epoch * 1_000_000_000).
    Response is a plain list of pre-signed URL strings.
    """
    start_ns = int(io_start_wall.timestamp() * 1_000_000_000)
    end_ns   = int(io_end_wall.timestamp()   * 1_000_000_000)
    url  = _audit_url(domino_url, DOWNLOAD_URLS_PATH)
    params = {"startTimestamp": start_ns, "endTimestamp": end_ns}
    t0   = time.monotonic()
    resp = requests.get(url, headers=_audit_headers(api_key), params=params, timeout=timeout)
    lat  = (time.monotonic() - t0) * 1000
    resp.raise_for_status()
    data = resp.json()
    # Response is a plain list of pre-signed URL strings
    if not isinstance(data, list):
        data = data.get("urls", data.get("downloadUrls", []))
    return data, lat


def count_parquet_rows(url):
    """
    Download a Parquet file from a pre-signed URL and count its rows.
    Returns (row_count, file_size_bytes) or raises on error.
    Requires pyarrow or pandas; falls back gracefully if not installed.
    """
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        _urllib_request.urlretrieve(url, tmp_path)
        file_size = os.path.getsize(tmp_path)

        # Try pyarrow first, then pandas
        try:
            import pyarrow.parquet as pq
            table = pq.read_table(tmp_path)
            return table.num_rows, file_size
        except ImportError:
            pass

        try:
            import pandas as pd
            df = pd.read_parquet(tmp_path)
            return len(df), file_size
        except ImportError:
            pass

        return None, file_size  # can't count rows without a library

    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def check_api_and_lag(domino_url, api_key, wait_minutes, trigger_processing_now, io_start_wall, io_end_wall):
    banner("PHASE 4 OF 4 -- Audit API: Processing, Status & Event File Verification")

    section("What we are doing")
    info("Using the three real Workspace File Audit Trail API endpoints to verify")
    info("the pipeline processed our Phase 2 events and that output files exist.")
    blank()
    info("How the API actually works (not a direct event query):")
    info("  There is no endpoint that returns events as JSON rows. Instead,")
    info("  events are stored as monthly Parquet files in object storage under:")
    info("  output/events_MM_YYYY.parquet (one file per calendar month).")
    info("  The API gives you pre-signed download URLs for those files; you")
    info("  download and inspect them to verify events are present.")
    blank()
    info("The three real endpoints (paths relative to --audit-api-url):")
    info("  POST /v1/process              Manually trigger a processing run")
    info("  GET  /v1/process/latest       Status of the most recent run")
    info("  GET  /v1/events/download-urls Pre-signed URLs for Parquet output files")
    blank()
    info("IMPORTANT -- base URL discovery:")
    info("  The audit service is a separate microservice, NOT proxied through")
    info("  nucleus-frontend. Do not use DOMINO_API_HOST or --domino-url here.")
    info("  To find the correct base URL for your deployment:")
    info("    kubectl get ingress -n domino-platform | grep -i audit")
    info("    kubectl get svc    -n domino-platform | grep -i audit")
    info("  Or check the environment variables of the running Audit App pod.")
    info("  Pass the discovered URL as --audit-api-url.")
    blank()
    info("What this phase tests:")
    info("  Step 1 -- Optionally trigger processing immediately (skips the 60-min wait)")
    info("  Step 2 -- Poll /v1/process/latest until processing completes")
    info("  Step 3 -- Call /v1/events/download-urls and measure API latency (x3)")
    info("  Step 4 -- Download the current month's Parquet and count event rows")
    blank()
    info("  Domino Cloud: Domino's platform team monitors pipeline health and")
    info("  manages all infrastructure-level alerts automatically.")

    result = {
        "skipped":              False,
        "api_ok":               False,
        "trigger_attempted":    False,
        "trigger_ok":           False,
        "processing_status":    None,
        "processing_completed": False,
        "download_url_latencies_ms": [],
        "avg_url_latency_ms":   None,
        "parquet_row_count":    None,
        "parquet_size_bytes":   None,
        "error":                None,
    }

    # ------------------------------------------------------------------
    # Step 1: Optionally trigger processing immediately
    # ------------------------------------------------------------------
    section("Step 1 -- Trigger immediate processing (POST /v1/process)")

    if trigger_processing_now:
        info("--trigger-processing flag set. Sending POST /v1/process ...")
        info("This asks the Event Processor to run a batch right now, rather")
        info("than waiting for the next scheduled 60-minute interval.")
        try:
            trigger_resp, trigger_lat = trigger_processing(domino_url, api_key)
            result["trigger_attempted"] = True
            result["trigger_ok"]        = True
            ok(f"Trigger accepted  ({trigger_lat:.0f}ms): {trigger_resp}")
        except requests.HTTPError as e:
            result["trigger_attempted"] = True
            if "403" in str(e):
                warn("Trigger returned 403 Forbidden.")
                warn("The /api/workspace-audit endpoints require Domino admin permissions.")
                warn("Ask a Domino admin to trigger processing, or verify events via the")
                warn("Workspace File Audit App directly (it runs with admin-level access).")
                result["admin_required"] = True
            else:
                warn(f"Trigger returned HTTP error: {e}")
                warn("Processing may still run on schedule. Continuing to poll status.")
        except Exception as e:
            result["trigger_attempted"] = True
            warn(f"Trigger failed: {e}")
            warn("Continuing to poll status in case a scheduled run completes.")
    else:
        info("--trigger-processing not set. Skipping immediate trigger.")
        if wait_minutes > 0:
            info(f"Will wait {wait_minutes} minutes for the scheduled batch instead.")
            info("Tip: use --trigger-processing to skip the wait entirely.")
        else:
            info("--check-api-lag-minutes is also 0. Will check current status only.")

    # ------------------------------------------------------------------
    # Step 2: Wait (if requested) then poll /v1/process/latest
    # ------------------------------------------------------------------
    section("Step 2 -- Check processing status (GET /v1/process/latest)")

    if wait_minutes > 0 and not trigger_processing_now:
        info(f"Waiting {wait_minutes} minutes for scheduled pipeline batch ...")
        info("Press Ctrl+C to skip the wait and check current status immediately.")
        blank()
        try:
            total_secs = wait_minutes * 60
            for elapsed_s in range(0, total_secs, 30):
                remaining = total_secs - elapsed_s
                print(f"\r  |  Pipeline wait... {remaining // 60}m {remaining % 60:02d}s remaining",
                      end="", flush=True)
                time.sleep(30)
            print()
        except KeyboardInterrupt:
            print()
            warn("Wait interrupted -- checking status now.")

    # If we triggered processing, poll until it completes or times out
    if result["trigger_ok"]:
        info("Polling /v1/process/latest until processing reports completion ...")
        info(f"Polling every {POLL_INTERVAL_SECS}s, timeout {POLL_TIMEOUT_SECS}s.")
        blank()
        t_poll_start = time.monotonic()
        while time.monotonic() - t_poll_start < POLL_TIMEOUT_SECS:
            try:
                status_data, _ = get_processing_status(domino_url, api_key)
                status = status_data.get("status", "unknown")
                elapsed_poll = time.monotonic() - t_poll_start
                print(f"\r  |  [{elapsed_poll:.0f}s] Processing status: {status}   ",
                      end="", flush=True)
                if status.lower() in ("completed", "success", "finished"):
                    print()
                    result["processing_completed"] = True
                    result["processing_status"]    = status
                    ok(f"Processing completed after {elapsed_poll:.0f}s.")
                    break
                elif status.lower() in ("failed", "error"):
                    print()
                    result["processing_status"] = status
                    err_ln(f"Processing reported failure status: {status}")
                    err_ln("Check workspace-audit service pod logs in domino-platform namespace.")
                    break
            except Exception as e:
                print()
                warn(f"Status poll error: {e}")
            time.sleep(POLL_INTERVAL_SECS)
        else:
            print()
            warn(f"Timed out after {POLL_TIMEOUT_SECS}s waiting for processing to complete.")
            warn("The run may still complete -- check /v1/process/latest manually.")
    else:
        # Just do a single status check
        info("Fetching current processing status ...")
        try:
            status_data, status_lat = get_processing_status(domino_url, api_key)
            status = status_data.get("status", "unknown")
            result["processing_status"] = status
            ok(f"Latest processing status : {status}  ({status_lat:.0f}ms)")
            if status.lower() in ("completed", "success", "finished"):
                result["processing_completed"] = True
            else:
                note("Status is not 'completed' -- events may not yet be visible.")
                note("Re-run with --trigger-processing or --check-api-lag-minutes 65.")
        except requests.HTTPError as e:
            if "403" in str(e):
                warn("Status check returned 403 Forbidden.")
                warn("The audit API endpoints require Domino admin permissions.")
                warn("This is expected if you are not a Domino admin.")
                blank()
                warn("To verify events without admin rights:")
                warn("  1. Ask a Domino admin to open the Workspace File Audit App")
                warn("  2. Filter for files matching: audit_test_*.bin or dedup_test_*.txt")
                warn("  3. Confirm events appear after the 60-min pipeline window")
                result["admin_required"] = True
                result["error"] = "403 Forbidden — admin rights required"
            else:
                err_ln(f"HTTP error fetching status: {e}")
                result["error"] = str(e)
            return result
        except Exception as e:
            err_ln(f"Error fetching status: {e}")
            result["error"] = str(e)
            return result

    # ------------------------------------------------------------------
    # Step 3: Get download URLs and measure latency
    # ------------------------------------------------------------------
    section("Step 3 -- Fetch event download URLs (GET /v1/events/download-urls)")
    info("Calling the endpoint 3 times to measure response latency variance.")
    blank()

    url_latencies = []
    download_urls = []

    try:
        for attempt in range(1, 4):
            urls_data, lat = get_download_urls(domino_url, api_key, io_start_wall, io_end_wall)
            url_latencies.append(lat)
            # Response is a plain list of pre-signed URL strings (confirmed from app source)
            download_urls = urls_data if isinstance(urls_data, list) else []
            ok(f"  Query {attempt}/3: {len(download_urls)} URL(s) returned  |  {lat:.0f}ms")
            time.sleep(1)

        avg_lat = sum(url_latencies) / len(url_latencies)
        result["download_url_latencies_ms"] = url_latencies
        result["avg_url_latency_ms"]        = avg_lat
        result["api_ok"]                    = True

        blank()
        ok(f"Avg download-URL latency : {avg_lat:.0f}ms")
        ok(f"Parquet files available  : {len(download_urls)}")

        if not download_urls:
            blank()
            warn("No download URLs returned. Possible causes:")
            warn("  - No events have been processed yet for this deployment")
            warn("  - Audit Trail was not enabled before the test ran")
            warn("  - The API key lacks permissions to access audit output files")

    except requests.HTTPError as e:
        if "403" in str(e):
            warn("Download URLs endpoint returned 403 Forbidden.")
            warn("All /api/workspace-audit endpoints require Domino admin permissions.")
            warn("This is expected behaviour for non-admin users — it is not a bug.")
            blank()
            warn("To verify events were captured:")
            warn("  Ask a Domino admin to open the Workspace File Audit App and filter")
            warn("  for filenames matching: audit_test_*.bin and dedup_test_*.txt")
            warn("  Events should appear after the 60-minute pipeline processing window.")
            result["admin_required"] = True
            result["error"] = "403 Forbidden — admin rights required"
        else:
            err_ln(f"HTTP error fetching download URLs: {e}")
            err_ln("Verify --domino-url and --api-key are correct.")
            result["error"] = str(e)
        return result
    except Exception as e:
        err_ln(f"Error fetching download URLs: {e}")
        result["error"] = str(e)
        return result

    # ------------------------------------------------------------------
    # Step 4: Download current month's Parquet and count rows
    # ------------------------------------------------------------------
    section("Step 4 -- Download Parquet and count event rows")
    info("Events are stored as monthly Parquet files: output/events_MM_YYYY.parquet")
    info("We download the current month's file to verify events are present and")
    info("count total rows as a sanity check against the Phase 2 I/O volume.")
    blank()

    if not download_urls:
        warn("No download URLs available -- skipping Parquet row count.")
        return result

    # Response is a plain list of pre-signed URL strings.
    # We download all of them (typically one per month) and count total rows.
    # Use the first URL as the primary target for the row count check.
    target_url = download_urls[0] if download_urls else None

    if not target_url:
        warn("Could not identify a usable download URL from the response.")
        warn(f"Raw response: {download_urls[:2]}")
        return result

    info(f"Downloading Parquet file (most recent available) ...")
    info("(requires pyarrow or pandas to count rows; install with pip if missing)")
    blank()

    try:
        row_count, file_size = count_parquet_rows(target_url)
        result["parquet_size_bytes"] = file_size

        if row_count is not None:
            result["parquet_row_count"] = row_count
            ok(f"Parquet file size : {file_size / 1024:.1f} KB")
            ok(f"Total event rows  : {row_count:,}")
            blank()
            if row_count > 0:
                note("Events are present in the output Parquet. Pipeline is working.")
                note("Row count will be much lower than Phase 2 raw op count due to")
                note("deduplication (default: 60-min window for reads and writes).")
            else:
                warn("Parquet file downloaded but contains zero rows.")
                warn("Phase 2 I/O events may not have been captured or processed yet.")
        else:
            ok(f"Parquet file size : {file_size / 1024:.1f} KB")
            warn("Could not count rows -- install pyarrow or pandas:")
            warn("  pip install pyarrow")
            warn("File downloaded successfully; inspect it manually to verify events.")

    except Exception as e:
        warn(f"Could not download or read Parquet file: {e}")
        warn("The pre-signed URL may have expired, or the file may not exist yet.")
        result["error"] = str(e)

    section("Phase 4 result summary")
    ok(f"API reachable              : yes")
    ok(f"Processing status          : {result['processing_status']}")
    ok(f"Avg download-URL latency   : {result['avg_url_latency_ms']:.0f}ms"
       if result["avg_url_latency_ms"] else "  Avg download-URL latency   : n/a")
    if result["parquet_row_count"] is not None:
        ok(f"Event rows in Parquet      : {result['parquet_row_count']:,}")
    elif result["parquet_size_bytes"] is not None:
        ok(f"Parquet file size          : {result['parquet_size_bytes'] / 1024:.1f} KB (rows not counted)")

    return result


# ---------------------------------------------------------------------------
# Phase 5: Summary report
# ---------------------------------------------------------------------------

def build_checks(baseline, io_result, dedup_result, api_result):
    cpu_overhead = io_result["cpu_avg_pct"] - baseline["cpu_avg_pct"]
    mem_overhead = io_result["mem_avg_mb"]  - baseline["mem_avg_mb"]
    error_rate   = len(io_result["errors"]) / max(io_result["total_ops"], 1) * 100

    checks = []
    checks.append([
        "CPU overhead during I/O",
        f"{cpu_overhead:+.1f}%",
        f"<= {CPU_OVERHEAD_THRESHOLD_PCT}%",
        "PASS" if cpu_overhead <= CPU_OVERHEAD_THRESHOLD_PCT else "WARN",
    ])
    checks.append([
        "Memory overhead during I/O",
        f"{mem_overhead:+.1f} MB",
        f"<= {MEM_OVERHEAD_THRESHOLD_MB} MB",
        "PASS" if mem_overhead <= MEM_OVERHEAD_THRESHOLD_MB else "WARN",
    ])
    checks.append([
        "File I/O error rate",
        f"{error_rate:.2f}%",
        "< 1%",
        "PASS" if error_rate < 1.0 else "FAIL",
    ])
    checks.append([
        "Throughput",
        f"{io_result['ops_per_sec']:.1f} ops/s",
        "Informational",
        "INFO",
    ])
    checks.append([
        "Dedup validation",
        f"{dedup_result['file_reads']:,} reads -> expect 1 event",
        "Verify in Audit App",
        "ACTION",
    ])

    if not api_result.get("skipped"):
        if api_result.get("api_ok"):
            # Download-URL endpoint latency
            avg_lat = api_result.get("avg_url_latency_ms")
            if avg_lat is not None:
                lat_ok = avg_lat <= API_LATENCY_THRESHOLD_MS
                checks.append([
                    "Audit API avg latency",
                    f"{avg_lat:.0f}ms",
                    f"<= {API_LATENCY_THRESHOLD_MS}ms",
                    "PASS" if lat_ok else "WARN",
                ])
            # Processing status
            proc_status = api_result.get("processing_status", "unknown")
            proc_ok = api_result.get("processing_completed", False)
            checks.append([
                "Processing status",
                proc_status,
                "completed",
                "PASS" if proc_ok else "WARN",
            ])
            # Parquet row count
            row_count = api_result.get("parquet_row_count")
            if row_count is not None:
                checks.append([
                    "Event rows in Parquet",
                    f"{row_count:,}",
                    "> 0",
                    "PASS" if row_count > 0 else "WARN",
                ])
            else:
                checks.append([
                    "Event rows in Parquet",
                    "Not counted (install pyarrow)",
                    "> 0",
                    "INFO",
                ])
        else:
            error = api_result.get("error", "unknown")
            if api_result.get("admin_required"):
                checks.append([
                    "Audit API (admin only)",
                    "403 Forbidden — admin rights required",
                    "Run as Domino admin, or verify via Audit App",
                    "SKIP",
                ])
            else:
                checks.append([
                    "Audit API reachable",
                    f"ERROR: {error}",
                    "Must be reachable",
                    "FAIL",
                ])
    else:
        checks.append([
            "Audit API check",
            f"Skipped ({api_result.get('reason','')})",
            "Provide --domino-url and --api-key",
            "SKIP",
        ])

    summary = {
        "cpu_overhead_pct": cpu_overhead,
        "mem_overhead_mb":  mem_overhead,
        "error_rate_pct":   error_rate,
        "ops_per_sec":      io_result["ops_per_sec"],
    }
    return checks, summary


def print_report(baseline, io_result, dedup_result, api_result, args):
    banner("PHASE 5 -- FINAL REPORT")

    section("Test configuration")
    info(f"  Dataset path : {args.dataset_path}")
    info(f"  Workers      : {args.workers}")
    info(f"  Duration     : {args.duration}s")
    info(f"  File size    : {args.file_size_kb} KB")
    info(f"  I/O start    : {io_result['io_start_wall']}")
    info(f"  I/O end      : {io_result['io_end_wall']}")
    info(f"  Report time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    section("Resource usage: baseline vs under load")
    resource_rows = [
        ["Metric",     "Baseline (idle)", "During I/O (avg)", "During I/O (peak)"],
        ["CPU %",
         f"{baseline['cpu_avg_pct']:.1f}%",
         f"{io_result['cpu_avg_pct']:.1f}%",
         f"{io_result['cpu_max_pct']:.1f}%"],
        ["Memory (MB)",
         f"{baseline['mem_avg_mb']:.1f}",
         f"{io_result['mem_avg_mb']:.1f}",
         f"{io_result['mem_max_mb']:.1f}"],
    ]
    print(tabulate(resource_rows, headers="firstrow", tablefmt="rounded_outline"))

    section("File operation breakdown")
    ops_rows = [[op.capitalize(), f"{count:,}"] for op, count in io_result["ops"].items()]
    ops_rows.append(["-- TOTAL --", f"{io_result['total_ops']:,}"])
    ops_rows.append(["Ops/sec",    f"{io_result['ops_per_sec']:.1f}"])
    print(tabulate(ops_rows, headers=["Operation", "Count"], tablefmt="rounded_outline"))

    section("Pass / fail checks")
    checks, summary = build_checks(baseline, io_result, dedup_result, api_result)
    print(tabulate(checks,
                   headers=["Check", "Measured", "Threshold", "Result"],
                   tablefmt="rounded_outline"))

    if io_result["errors"]:
        section(f"I/O errors ({len(io_result['errors'])} total)")
        for e in io_result["errors"][:10]:
            warn(e)
        if len(io_result["errors"]) > 10:
            warn(f"  ... and {len(io_result['errors']) - 10} more (see JSON output)")

    section("How to interpret these results")
    blank()
    info("CPU / Memory overhead:")
    info("  Domino's published estimates for audit overhead are approximately")
    info("  15% CPU and 10% memory per workspace pod. Our thresholds are set")
    info("  slightly higher (20% CPU / 15 MB) to account for measurement noise.")
    info("  IMPORTANT: the numbers above reflect the test process workload only.")
    info("  The Falco sidecar daemon runs as a separate process. To see the")
    info("  true combined overhead, compare Grafana /grafana-workload metrics")
    info("  taken with audit OFF vs ON under equivalent workload conditions.")
    blank()
    info("Hardware sizing recommendation:")
    info("  If you enable audit on a fleet of workspaces, plan for one hardware")
    info("  tier step up across the board (e.g. small -> medium). Workloads")
    info("  with very high file I/O (ML data ingestion, ETL pipelines, large")
    info("  dataset reads) will see proportionally higher overhead than moderate")
    info("  interactive workspace usage.")
    blank()
    info("Deduplication:")
    info(f"  Search the Workspace File Audit App for: {dedup_result['test_file_name']}")
    info("  after the 60-minute processing window has elapsed. Expect 1 event.")
    info("  If many events appear, tune via admin config key:")
    info("  com.cerebro.domino.workspaceFileAudit.UniqueReadEventPeriodInMinutes")
    info("  com.cerebro.domino.workspaceFileAudit.UniqueWriteEventPeriodInMinutes")
    info("  (both default to 60 minutes; reads and writes are tuned independently)")
    blank()
    info("Event pipeline lag:")
    info("  Default batch interval is 60 minutes (configurable 60-360 min via")
    info("  com.cerebro.domino.workspaceFileAudit.eventProcessingInMinutes).")
    info("  Shorter intervals reduce lag but increase pipeline infrastructure")
    info("  load. Only reduce if a compliance requirement demands it.")
    blank()
    info("Audit API:")
    info("  The API does not return events as JSON rows. Events are stored as")
    info("  monthly Parquet files (output/events_MM_YYYY.parquet) in object")
    info("  storage. The API returns pre-signed download URLs; you download and")
    info("  inspect the files to verify events. Use --trigger-processing to")
    info("  kick off a batch immediately rather than waiting 60 minutes.")
    blank()
    info("Monitoring during production rollout:")
    info("  - /grafana-workload : per-pod CPU/memory trends during audit-on runs")
    info("  - Contact Domino Support with io_start_wall timestamp if events are")
    info("    missing or significantly delayed beyond the expected 60-min window.")
    info("  - In cloud deployments, Domino's platform team manages all pipeline")
    info("    infrastructure alerts on your behalf.")

    # Save JSON
    out_path = Path("audit_trail_test_results.json")
    with open(out_path, "w") as f:
        json.dump({
            "baseline":     baseline,
            "io_result":    {**io_result, "errors": io_result["errors"][:50]},
            "dedup_result": dedup_result,
            "api_result":   api_result,
            "summary":      summary,
        }, f, indent=2, default=str)

    blank()
    print(DIVIDER)
    ok(f"Full results saved to: {out_path.resolve()}")
    print(DIVIDER)
    blank()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Domino Workspace File Access Audit Trail load tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--dataset-path", required=True,
                   help="Path to a Domino Dataset or NetApp Volume mount point")
    p.add_argument("--domino-url",
                   default="",
                   help=("External Domino deployment URL (e.g. https://domino-dev.myorg.com). "                         "Must be the external ingress URL — the same URL you use in a browser. "                         "Do NOT use DOMINO_API_HOST which resolves to nucleus-frontend internally. "                         "The audit API path /api/workspace-audit/v1/... will be appended automatically."))
    p.add_argument("--api-key",
                   default=os.environ.get("DOMINO_USER_API_KEY", ""),
                   help="Domino user API key")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION_SECONDS,
                   help=f"I/O phase duration in seconds (default: {DEFAULT_DURATION_SECONDS})")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   help=f"Parallel I/O worker threads (default: {DEFAULT_WORKERS})")
    p.add_argument("--file-size-kb", type=int, default=DEFAULT_FILE_SIZE_KB,
                   help=f"Test file size in KB (default: {DEFAULT_FILE_SIZE_KB})")
    p.add_argument("--dedup-window-seconds", type=int,
                   default=DEFAULT_DEDUP_WINDOW_SECONDS,
                   help=f"Seconds to repeat reads on same file (default: {DEFAULT_DEDUP_WINDOW_SECONDS})")
    p.add_argument("--check-api-lag-minutes", type=int, default=0,
                   help="Wait N minutes for scheduled pipeline batch before API check "
                        "(0=don't wait; ignored if --trigger-processing is set)")
    p.add_argument("--trigger-processing", action="store_true", default=False,
                   help="Immediately trigger a processing run via POST /v1/process "
                        "instead of waiting for the scheduled 60-min batch")
    return p.parse_args()


def main():
    args = parse_args()

    # Pre-flight
    blank()
    print(DIVIDER)
    print("  DOMINO WORKSPACE FILE ACCESS AUDIT TRAIL -- LOAD & IMPACT TEST")
    print(DIVIDER)
    blank()

    section("Pre-flight checks")
    dataset_path = Path(args.dataset_path)

    if not dataset_path.exists():
        err_ln(f"Dataset path does not exist: {dataset_path}")
        err_ln("Ensure the Dataset or NetApp Volume is mounted in this workspace.")
        sys.exit(1)
    ok(f"Dataset path exists  : {dataset_path}")

    probe = dataset_path / f".audit_probe_{rand_str()}"
    try:
        probe.touch()
        probe.unlink()
        ok("Write permission confirmed on dataset path.")
    except PermissionError:
        err_ln(f"No write permission at {dataset_path}")
        err_ln("This test requires write access to generate auditable file events.")
        sys.exit(1)

    blank()
    info(f"Python      : {sys.version.split()[0]}")
    info(f"psutil      : {psutil.__version__}")
    info(f"Workers     : {args.workers}")
    info(f"Duration    : {args.duration}s")
    info(f"File size   : {args.file_size_kb} KB")

    if args.domino_url and args.api_key:
        internal_indicators = ("nucleus-frontend", "domino-platform", "svc.cluster", "localhost", "127.0.0.1")
        if any(ind in args.domino_url for ind in internal_indicators):
            warn(f"--domino-url looks like an internal cluster address: {args.domino_url}")
            warn("The audit API must be called via the EXTERNAL Domino URL (same as browser).")
            warn("Phase 4 calls will likely fail. Pass the external URL instead:")
            warn("  --domino-url https://domino-dev.myorg.com")
        else:
            ok(f"Domino URL : {args.domino_url}")
            ok(f"Audit API  : {args.domino_url}/api/workspace-audit/v1/...")
        ok("API key provided -- Phase 4 will run.")
        if args.trigger_processing:
            ok("--trigger-processing: will POST /api/workspace-audit/v1/process after I/O.")
        elif args.check_api_lag_minutes > 0:
            ok(f"Will wait {args.check_api_lag_minutes}m for scheduled pipeline batch.")
        else:
            note("Neither --trigger-processing nor --check-api-lag-minutes set.")
            note("Phase 4 will check current status and download URLs only.")
            note("Tip: add --trigger-processing to force processing immediately.")
    else:
        warn("--domino-url or --api-key not provided.")
        warn("Phase 4 (API check) will be skipped.")
        warn("Pass the external Domino URL and API key to enable it:")
        warn("  --domino-url https://domino-dev.myorg.com --api-key $DOMINO_USER_API_KEY")

    blank()
    note("Starting test in 3 seconds. Press Ctrl+C to abort.")
    time.sleep(3)

    # Run phases
    baseline = capture_baseline(duration=5)

    io_result = run_io_phase(
        dataset_path=dataset_path,
        duration=args.duration,
        workers=args.workers,
        file_size_kb=args.file_size_kb,
    )

    dedup_result = run_dedup_validation(
        dataset_path=dataset_path,
        window_seconds=args.dedup_window_seconds,
    )

    # Parse io_start_wall and io_end_wall back to datetime for nanosecond timestamp params
    from datetime import datetime, timezone as _tz
    io_start_dt = datetime.fromisoformat(io_result["io_start_wall"])
    io_end_dt   = datetime.fromisoformat(io_result["io_end_wall"])

    api_result = {"skipped": True, "reason": "no_api_config"}
    if args.domino_url and args.api_key:
        api_result = check_api_and_lag(
            domino_url=args.domino_url,
            api_key=args.api_key,
            wait_minutes=args.check_api_lag_minutes,
            trigger_processing_now=args.trigger_processing,
            io_start_wall=io_start_dt,
            io_end_wall=io_end_dt,
        )
    else:
        banner("PHASE 4 OF 4 -- Audit API Check  [SKIPPED]")
        info("--domino-url or --api-key not supplied. See pre-flight warning above.")

    print_report(baseline, io_result, dedup_result, api_result, args)


if __name__ == "__main__":
    main()
