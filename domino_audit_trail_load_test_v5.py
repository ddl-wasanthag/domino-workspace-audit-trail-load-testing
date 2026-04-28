#!/usr/bin/env python3
"""
Domino Workspace File Access Audit Trail - Loadgen Script v5
=============================================================

Stress edition — built directly on v3's proven lifecycle pattern.
Nothing is bypassed: all ops are real filesystem calls on the mounted
Domino Dataset so Falco picks them up exactly as in production.

What changed vs v3
------------------
1. --total-events N (default 1,000,000)
   Convenience flag: auto-calculates --lifecycles so the run produces
   approximately N Falco events.  Pass --lifecycles directly if you prefer
   the old interface.

2. --duration-min M (default 60)
   Spread the events evenly over M minutes instead of bursting.  Each
   worker self-paces: after lifecycle i it checks how far ahead/behind it
   is versus the ideal linear schedule and sleeps the gap.  Self-correcting
   — if a lifecycle ran slow the next sleep is shorter (or zero).
   Set --duration-min 0 to disable pacing and run at full speed.

3. --workers defaults to max(4, cpu_count)
   Always at least 4 threads even on a single-vCPU node — file I/O is
   GIL-releasing so overlapping waits still helps.  On a large tier with
   16+ cores you get full parallelism automatically.

4. --reads-per-lifecycle N (default 3)
   Each lifecycle does N consecutive reads before the optional rename +
   delete.  v3 default was 1.  More reads = more Falco open-file events
   without extra writes or creates.

5. Progress ticker shows estimated Falco events/sec in addition to
   lifecycle rate.

6. Summary reports raw Falco event estimate, events/sec, and pacing info
   so results are directly comparable across runs.

Everything else — op pattern, dedup phase, upload to safe project, log
capture, JSON summary format — is unchanged from v3.

Lifecycle structure (per worker, per lifecycle)
-----------------------------------------------
    1. Create  — write_bytes(payload)              → 1 Falco event
    2. Write   — write_bytes(payload reversed)     → 1 Falco event
    3. Read    — read_bytes() × reads_per_lifecycle → N Falco events
    4. Rename  — rename() (20% of lifecycles)      → 1 Falco event
    5. Delete  — unlink()                          → 1 Falco event

Average Falco events per lifecycle (default reads_per_lifecycle=3):
    = 1 + 1 + 3 + 0.20 + 1  =  6.20 events

    Each read targets a DISTINCT file path (sliding window pool) so Falco's
    60-min read-dedup does not collapse them.  Every read counts.

Usage (run inside a large-tier Domino workspace)
------------------------------------------------

    # Default: 1 M events paced over 60 min, all CPUs
    python domino_audit_trail_load_test_v5.py \\
        --dataset-path /domino/datasets/local/<dataset>

    # Explicit: 1 M events over 2 hours, 32 workers
    python domino_audit_trail_load_test_v5.py \\
        --dataset-path /domino/datasets/local/<dataset> \\
        --total-events 1000000 \\
        --duration-min 120 \\
        --workers 32

    # Full-speed burst (no pacing)
    python domino_audit_trail_load_test_v5.py \\
        --dataset-path /domino/datasets/local/<dataset> \\
        --total-events 1000000 \\
        --duration-min 0

    # Save results to a safe project before workspace teardown
    python domino_audit_trail_load_test_v5.py \\
        --dataset-path /domino/datasets/local/<dataset> \\
        --total-events 1000000 \\
        --duration-min 60 \\
        --results-project admin/audit-loadtest-results \\
        --results-dir falco_stress_logs \\
        --domino-url https://domino-dev.myorg.com \\
        --api-key $DOMINO_USER_API_KEY

Fleet-level event budget:
    Total Falco events ≈ num_workspaces × (lifecycles × events_per_lc
                          + dedup_reads + 2)
    Example: 10 large workspaces × 1,000,000 ≈ 10 M events fleet-wide
"""

import argparse
import io
import json
import math
import os
import random
import string
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None  # Only needed when --results-project is used

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_TOTAL_EVENTS        = 1_000_000
DEFAULT_DURATION_MIN        = 60          # spread events over 1 hour
DEFAULT_WORKERS             = max(4, os.cpu_count() or 4)  # at least 4
DEFAULT_FILE_SIZE_KB        = 64
DEFAULT_READS_PER_LIFECYCLE = 3           # v3 was 1
DEFAULT_DEDUP_READS         = 0
DEFAULT_RESULTS_DIR         = "falco_logs"

RENAME_PROBABILITY          = 0.20        # 20 % of lifecycles include a rename


def events_per_lifecycle(reads_per_lc: int) -> float:
    """Average Falco events emitted per lifecycle."""
    return 1.0 + 1.0 + reads_per_lc + RENAME_PROBABILITY + 1.0


# ---------------------------------------------------------------------------
# Log capture (unchanged from v3)
# ---------------------------------------------------------------------------
_LOG_BUFFER = io.StringIO()


def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[audit-loadgen {ts}] {msg}"
    print(line, flush=True)
    _LOG_BUFFER.write(line + "\n")


# ---------------------------------------------------------------------------
# Worker (v3-identical except reads_per_lifecycle + optional pacing)
# ---------------------------------------------------------------------------
class LifecycleWorker:
    """
    Executes a fixed number of complete file lifecycles against work_dir.

    Each lifecycle:
        1. Create  — write a new binary file           (1 Falco event)
        2. Write   — overwrite with fresh content       (1 Falco event)
        3. Read    — read_bytes() × reads_per_lifecycle (N Falco events)
        4. Rename  — rename it (RENAME_PROBABILITY %)  (1 Falco event)
        5. Delete  — unlink the file                   (1 Falco event)

    If duration_sec > 0 the worker self-paces: after each lifecycle it
    sleeps however long is needed to stay on the ideal linear schedule
    (elapsed / total_lifecycles × duration_sec).  Self-correcting — no
    sleep if running behind.

    Read dedup fix
    --------------
    Falco's audit pipeline deduplicates repeated reads of the same file
    path within its UniqueReadEventPeriodInMinutes window (default 60 min).
    Reading the same file N times produces only 1 Falco event.

    To make every read count as a distinct Falco event, each lifecycle
    reads from a sliding window pool of the last reads_per_lifecycle files
    created by previous lifecycles — each a unique path.  The pool is
    bounded: the oldest file is deleted once the pool is full (1 delete per
    lifecycle in steady state, matching v3's rate).

    Steady-state Falco events per lifecycle:
        Create  1   +  Write  1  +  Reads  reads_per_lifecycle
        +  Rename  0.20  +  Delete  1
        =  3.20 + reads_per_lifecycle
    """

    def __init__(self, worker_id: int, work_dir: Path,
                 lifecycles: int, file_size_kb: int,
                 reads_per_lifecycle: int,
                 duration_sec: float = 0.0):
        self.worker_id           = worker_id
        self.work_dir            = work_dir
        self.lifecycles          = lifecycles
        self.file_size_kb        = file_size_kb
        self.reads_per_lifecycle = reads_per_lifecycle
        self.duration_sec        = duration_sec   # 0 = no pacing
        self.counts = {
            "create": 0, "write": 0, "read": 0,
            "rename": 0, "delete": 0,
        }
        self.errors = []

    def run(self):
        payload  = bytes(random.getrandbits(8)
                         for _ in range(self.file_size_kb * 1024))
        t_start  = time.monotonic()
        # Sliding window pool of files on disk — bounded to reads_per_lifecycle.
        # Reads are sampled from this pool so every read path is distinct.
        pool: list[Path] = []

        for i in range(self.lifecycles):
            fname = self.work_dir / f"lc_{self.worker_id}_{rand_str()}.bin"
            try:
                # 1. Create — add new file to pool
                fname.write_bytes(payload)
                self.counts["create"] += 1
                pool.append(fname)

                # 2. Write (overwrite the new file)
                fname.write_bytes(payload[::-1])
                self.counts["write"] += 1

                # 3. Read — sample reads_per_lifecycle DISTINCT files from pool.
                #    Each path is unique → each read generates a Falco event
                #    (no dedup collapse).  During warm-up (pool smaller than
                #    reads_per_lifecycle) we read however many files exist.
                candidates   = [f for f in pool if f.exists()]
                n_reads      = min(self.reads_per_lifecycle, len(candidates))
                read_targets = random.sample(candidates, n_reads)
                for f in read_targets:
                    try:
                        _ = f.read_bytes()
                        self.counts["read"] += 1
                    except FileNotFoundError:
                        if f in pool:
                            pool.remove(f)

                # 4. Rename (probabilistic) — rename the file just created
                if random.random() < RENAME_PROBABILITY and fname in pool:
                    renamed = fname.with_name(fname.stem + "_r.bin")
                    try:
                        fname.rename(renamed)
                        pool[pool.index(fname)] = renamed
                        fname = renamed
                        self.counts["rename"] += 1
                    except Exception as e:
                        self.errors.append(f"rename: {e}")

                # 5. Delete oldest file once pool exceeds reads_per_lifecycle.
                #    In steady state: 1 delete per lifecycle, pool size stable.
                if len(pool) > self.reads_per_lifecycle:
                    oldest = pool.pop(0)
                    try:
                        if oldest.exists():
                            oldest.unlink()
                        self.counts["delete"] += 1
                    except Exception as e:
                        self.errors.append(f"delete: {e}")

            except Exception as e:
                self.errors.append(str(e))
                try:
                    if fname in pool:
                        pool.remove(fname)
                    if fname.exists():
                        fname.unlink()
                except Exception:
                    pass

            # ── Pacing ──────────────────────────────────────────────────────
            # After lifecycle i the ideal elapsed time is:
            #   (i+1) / lifecycles × duration_sec
            # Sleep the positive gap; skip if we're already running behind.
            if self.duration_sec > 0 and self.lifecycles > 1:
                ideal_elapsed = (i + 1) / self.lifecycles * self.duration_sec
                actual_elapsed = time.monotonic() - t_start
                gap = ideal_elapsed - actual_elapsed
                if gap > 0:
                    time.sleep(gap)

        # Cleanup any files remaining in the pool after all lifecycles finish
        for f in pool:
            try:
                if f.exists():
                    f.unlink()
                    self.counts["delete"] += 1
            except Exception:
                pass

    @property
    def total_ops(self):
        return sum(self.counts.values())


# ---------------------------------------------------------------------------
# Phase 1: Lifecycle I/O
# ---------------------------------------------------------------------------
def run_lifecycle_phase(dataset_path: Path, lifecycles: int,
                        workers: int, file_size_kb: int,
                        reads_per_lifecycle: int,
                        duration_sec: float):

    epl              = events_per_lifecycle(reads_per_lifecycle)
    estimated_events = int(lifecycles * epl)
    pacing_label     = (f"{duration_sec / 60:.1f} min"
                        if duration_sec > 0 else "none (full speed)")

    log("Phase 1 - File lifecycle I/O (stress mode)")
    log(f"  Dataset path    : {dataset_path}")
    log(f"  Lifecycles      : {lifecycles:,}")
    log(f"  Workers         : {workers} (cpu_count={os.cpu_count()})")
    log(f"  Per worker      : {math.ceil(lifecycles / workers):,} lifecycles")
    log(f"  File size       : {file_size_kb} KB")
    log(f"  Reads/lifecycle : {reads_per_lifecycle}")
    log(f"  Rename prob     : {int(RENAME_PROBABILITY * 100)}%")
    log(f"  Events/lifecycle: ~{epl:.2f}")
    log(f"  Est. Falco evts : ~{estimated_events:,}")
    log(f"  Pacing          : {pacing_label}")
    if duration_sec > 0:
        target_eps = estimated_events / duration_sec
        log(f"  Target rate     : ~{target_eps:.1f} events/sec sustained")

    work_dir = dataset_path / f"audit_loadgen_{rand_str()}"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Distribute lifecycles evenly
    base       = lifecycles // workers
    remainder  = lifecycles %  workers
    per_worker = [base + (1 if i < remainder else 0) for i in range(workers)]

    worker_objs = [
        LifecycleWorker(i, work_dir, per_worker[i], file_size_kb,
                        reads_per_lifecycle, duration_sec)
        for i in range(workers)
    ]
    threads = [threading.Thread(target=w.run, daemon=True) for w in worker_objs]

    t_start    = time.monotonic()
    start_wall = datetime.now(timezone.utc)

    for t in threads:
        t.start()

    # Progress ticker — every 30 s (paced) or 10 s (full speed)
    tick_interval  = 30 if duration_sec > 0 else 10
    completed_prev = 0
    ops_prev       = 0

    while any(t.is_alive() for t in threads):
        time.sleep(tick_interval)
        completed = sum(w.counts["delete"] for w in worker_objs)
        total_ops = sum(w.total_ops        for w in worker_objs)
        errors    = sum(len(w.errors)      for w in worker_objs)
        elapsed   = time.monotonic() - t_start

        lc_rate          = (completed - completed_prev) / tick_interval
        ops_rate         = (total_ops - ops_prev)       / tick_interval
        falco_est_so_far = int(completed * epl)
        event_rate       = falco_est_so_far / max(elapsed, 1)

        completed_prev = completed
        ops_prev       = total_ops
        pct = completed / lifecycles * 100 if lifecycles else 0

        eta_str = ""
        if lc_rate > 0 and completed < lifecycles:
            eta_s   = (lifecycles - completed) / lc_rate
            eta_str = f"  eta: {int(eta_s//60)}m{int(eta_s%60)}s"

        log(f"  Progress: {completed:,}/{lifecycles:,} ({pct:.0f}%)  "
            f"lc/s: {lc_rate:.1f}  ops/s: {ops_rate:.0f}  "
            f"~events/s: {event_rate:.1f}  "
            f"~events: {falco_est_so_far:,}  "
            f"elapsed: {elapsed:.0f}s  errors: {errors}{eta_str}")

    for t in threads:
        t.join()

    elapsed  = time.monotonic() - t_start
    end_wall = datetime.now(timezone.utc)

    # Cleanup work directory
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

    # Aggregate
    op_totals  = {k: sum(w.counts[k] for w in worker_objs)
                  for k in worker_objs[0].counts}
    all_errors = [e for w in worker_objs for e in w.errors]
    total_ops  = sum(op_totals.values())

    lc_completed     = op_totals["delete"]
    falco_events_est = int(lc_completed * epl)
    events_per_sec   = falco_events_est / max(elapsed, 1)

    log(f"  Completed in {elapsed:.1f}s  "
        f"({total_ops:,} total ops, {total_ops / max(elapsed, 1):.1f} ops/s,  "
        f"~{falco_events_est:,} Falco events, ~{events_per_sec:.1f} events/s)")

    if all_errors:
        log(f"  WARNING: {len(all_errors)} error(s) during lifecycles")
        for e in all_errors[:5]:
            log(f"    {e}")

    return {
        "lifecycles_requested" : lifecycles,
        "lifecycles_completed" : lc_completed,
        "ops"                  : op_totals,
        "total_ops"            : total_ops,
        "ops_per_sec"          : total_ops / max(elapsed, 1),
        "falco_events_est"     : falco_events_est,
        "falco_events_per_sec" : events_per_sec,
        "duration_s"           : elapsed,
        "pacing_target_s"      : duration_sec,
        "start_wall"           : start_wall.isoformat(),
        "end_wall"             : end_wall.isoformat(),
        "errors"               : all_errors[:50],
        "error_count"          : len(all_errors),
    }


# ---------------------------------------------------------------------------
# Phase 2: Dedup validation (unchanged from v3)
# ---------------------------------------------------------------------------
def run_dedup_phase(dataset_path: Path, dedup_reads: int, file_size_kb: int):
    log("Phase 2 - Dedup validation")
    log(f"  Single file, {dedup_reads:,} reads")
    log(f"  Expected audit events after pipeline: 1 create + 1 read + 1 delete")
    log(f"  (pipeline should collapse {dedup_reads:,} reads into 1 deduplicated event)")

    test_file = dataset_path / f"dedup_{rand_str()}.txt"
    test_file.write_bytes(bytes(file_size_kb * 1024))

    t_start    = time.monotonic()
    read_count = 0
    errors     = []
    for _ in range(dedup_reads):
        try:
            _ = test_file.read_bytes()
            read_count += 1
        except Exception as e:
            errors.append(str(e))
    elapsed = time.monotonic() - t_start

    try:
        test_file.unlink()
    except Exception:
        pass

    log(f"  Done: {read_count:,} reads in {elapsed:.1f}s "
        f"({read_count / max(elapsed, 1):.0f} reads/sec)")
    log(f"  File name for Audit App search: {test_file.name}")

    return {
        "test_file_name"  : test_file.name,
        "reads_performed" : read_count,
        "expected_events" : 1,
        "duration_s"      : elapsed,
        "errors"          : errors,
    }


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(lifecycle_result, dedup_result, args):
    log("=" * 60)
    log("SUMMARY")
    log("=" * 60)

    lc  = lifecycle_result
    ops = lc["ops"]

    log(f"  Lifecycles completed : {lc['lifecycles_completed']:,} "
        f"/ {lc['lifecycles_requested']:,}")
    log(f"  Reads per lifecycle  : {args.reads_per_lifecycle}")
    log(f"  Workers              : {args.workers}")
    log(f"  Total ops            : {lc['total_ops']:,}")
    log(f"  Throughput           : {lc['ops_per_sec']:.1f} ops/sec")
    log(f"  Duration             : {lc['duration_s']:.1f}s")
    log(f"  Pacing target        : "
        f"{'%d min' % args.duration_min if args.duration_min > 0 else 'none (full speed)'}")
    log(f"  I/O errors           : {lc['error_count']}")
    log(f"  Start (UTC)          : {lc['start_wall']}")
    log(f"  End   (UTC)          : {lc['end_wall']}")
    log("")
    log("  Op breakdown:")
    for op, count in ops.items():
        log(f"    {op.capitalize():<8} : {count:,}")

    if dedup_result:
        log("")
        log(f"  Dedup reads          : {dedup_result['reads_performed']:,}")
        log(f"  Dedup file           : {dedup_result['test_file_name']}")
        log(f"  Expected audit events: 1 create + 1 read + 1 delete")

    falco_events = lc["falco_events_est"]
    if dedup_result:
        falco_events += dedup_result["reads_performed"] + 2

    log("")
    log(f"  Falco events this workspace : ~{falco_events:,}")
    log(f"  Avg Falco events/sec        : ~{lc['falco_events_per_sec']:.1f}")
    log(f"  Target was                  : {args.total_events:,} events")
    log(f"  (multiply by fleet size for total pipeline pressure)")
    log("=" * 60)

    summary = {
        "workspace_id"        : os.environ.get("DOMINO_RUN_ID", "unknown"),
        "dataset_path"        : str(args.dataset_path),
        "lifecycles"          : lc["lifecycles_completed"],
        "reads_per_lifecycle" : args.reads_per_lifecycle,
        "workers"             : args.workers,
        "duration_min_target" : args.duration_min,
        "total_ops"           : lc["total_ops"],
        "ops_per_sec"         : round(lc["ops_per_sec"], 1),
        "falco_events_est"    : falco_events,
        "falco_events_per_sec": round(lc["falco_events_per_sec"], 1),
        "total_events_target" : args.total_events,
        "duration_s"          : round(lc["duration_s"], 1),
        "error_count"         : lc["error_count"],
        "ops"                 : lc["ops"],
        "start_wall"          : lc["start_wall"],
        "end_wall"            : lc["end_wall"],
        "dedup"               : dedup_result,
        "profile_version"     : "v5-stress",
    }
    log("JSON_SUMMARY: " + json.dumps(summary))
    return summary


# ---------------------------------------------------------------------------
# Upload to safe project (unchanged from v3)
# ---------------------------------------------------------------------------
def upload_to_project(payload_bytes: bytes, domino_url: str, api_key: str,
                      project: str, remote_path: str) -> dict:
    """Upload raw bytes to a Domino project via the v1 Files REST API."""
    if requests is None:
        raise RuntimeError(
            "The 'requests' library is required for --results-project. "
            "Install it: pip install requests"
        )

    try:
        owner, name = project.split("/", 1)
    except ValueError:
        raise ValueError(
            f"--results-project must be owner/projectName, got: {project!r}"
        )

    url = (f"{domino_url.rstrip('/')}/v1/projects/{owner}/{name}"
           f"/files/{remote_path.lstrip('/')}")
    headers = {
        "X-Domino-Api-Key" : api_key,
        "Content-Type"     : "application/octet-stream",
    }
    resp   = requests.put(url, headers=headers, data=payload_bytes, timeout=120)
    result = {
        "status_code" : resp.status_code,
        "url"         : url,
        "ok"          : resp.ok,
        "response"    : resp.text[:500],
    }
    if resp.status_code == 404:
        result["hint"] = (
            f"HTTP 404 on PUT /v1/projects/{owner}/{name}/files/... — "
            f"verify (a) project '{owner}/{name}' exists and "
            f"(b) the API key owner has write access."
        )
    return result


def write_results_to_safe_project(summary: dict, args) -> dict:
    """Upload JSON summary + captured log to the safe project.
    Never raises — upload errors become warnings."""
    result = {"enabled": False}
    if not args.results_project:
        return result

    result["enabled"] = True

    domino_url = args.domino_url or os.environ.get("DOMINO_API_HOST")
    api_key    = args.api_key    or os.environ.get("DOMINO_USER_API_KEY")

    if not domino_url:
        log("WARNING: --results-project set but no --domino-url or "
            "$DOMINO_API_HOST is available. Skipping upload.")
        result["skipped"] = "no_url"
        return result
    if not api_key:
        log("WARNING: --results-project set but no --api-key or "
            "$DOMINO_USER_API_KEY is available. Skipping upload.")
        result["skipped"] = "no_api_key"
        return result

    if "nucleus-frontend" in domino_url:
        log("WARNING: the provided Domino URL looks like the internal "
            "nucleus-frontend address, which cannot route Files API traffic. "
            "Pass --domino-url with the external Domino hostname.")

    run_id = os.environ.get("DOMINO_RUN_ID", "local") or "local"
    ts     = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base   = f"audit_loadgen_{run_id}_{ts}"

    results_dir = args.results_dir.strip("/") or DEFAULT_RESULTS_DIR
    json_path   = f"{results_dir}/{base}.json"
    log_path    = f"{results_dir}/{base}.log"

    result.update({
        "project"     : args.results_project,
        "domino_url"  : domino_url,
        "remote_json" : json_path,
        "remote_log"  : log_path,
    })

    log(f"Uploading results to Domino project "
        f"'{args.results_project}' under '{results_dir}/' ...")

    try:
        summary_bytes = json.dumps(summary, indent=2).encode("utf-8")
        r_json = upload_to_project(summary_bytes, domino_url, api_key,
                                   args.results_project, json_path)
        result["json_upload"] = r_json
        log(f"  JSON upload: HTTP {r_json['status_code']} -> {json_path}")
        if not r_json["ok"]:
            if r_json.get("hint"):
                log(f"    hint: {r_json['hint']}")
            log(f"    body: {r_json['response']}")
    except Exception as e:
        log(f"  JSON upload FAILED: {e}")
        result["json_error"] = str(e)

    try:
        log_bytes = _LOG_BUFFER.getvalue().encode("utf-8")
        r_log = upload_to_project(log_bytes, domino_url, api_key,
                                  args.results_project, log_path)
        result["log_upload"] = r_log
        log(f"  Log upload:  HTTP {r_log['status_code']} -> {log_path}")
        if not r_log["ok"]:
            if r_log.get("hint"):
                log(f"    hint: {r_log['hint']}")
            log(f"    body: {r_log['response']}")
    except Exception as e:
        log(f"  Log upload FAILED: {e}")
        result["log_error"] = str(e)

    print("UPLOAD_RESULT: " + json.dumps(result), flush=True)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Domino Workspace File Access Audit Trail - Loadgen v5 "
                    "(stress edition, paced)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "--dataset-path", required=True,
        help="Path to a mounted Domino Dataset or NetApp Volume"
    )
    p.add_argument(
        "--total-events", type=int, default=DEFAULT_TOTAL_EVENTS,
        help=f"Target total Falco events to generate "
             f"(default: {DEFAULT_TOTAL_EVENTS:,}). Auto-calculates "
             f"--lifecycles. Ignored if --lifecycles is passed explicitly."
    )
    p.add_argument(
        "--lifecycles", type=int, default=None,
        help="Number of complete file lifecycles (overrides --total-events)."
    )
    p.add_argument(
        "--duration-min", type=int, default=DEFAULT_DURATION_MIN,
        help=f"Spread events evenly over this many minutes "
             f"(default: {DEFAULT_DURATION_MIN}). "
             f"Each worker self-paces using a linear schedule. "
             f"Set 0 to disable pacing and run at full speed."
    )
    p.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Parallel worker threads (default: max(4, cpu_count) = "
             f"{DEFAULT_WORKERS}). Lifecycles distributed evenly. "
             f"I/O threads benefit from >1 even on a single vCPU."
    )
    p.add_argument(
        "--reads-per-lifecycle", type=int, default=DEFAULT_READS_PER_LIFECYCLE,
        help=f"Read calls per lifecycle (default: {DEFAULT_READS_PER_LIFECYCLE}). "
             f"Increasing this raises Falco event volume without extra writes."
    )
    p.add_argument(
        "--file-size-kb", type=int, default=DEFAULT_FILE_SIZE_KB,
        help=f"File size in KB (default: {DEFAULT_FILE_SIZE_KB})"
    )
    p.add_argument(
        "--dedup-reads", type=int, default=DEFAULT_DEDUP_READS,
        help=f"Repeated reads on a single file for dedup validation "
             f"(default: {DEFAULT_DEDUP_READS} = disabled)."
    )

    # --- Safe-project upload flags (same as v3) ------------------------------
    p.add_argument(
        "--results-project", default=None,
        help="Safe Domino project for uploading run artifacts "
             "(owner/projectName). If unset, no upload is performed."
    )
    p.add_argument(
        "--results-dir", default=DEFAULT_RESULTS_DIR,
        help=f"Subdirectory in the safe project for artifacts "
             f"(default: {DEFAULT_RESULTS_DIR})."
    )
    p.add_argument(
        "--domino-url", default=None,
        help="External Domino URL. Falls back to $DOMINO_API_HOST."
    )
    p.add_argument(
        "--api-key", default=None,
        help="Domino API key. Falls back to $DOMINO_USER_API_KEY."
    )

    return p.parse_args()


def main():
    args = parse_args()
    dataset_path = Path(args.dataset_path)

    # Resolve lifecycles
    epl = events_per_lifecycle(args.reads_per_lifecycle)
    if args.lifecycles is not None:
        lifecycles        = args.lifecycles
        args.total_events = int(lifecycles * epl)
    else:
        lifecycles = max(1, int(math.ceil(args.total_events / epl)))

    duration_sec = args.duration_min * 60

    # Pre-flight
    log("Domino Workspace File Access Audit Trail - Loadgen v5 (stress)")
    log(f"  Python          : {sys.version.split()[0]}")
    log(f"  Dataset path    : {dataset_path}")
    log(f"  Total events    : ~{args.total_events:,} (target)")
    log(f"  Lifecycles      : {lifecycles:,}")
    log(f"  Duration        : "
        f"{'%d min' % args.duration_min if args.duration_min > 0 else 'unlimited (full speed)'}")
    log(f"  Workers         : {args.workers}")
    log(f"  Reads/lifecycle : {args.reads_per_lifecycle}")
    log(f"  Events/lifecycle: ~{epl:.2f}")
    log(f"  File size       : {args.file_size_kb} KB")
    log(f"  Dedup reads     : {args.dedup_reads:,} "
        f"({'disabled' if args.dedup_reads == 0 else 'enabled'})")
    log(f"  Workspace ID    : {os.environ.get('DOMINO_RUN_ID', 'unknown')}")
    log(f"  Results proj    : {args.results_project or '(upload disabled)'}")
    if args.results_project:
        log(f"  Results dir     : {args.results_dir}")

    if duration_sec > 0:
        target_eps = args.total_events / duration_sec
        log(f"  Target rate     : ~{target_eps:.1f} events/sec sustained "
            f"over {args.duration_min} min")

    if not dataset_path.exists():
        log(f"ERROR: Dataset path does not exist: {dataset_path}")
        sys.exit(1)

    probe = dataset_path / f".probe_{rand_str()}"
    try:
        probe.touch()
        probe.unlink()
    except PermissionError:
        log(f"ERROR: No write permission at {dataset_path}")
        sys.exit(1)

    log("Pre-flight checks passed. Starting...")

    # Phase 1 - lifecycle I/O
    lifecycle_result = run_lifecycle_phase(
        dataset_path        = dataset_path,
        lifecycles          = lifecycles,
        workers             = args.workers,
        file_size_kb        = args.file_size_kb,
        reads_per_lifecycle = args.reads_per_lifecycle,
        duration_sec        = float(duration_sec),
    )

    # Phase 2 - dedup validation (optional, unchanged from v3)
    dedup_result = None
    if args.dedup_reads > 0:
        dedup_result = run_dedup_phase(
            dataset_path = dataset_path,
            dedup_reads  = args.dedup_reads,
            file_size_kb = args.file_size_kb,
        )

    summary = print_summary(lifecycle_result, dedup_result, args)

    upload_result = write_results_to_safe_project(summary, args)
    if upload_result.get("enabled"):
        if (upload_result.get("json_upload", {}).get("ok") and
                upload_result.get("log_upload", {}).get("ok")):
            log("Upload to safe project: SUCCESS")
        else:
            log("Upload to safe project: completed with warnings "
                "(see messages above)")


if __name__ == "__main__":
    main()
