#!/usr/bin/env python3
"""
Domino Workspace File Access Audit Trail - Loadgen Script v2
=============================================================
Purpose:
  Generate a controlled, reproducible volume of auditable file system events
  against a Domino Dataset or NetApp Volume mount. Designed to run as a
  Domino pre-run script inside workspaces spun up by a loadgen tool.

Each --lifecycles N means N complete file lifecycles:

    Create -> Write -> Read -> [Rename 20% of files] -> Delete

Every file that is created is deleted before the script exits, leaving the
filesystem clean. No files are orphaned.

Optionally, a dedup validation phase creates a single file, reads it
--dedup-reads N times, then deletes it. This verifies that the audit pipeline
collapses repeated reads into a single deduplicated event.

Total Falco events per run (approximate):
  Lifecycle events : lifecycles * 4.2  (4 ops + 20% chance of rename)
  Dedup events     : dedup_reads + 2   (N reads + 1 create + 1 delete)

Usage (as pre-run script):
  python domino_audit_trail_load_test_v2.py \
      --dataset-path /domino/datasets/local/<dataset> \
      --lifecycles   1000 \
      --workers      4

  # With dedup validation:
  python domino_audit_trail_load_test_v2.py \
      --dataset-path /domino/datasets/local/<dataset> \
      --lifecycles   1000 \
      --workers      4 \
      --dedup-reads  200

Fleet-level load calculation:
  Total Falco events = num_workspaces * (lifecycles * 4.2 + dedup_reads + 2)
  Example: 50 workspaces * (1000 * 4.2) = 210,000 events across the fleet
"""

import argparse
import json
import math
import os
import random
import string
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_LIFECYCLES   = 1000
DEFAULT_WORKERS      = 4
DEFAULT_FILE_SIZE_KB = 64
DEFAULT_DEDUP_READS  = 0          # 0 = dedup phase disabled
RENAME_PROBABILITY   = 0.20       # 20% of lifecycles include a rename


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[audit-loadgen {ts}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Worker: runs a fixed number of complete file lifecycles
# ---------------------------------------------------------------------------

class LifecycleWorker:
    """
    Executes a fixed number of complete file lifecycles against work_dir.

    Each lifecycle:
      1. Create  — write a new binary file
      2. Write   — overwrite it with fresh content
      3. Read    — read it back
      4. Rename  — rename it (RENAME_PROBABILITY % of lifecycles)
      5. Delete  — unlink the file

    Every file created is deleted before the worker exits.
    Ops are counted per type for the final summary.
    """

    def __init__(self, worker_id: int, work_dir: Path,
                 lifecycles: int, file_size_kb: int):
        self.worker_id    = worker_id
        self.work_dir     = work_dir
        self.lifecycles   = lifecycles
        self.file_size_kb = file_size_kb
        self.counts = {
            "create": 0, "write": 0, "read": 0,
            "rename": 0, "delete": 0
        }
        self.errors       = []

    def run(self):
        payload = bytes(random.getrandbits(8)
                        for _ in range(self.file_size_kb * 1024))

        for _ in range(self.lifecycles):
            fname = self.work_dir / f"lc_{self.worker_id}_{rand_str()}.bin"
            try:
                # 1. Create
                fname.write_bytes(payload)
                self.counts["create"] += 1

                # 2. Write (overwrite with new content)
                fname.write_bytes(payload[::-1])
                self.counts["write"] += 1

                # 3. Read
                _ = fname.read_bytes()
                self.counts["read"] += 1

                # 4. Rename (probabilistic)
                if random.random() < RENAME_PROBABILITY:
                    renamed = fname.with_name(fname.stem + "_r.bin")
                    fname.rename(renamed)
                    self.counts["rename"] += 1
                    fname = renamed

                # 5. Delete
                fname.unlink()
                self.counts["delete"] += 1

            except Exception as e:
                self.errors.append(str(e))
                # Best-effort cleanup if file still exists
                try:
                    if fname.exists():
                        fname.unlink()
                except Exception:
                    pass

    @property
    def total_ops(self):
        return sum(self.counts.values())


# ---------------------------------------------------------------------------
# Phase 1: Lifecycle I/O
# ---------------------------------------------------------------------------

def run_lifecycle_phase(dataset_path: Path, lifecycles: int,
                        workers: int, file_size_kb: int):
    log(f"Phase 1 — File lifecycle I/O")
    log(f"  Dataset path : {dataset_path}")
    log(f"  Lifecycles   : {lifecycles:,} total")
    log(f"  Workers      : {workers}")
    log(f"  Per worker   : {math.ceil(lifecycles / workers):,} lifecycles")
    log(f"  File size    : {file_size_kb} KB")
    log(f"  Rename prob  : {int(RENAME_PROBABILITY * 100)}%")
    log(f"  Expected ops : ~{int(lifecycles * (4 + RENAME_PROBABILITY)):,} "
        f"({lifecycles} creates/writes/reads/deletes "
        f"+ ~{int(lifecycles * RENAME_PROBABILITY)} renames)")

    work_dir = dataset_path / f"audit_loadgen_{rand_str()}"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Distribute lifecycles across workers as evenly as possible
    base    = lifecycles // workers
    remainder = lifecycles % workers
    per_worker = [base + (1 if i < remainder else 0) for i in range(workers)]

    worker_objs = [
        LifecycleWorker(i, work_dir, per_worker[i], file_size_kb)
        for i in range(workers)
    ]
    threads = [threading.Thread(target=w.run, daemon=True) for w in worker_objs]

    t_start    = time.monotonic()
    start_wall = datetime.now(timezone.utc)

    for t in threads:
        t.start()

    # Progress ticker — one line every 10 seconds
    completed_prev = 0
    while any(t.is_alive() for t in threads):
        time.sleep(10)
        completed  = sum(w.counts["delete"] for w in worker_objs)
        errors     = sum(len(w.errors) for w in worker_objs)
        elapsed    = time.monotonic() - t_start
        rate       = (completed - completed_prev) / 10
        completed_prev = completed
        pct        = completed / lifecycles * 100
        log(f"  Progress: {completed:,}/{lifecycles:,} lifecycles "
            f"({pct:.0f}%)  rate: {rate:.0f}/s  "
            f"elapsed: {elapsed:.0f}s  errors: {errors}")

    for t in threads:
        t.join()

    elapsed = time.monotonic() - t_start
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

    # Aggregate results
    op_totals  = {k: sum(w.counts[k] for w in worker_objs)
                  for k in worker_objs[0].counts}
    all_errors = [e for w in worker_objs for e in w.errors]
    total_ops  = sum(op_totals.values())

    log(f"  Completed in {elapsed:.1f}s  "
        f"({total_ops:,} total ops, "
        f"{total_ops / elapsed:.0f} ops/sec)")

    if all_errors:
        log(f"  WARNING: {len(all_errors)} error(s) during lifecycles")
        for e in all_errors[:5]:
            log(f"    {e}")

    return {
        "lifecycles_requested" : lifecycles,
        "lifecycles_completed" : op_totals["delete"],
        "ops"                  : op_totals,
        "total_ops"            : total_ops,
        "ops_per_sec"          : total_ops / max(elapsed, 1),
        "duration_s"           : elapsed,
        "start_wall"           : start_wall.isoformat(),
        "end_wall"             : end_wall.isoformat(),
        "errors"               : all_errors[:50],
        "error_count"          : len(all_errors),
    }


# ---------------------------------------------------------------------------
# Phase 2: Dedup validation (optional)
# ---------------------------------------------------------------------------

def run_dedup_phase(dataset_path: Path, dedup_reads: int, file_size_kb: int):
    log(f"Phase 2 — Dedup validation")
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

    lc = lifecycle_result
    ops = lc["ops"]

    log(f"  Lifecycles completed : {lc['lifecycles_completed']:,} "
        f"/ {lc['lifecycles_requested']:,}")
    log(f"  Total ops            : {lc['total_ops']:,}")
    log(f"  Throughput           : {lc['ops_per_sec']:.0f} ops/sec")
    log(f"  Duration             : {lc['duration_s']:.1f}s")
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

    # Fleet-level event budget (informational)
    falco_events = lc["total_ops"]
    if dedup_result:
        falco_events += dedup_result["reads_performed"] + 2
    log("")
    log(f"  Falco events this workspace : ~{falco_events:,}")
    log(f"  (multiply by fleet size for total pipeline pressure)")
    log("=" * 60)

    # Emit compact JSON summary to stdout for log capture
    summary = {
        "workspace_id"      : os.environ.get("DOMINO_RUN_ID", "unknown"),
        "dataset_path"      : str(args.dataset_path),
        "lifecycles"        : lc["lifecycles_completed"],
        "total_ops"         : lc["total_ops"],
        "ops_per_sec"       : round(lc["ops_per_sec"], 1),
        "duration_s"        : round(lc["duration_s"], 1),
        "error_count"       : lc["error_count"],
        "ops"               : lc["ops"],
        "start_wall"        : lc["start_wall"],
        "end_wall"          : lc["end_wall"],
        "falco_events_est"  : falco_events,
        "dedup"             : dedup_result,
    }
    log("JSON_SUMMARY: " + json.dumps(summary))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Domino Workspace File Access Audit Trail — Loadgen v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--dataset-path", required=True,
        help="Path to a mounted Domino Dataset or NetApp Volume"
    )
    p.add_argument(
        "--lifecycles", type=int, default=DEFAULT_LIFECYCLES,
        help=f"Number of complete file lifecycles to execute per workspace "
             f"(default: {DEFAULT_LIFECYCLES}). Each lifecycle = "
             f"create + write + read + [rename] + delete."
    )
    p.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Parallel worker threads (default: {DEFAULT_WORKERS}). "
             f"Lifecycles are distributed evenly across workers."
    )
    p.add_argument(
        "--file-size-kb", type=int, default=DEFAULT_FILE_SIZE_KB,
        help=f"File size in KB (default: {DEFAULT_FILE_SIZE_KB})"
    )
    p.add_argument(
        "--dedup-reads", type=int, default=DEFAULT_DEDUP_READS,
        help=f"Number of repeated reads on a single file for dedup validation "
             f"(default: {DEFAULT_DEDUP_READS} = disabled). "
             f"Adds a create + N reads + delete lifecycle after Phase 1."
    )
    return p.parse_args()


def main():
    args = parse_args()

    dataset_path = Path(args.dataset_path)

    # Pre-flight
    log("Domino Workspace File Access Audit Trail — Loadgen v2")
    log(f"  Python       : {sys.version.split()[0]}")
    log(f"  Dataset path : {dataset_path}")
    log(f"  Lifecycles   : {args.lifecycles:,}")
    log(f"  Workers      : {args.workers}")
    log(f"  File size    : {args.file_size_kb} KB")
    log(f"  Dedup reads  : {args.dedup_reads:,} "
        f"({'disabled' if args.dedup_reads == 0 else 'enabled'})")
    log(f"  Workspace ID : {os.environ.get('DOMINO_RUN_ID', 'unknown')}")

    if not dataset_path.exists():
        log(f"ERROR: Dataset path does not exist: {dataset_path}")
        sys.exit(1)

    # Write permission check
    probe = dataset_path / f".probe_{rand_str()}"
    try:
        probe.touch()
        probe.unlink()
    except PermissionError:
        log(f"ERROR: No write permission at {dataset_path}")
        sys.exit(1)

    log("Pre-flight checks passed. Starting...")

    # Phase 1 — lifecycle I/O
    lifecycle_result = run_lifecycle_phase(
        dataset_path  = dataset_path,
        lifecycles    = args.lifecycles,
        workers       = args.workers,
        file_size_kb  = args.file_size_kb,
    )

    # Phase 2 — dedup validation (optional)
    dedup_result = None
    if args.dedup_reads > 0:
        dedup_result = run_dedup_phase(
            dataset_path = dataset_path,
            dedup_reads  = args.dedup_reads,
            file_size_kb = args.file_size_kb,
        )

    print_summary(lifecycle_result, dedup_result, args)


if __name__ == "__main__":
    main()
