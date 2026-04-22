#!/usr/bin/env python3
"""
Domino Workspace File Access Audit Trail - Loadgen Script v4
=============================================================

Change vs v3
------------
v3 hammered file lifecycles back-to-back with 4 worker threads. That is great
for saturating the Falco/audit pipeline but does not resemble a real
Statistical Compute (SCE) programmer's working day.

v4 replaces Phase 1 with a *realistic* per-workspace profile: a single
simulated programmer performing bursts of dataset I/O separated by idle
"thinking" gaps, over the 20-minute kill-switch lifetime of a Loadgen
workspace. Phase 2 (dedup validation) and the safe-project upload from v3
are unchanged.

Profile timeline (fits inside 20-min kill switch with ~2-min safety buffer)
---------------------------------------------------------------------------

    [ 0s    -  ~30s ]  SESSION START  - "morning load" of SDTM reads
    [ ~30s  - ~15m  ]  WORKING        - Poisson bursts of program runs
                                         (reads -> writes -> stat/delete)
    [ ~15m  - ~16m  ]  WIND-DOWN      - a final small burst
    [ ~16m  - ~18m  ]  CLEANUP        - delete any remaining session files
    [ ~18m  - ~20m  ]  idle           - buffer before kill-switch fires

Per-workspace event volume (default profile)
--------------------------------------------
    Morning load  : ~8-15 reads + ~8 initial file creates
    Working phase : ~12 bursts * ~8 ops = ~96 ops (read/write/stat/delete mix)
    Wind-down     : ~3-8 ops
    Cleanup       : ~variable deletes for remaining pool files
    ------------------------------------------------------------------
    RAW OPS TOTAL   : ~130-150 ops emitted per workspace (average)

Dedup-aware Falco event count
-----------------------------
Falco's audit pipeline deduplicates repeated reads of the same path within
the `UniqueReadEventPeriodInMinutes` window (default 60 min). Since the
whole simulated session (~15 min active + cleanup) sits inside one dedup
window, repeated reads of the same file collapse into a single audit event.
Writes / creates / deletes are NOT deduped.

    raw events      = writes + deletes + ALL reads
    post-dedup      = writes + deletes + UNIQUE-read-paths

Empirically the post-dedup count lands at ~70-90 events/workspace for the
default profile (vs ~130-150 raw ops), i.e. the pipeline sees roughly
40-50% of the ops count as distinct Falco events.

Example CDISC workflow modeled by each burst
--------------------------------------------
Each program burst in the working phase picks a named SCE task from the
`SCE_PROGRAMS` catalog below. The filename prefix makes the generated
audit events identifiable when you inspect them in the Falco logs:

    morning load    ->  sdtm/dm_*, sdtm/ae_*, sdtm/ex_*, sdtm/vs_*, sdtm/lb_*
                         (reads only - "pulling in the source datasets")
    build_adsl      ->  reads sdtm/{dm,ex,vs} -> writes adam/adsl_*
    build_adae      ->  reads adam/adsl + sdtm/ae -> writes adam/adae_*
    build_adlb      ->  reads adam/adsl + sdtm/lb -> writes adam/adlb_*
    tlf_ae_summary  ->  reads adam/{adsl,adae} -> writes tlf/t_ae_*
    tlf_dm_listing  ->  reads adam/adsl -> writes tlf/l_dm_*
    qc_compare      ->  reads adam/* (QC pass, mostly reads)

The BurstSession picks one program per burst and emits a read-heavy,
write-a-little, stat/delete-occasionally mix against the prefix for that
program. The op mix (60% read / 25% write / 15% stat+delete) applies to
every program; what varies is the filename pattern, so a reviewer looking
at Falco events can recognize the workflow stage that produced them.

At 200 concurrent workspaces (the observed prod peak) this gives roughly
25 events/sec sustained fleet-wide, with short bursts into the hundreds of
events/sec when program runs happen to line up across workspaces - a
realistic approximation of production audit traffic.

Fleet-level event budget (post-dedup)
-------------------------------------
    Total Falco events ~= num_workspaces * (~80 + 3_if_dedup_phase)
    Example: 500 workspaces * 80 = ~40,000 audit events fleet-wide

    If you want the pre-dedup (raw) number instead (e.g. to stress the
    in-node Falco ring buffer rather than the downstream pipeline):
        Raw ops ~= num_workspaces * (~135 + dedup_reads + 2)

Usage (as pre-run script, with log upload to a safe project)
------------------------------------------------------------

    python domino_audit_trail_load_test_v4.py \
        --dataset-path      /domino/datasets/local/<dataset> \
        --duration-min      15 \
        --dedup-reads       200 \
        --results-project   admin/audit-loadtest-results \
        --results-dir       falco_logs \
        --domino-url        https://domino-dev.myorg.com \
        --api-key           $DOMINO_USER_API_KEY

If --results-project is omitted, no upload is performed.
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
# Defaults - all tunable via CLI
# ---------------------------------------------------------------------------
DEFAULT_DURATION_MIN       = 15        # Active simulation window
SAFETY_BUFFER_SEC          = 120       # Leave 2 min before kill switch
DEFAULT_FILE_SIZE_KB       = 64

# Morning-load phase
MORNING_READS_RANGE        = (8, 15)   # Number of reads of SDTM-style files
MORNING_INITIAL_FILES      = 8         # Files pre-created as "input" pool
MORNING_PAUSE_RANGE_SEC    = (5, 30)   # Pause after morning reads

# Working phase
BURST_COUNT_LAMBDA         = 12.0      # Poisson lambda for number of bursts
BURST_SIZE_MU              = 2.0       # log-normal mu (burst size mean ~7.4)
BURST_SIZE_SIGMA           = 0.5
BURST_SIZE_CLAMP           = (3, 20)
INTER_BURST_MEAN_SEC       = 75        # Mean idle gap between bursts
INTRA_BURST_MEAN_SEC       = 0.3       # Mean spacing between ops in a burst

# Burst op mix (roughly how a program run distributes its I/O)
OP_MIX_READ_FRACTION       = 0.60      # 60% reads
OP_MIX_WRITE_FRACTION      = 0.25      # 25% writes (new + overwrite)
OP_MIX_OTHER_FRACTION      = 0.15      # 15% stat + delete (split 70/30)
OVERWRITE_PROB             = 0.5       # Fraction of writes that overwrite

# Wind-down phase
WINDDOWN_RANGE             = (3, 8)    # Number of ops at session end

# File pool management
MAX_POOL_SIZE              = 50        # Cap to avoid runaway dataset growth

# ---------------------------------------------------------------------------
# CDISC workflow catalog
# ---------------------------------------------------------------------------
# Each program represents a real SCE task. The working phase picks one per
# burst (weighted) and uses `output_prefix` for any files that burst writes.
# Filename patterns show up in the Falco audit events so reviewers can tell
# which workflow stage produced them.
#
# Weights chosen to match the target daily profile share once compressed into
# the 15-min kill-switch window:
#
#     ADaM builds     ~44%   (adsl + adae + adlb)
#     TLF generation  ~15%   (t_ae + l_dm)
#     QC compare      ~15%
#     Ad-hoc peek     ~15%   (tiny 1-3 op read bursts)
#     other/morning   ~11%   (folded into morning load + wind-down)
#
# `size_override` lets a program overrule the default lognormal burst size.
# Peeks are intentionally 1-3 ops to reproduce the "quick flurry of reads"
# pattern from the daily profile, which would otherwise get smoothed out.
SDTM_DOMAINS = ["dm", "ae", "ex", "vs", "lb"]   # seeded in morning load

SCE_PROGRAMS = [
    # (name,             output_prefix,   weight,  size_override)
    ("build_adsl",       "adam/adsl",     0.22,    None),
    ("build_adae",       "adam/adae",     0.20,    None),
    ("build_adlb",       "adam/adlb",     0.13,    None),
    ("tlf_ae_summary",   "tlf/t_ae",      0.10,    (8, 20)),
    ("tlf_dm_listing",   "tlf/l_dm",      0.05,    (8, 20)),
    ("qc_compare",       "qc/compare",    0.15,    (10, 20)),
    ("peek_dataset",     "tmp/peek",      0.15,    (1, 3)),
]

# Dedup phase defaults (from v3)
DEFAULT_DEDUP_READS        = 0         # 0 = disabled
DEFAULT_RESULTS_DIR        = "falco_logs"

# ---------------------------------------------------------------------------
# Log capture - tees every log() line to a buffer so we can upload the
# complete console trace at the end of the run.
# ---------------------------------------------------------------------------
_LOG_BUFFER = io.StringIO()


def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[audit-loadgen {ts}] {msg}"
    print(line, flush=True)
    _LOG_BUFFER.write(line + "\n")


def weighted_pick(mix: dict) -> str:
    r = random.random()
    cum = 0.0
    for k, v in mix.items():
        cum += v
        if r < cum:
            return k
    return next(iter(mix))


# ---------------------------------------------------------------------------
# BurstSession: one statistical programmer, one workspace
# ---------------------------------------------------------------------------
class BurstSession:
    """Simulates one SCE programmer working against a mounted Domino dataset
    for a bounded time window. Emits bursts of dataset file operations with
    realistic idle gaps between them.

    Honours `deadline_monotonic` at every sleep / op boundary - the session
    will cut phases short rather than run past the deadline.
    """

    def __init__(self, work_dir: Path, deadline_monotonic: float,
                 file_size_kb: int):
        self.work_dir    = work_dir
        self.deadline    = deadline_monotonic
        self.payload     = bytes(random.getrandbits(8)
                                 for _ in range(file_size_kb * 1024))
        self.counts      = {"read": 0, "write": 0, "stat": 0,
                            "delete": 0, "rename": 0}
        self.errors      = []
        self.file_pool   = []   # Files currently on disk in this session
        # Unique read paths - needed to estimate post-dedup Falco event count.
        # Falco collapses repeated reads of the same path within the
        # UniqueReadEventPeriodInMinutes window (default 60 min). Our whole
        # session fits inside that window, so reads-per-unique-path > 1 all
        # collapse to a single audit event.
        self.unique_reads = set()
        self.burst_count = 0

    # ---- time guard --------------------------------------------------------
    def _time_left(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def _sleep_bounded(self, seconds: float):
        """Sleep for `seconds` but never past the deadline."""
        seconds = min(seconds, self._time_left())
        if seconds > 0:
            time.sleep(seconds)

    def _expired(self) -> bool:
        return time.monotonic() >= self.deadline

    # ---- primitive file ops -----------------------------------------------
    def _create_file(self, prefix: str = "data") -> Path:
        """Create a file. `prefix` may contain a '/' (e.g. 'adam/adsl'),
        in which case the part before '/' becomes a subdirectory and the
        part after becomes the filename stem. Subdirs are created lazily."""
        if len(self.file_pool) >= MAX_POOL_SIZE:
            # Force a delete to keep the pool bounded
            self._emit_delete()
        if "/" in prefix:
            subdir, stem = prefix.rsplit("/", 1)
            target_dir = self.work_dir / subdir
            target_dir.mkdir(parents=True, exist_ok=True)
            fname = target_dir / f"{stem}_{rand_str()}.bin"
        else:
            fname = self.work_dir / f"{prefix}_{rand_str()}.bin"
        try:
            fname.write_bytes(self.payload)
            self.file_pool.append(fname)
            self.counts["write"] += 1
        except Exception as e:
            self.errors.append(f"create: {e}")
        return fname

    def _emit_read(self):
        if not self.file_pool:
            self._create_file(prefix="bootstrap")
            return
        f = random.choice(self.file_pool)
        try:
            _ = f.read_bytes()
            self.counts["read"] += 1
            # Track the unique path so we can estimate post-dedup events.
            self.unique_reads.add(str(f))
        except FileNotFoundError:
            # File was deleted between choice and read - remove from pool
            if f in self.file_pool:
                self.file_pool.remove(f)
        except Exception as e:
            self.errors.append(f"read: {e}")

    def _emit_write(self, prefix: str = "adam/out"):
        if self.file_pool and random.random() < OVERWRITE_PROB:
            # Overwrite an existing file - simulates iteration
            f = random.choice(self.file_pool)
            try:
                f.write_bytes(self.payload[::-1])
                self.counts["write"] += 1
            except Exception as e:
                self.errors.append(f"overwrite: {e}")
        else:
            self._create_file(prefix=prefix)

    def _emit_stat(self):
        if not self.file_pool:
            return
        f = random.choice(self.file_pool)
        try:
            _ = f.stat()
            self.counts["stat"] += 1
        except FileNotFoundError:
            if f in self.file_pool:
                self.file_pool.remove(f)
        except Exception as e:
            self.errors.append(f"stat: {e}")

    def _emit_delete(self):
        if not self.file_pool:
            return
        idx = random.randrange(len(self.file_pool))
        f = self.file_pool.pop(idx)
        try:
            f.unlink()
            self.counts["delete"] += 1
        except FileNotFoundError:
            pass
        except Exception as e:
            self.errors.append(f"delete: {e}")

    def _emit(self, op: str, write_prefix: str = "adam/out"):
        if op == "read":
            self._emit_read()
        elif op == "write":
            self._emit_write(prefix=write_prefix)
        elif op == "stat":
            self._emit_stat()
        elif op == "delete":
            self._emit_delete()

    # ---- phases -----------------------------------------------------------
    def _morning_load(self):
        """Simulate workspace boot + morning SDTM review: pre-create an
        SDTM-style input pool (dm/ae/ex/vs/lb domains), read each file
        once, then do 3-5 short review bursts. This combines the 'Boot'
        and 'Morning SDTM review' rows of the daily profile."""
        n_reads = random.randint(*MORNING_READS_RANGE)
        log(f"  Phase: MORNING LOAD - {MORNING_INITIAL_FILES} SDTM inputs + "
            f"{n_reads} reads")

        # Seed pool with named SDTM domains. Cycle through SDTM_DOMAINS so
        # filenames look like sdtm/dm_*.bin, sdtm/ae_*.bin, sdtm/ex_*.bin...
        for i in range(MORNING_INITIAL_FILES):
            if self._expired():
                return
            domain = SDTM_DOMAINS[i % len(SDTM_DOMAINS)]
            self._create_file(prefix=f"sdtm/{domain}")
            self._sleep_bounded(random.expovariate(1 / INTRA_BURST_MEAN_SEC))

        for _ in range(n_reads):
            if self._expired():
                return
            self._emit_read()
            self._sleep_bounded(random.expovariate(1 / INTRA_BURST_MEAN_SEC))

        # 3-5 short SDTM-review bursts (3-8 reads each) before real work
        # starts. Matches "Morning SDTM review" in the daily profile.
        for _ in range(random.randint(3, 5)):
            if self._expired():
                return
            for _ in range(random.randint(3, 8)):
                if self._expired():
                    return
                self._emit_read()
                self._sleep_bounded(
                    random.expovariate(1 / INTRA_BURST_MEAN_SEC))
            # Short pause between review bursts
            self._sleep_bounded(random.uniform(3, 10))

        # Programmer inspects the data briefly before starting work
        pause = random.uniform(*MORNING_PAUSE_RANGE_SEC)
        self._sleep_bounded(pause)

    def _pick_program(self) -> tuple:
        """Pick one SCE program from the catalog, weighted. Returns the
        full tuple (name, output_prefix, weight, size_override)."""
        total = sum(p[2] for p in SCE_PROGRAMS)
        r = random.random() * total
        cum = 0.0
        for p in SCE_PROGRAMS:
            cum += p[2]
            if r < cum:
                return p
        return SCE_PROGRAMS[-1]

    def _run_program_burst(self, size: int, program: tuple = None):
        """A single 'program run' - reads inputs, writes outputs, possibly
        does some stat/delete housekeeping. If `program` is supplied, writes
        go under that program's output_prefix and pure-read programs
        (e.g. peek, qc_compare) get a read-heavier mix."""
        prefix = "adam/out"
        is_read_heavy = False
        if program is not None:
            _, prefix, _, _ = program
            # QC and peek are overwhelmingly reads of existing files
            is_read_heavy = program[0] in ("peek_dataset", "qc_compare")

        if is_read_heavy:
            n_read  = max(1, int(round(size * 0.85)))
            n_write = max(0, int(round(size * 0.10)))
            n_other = max(0, size - n_read - n_write)
        else:
            n_read  = max(1, round(size * OP_MIX_READ_FRACTION))
            n_write = max(0, round(size * OP_MIX_WRITE_FRACTION))
            n_other = max(0, size - n_read - n_write)

        for _ in range(n_read):
            if self._expired():
                return
            self._emit_read()
            self._sleep_bounded(random.expovariate(1 / INTRA_BURST_MEAN_SEC))

        for _ in range(n_write):
            if self._expired():
                return
            self._emit_write(prefix=prefix)
            self._sleep_bounded(random.expovariate(1 / INTRA_BURST_MEAN_SEC))

        for _ in range(n_other):
            if self._expired():
                return
            op = weighted_pick({"stat": 0.7, "delete": 0.3})
            self._emit(op, write_prefix=prefix)
            self._sleep_bounded(random.expovariate(1 / INTRA_BURST_MEAN_SEC))

    def _working_phase(self, winddown_reserve_sec: float = 90.0):
        """Fire Poisson-distributed bursts of program runs, stopping early
        if we run out of time."""
        # Leave a reserve for wind-down + cleanup
        phase_deadline = self.deadline - winddown_reserve_sec
        n_bursts_target = max(
            1,
            int(random.gauss(BURST_COUNT_LAMBDA, math.sqrt(BURST_COUNT_LAMBDA)))
        )
        log(f"  Phase: WORKING - target ~{n_bursts_target} bursts over "
            f"{(phase_deadline - time.monotonic())/60:.1f} min")

        program_tally = {}
        for _ in range(n_bursts_target):
            if time.monotonic() >= phase_deadline:
                break
            program = self._pick_program()
            pname, _, _, size_override = program
            if size_override is not None:
                lo, hi = size_override
                size = random.randint(lo, hi)
            else:
                size = int(round(random.lognormvariate(
                    BURST_SIZE_MU, BURST_SIZE_SIGMA)))
                size = max(BURST_SIZE_CLAMP[0],
                           min(BURST_SIZE_CLAMP[1], size))
            self._run_program_burst(size, program=program)
            self.burst_count += 1
            program_tally[pname] = program_tally.get(pname, 0) + 1

            # Idle gap - programmer editing code / reviewing output
            gap = random.expovariate(1 / INTER_BURST_MEAN_SEC)
            # Never sleep past the phase deadline
            gap = min(gap, max(0.0, phase_deadline - time.monotonic()))
            if gap > 0:
                time.sleep(gap)

        self.program_tally = program_tally
        tally_str = ", ".join(f"{k}={v}" for k, v
                              in sorted(program_tally.items()))
        log(f"  Working phase complete: {self.burst_count} bursts fired "
            f"({tally_str})")

    def _winddown_phase(self):
        """Final small burst simulating end-of-day finishing touches."""
        if self._expired():
            return
        n = random.randint(*WINDDOWN_RANGE)
        log(f"  Phase: WIND-DOWN - {n} closing ops")
        for _ in range(n):
            if self._expired():
                return
            op = weighted_pick({"read": 0.5, "write": 0.4, "stat": 0.1})
            self._emit(op)
            self._sleep_bounded(random.expovariate(1 / INTRA_BURST_MEAN_SEC))

    def _cleanup_phase(self):
        """Delete any files remaining so the dataset is clean on exit.
        Respects the deadline but tries hard to finish - leaving orphaned
        files is worse than running slightly over if the deadline is tight.
        """
        if not self.file_pool:
            return
        log(f"  Phase: CLEANUP - removing {len(self.file_pool)} session files")
        for f in list(self.file_pool):
            try:
                if f.exists():
                    f.unlink()
                    self.counts["delete"] += 1
            except Exception as e:
                self.errors.append(f"cleanup: {e}")
        self.file_pool.clear()

    # ---- entry point ------------------------------------------------------
    def run(self):
        self._morning_load()
        self._working_phase()
        self._winddown_phase()
        self._cleanup_phase()

    @property
    def total_ops(self):
        return sum(self.counts.values())


# ---------------------------------------------------------------------------
# Phase 1 orchestration (replaces v3's run_lifecycle_phase)
# ---------------------------------------------------------------------------
def run_burst_phase(dataset_path: Path, duration_sec: int, file_size_kb: int):
    log("Phase 1 - Statistical programmer simulation (burst profile)")
    log(f"  Dataset path : {dataset_path}")
    log(f"  Active window: {duration_sec}s (~{duration_sec/60:.1f} min)")
    log(f"  File size    : {file_size_kb} KB")
    log(f"  Burst count  : Poisson(lambda={BURST_COUNT_LAMBDA})")
    log(f"  Burst size   : log-normal(mu={BURST_SIZE_MU}, "
        f"sigma={BURST_SIZE_SIGMA}), clamped to {BURST_SIZE_CLAMP}")
    log(f"  Inter-burst  : exp(mean={INTER_BURST_MEAN_SEC}s)")
    log(f"  Op mix       : read {int(OP_MIX_READ_FRACTION*100)}% / "
        f"write {int(OP_MIX_WRITE_FRACTION*100)}% / "
        f"other {int(OP_MIX_OTHER_FRACTION*100)}%")

    work_dir = dataset_path / f"audit_loadgen_{rand_str()}"
    work_dir.mkdir(parents=True, exist_ok=True)

    t_start    = time.monotonic()
    start_wall = datetime.now(timezone.utc)
    deadline   = t_start + duration_sec

    session = BurstSession(
        work_dir           = work_dir,
        deadline_monotonic = deadline,
        file_size_kb       = file_size_kb,
    )

    # Progress ticker (background thread, non-daemon-safe exit)
    stop_ticker = threading.Event()

    def ticker():
        last = 0
        while not stop_ticker.wait(10):
            total   = session.total_ops
            rate    = (total - last) / 10.0
            last    = total
            elapsed = time.monotonic() - t_start
            log(f"  Progress: {total:,} ops emitted  "
                f"rate: {rate:.1f}/s  "
                f"pool: {len(session.file_pool)}  "
                f"elapsed: {elapsed:.0f}s")

    tk = threading.Thread(target=ticker, daemon=True)
    tk.start()

    try:
        session.run()
    finally:
        stop_ticker.set()
        tk.join(timeout=2)

    elapsed  = time.monotonic() - t_start
    end_wall = datetime.now(timezone.utc)

    # Best-effort: remove the session directory (should be empty after cleanup)
    try:
        for f in work_dir.rglob("*"):
            if f.is_file():
                f.unlink()
        work_dir.rmdir()
    except Exception:
        pass

    log(f"  Completed in {elapsed:.1f}s "
        f"({session.total_ops:,} total ops, "
        f"{session.total_ops / max(elapsed, 1):.1f} ops/sec, "
        f"{session.burst_count} bursts)")

    if session.errors:
        log(f"  WARNING: {len(session.errors)} error(s) during session")
        for e in session.errors[:5]:
            log(f"    {e}")

    return {
        "duration_s"         : elapsed,
        "total_ops"          : session.total_ops,
        "ops"                : session.counts,
        "burst_count"        : session.burst_count,
        "ops_per_sec"        : session.total_ops / max(elapsed, 1),
        "unique_reads_count" : len(session.unique_reads),
        "start_wall"         : start_wall.isoformat(),
        "end_wall"           : end_wall.isoformat(),
        "errors"             : session.errors[:50],
        "error_count"        : len(session.errors),
    }


# ---------------------------------------------------------------------------
# Phase 2: Dedup validation (unchanged from v3)
# ---------------------------------------------------------------------------
def run_dedup_phase(dataset_path: Path, dedup_reads: int, file_size_kb: int):
    log("Phase 2 - Dedup validation")
    log(f"  Single file, {dedup_reads:,} reads")
    log(f"  Expected audit events after pipeline: 1 create + 1 read + 1 delete")
    log(f"  (pipeline should collapse {dedup_reads:,} reads into 1 "
        f"deduplicated event)")

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
def print_summary(burst_result, dedup_result, args):
    log("=" * 60)
    log("SUMMARY")
    log("=" * 60)

    br  = burst_result
    ops = br["ops"]

    log(f"  Bursts fired         : {br['burst_count']}")
    log(f"  Total ops            : {br['total_ops']:,}")
    log(f"  Throughput           : {br['ops_per_sec']:.2f} ops/sec "
        f"(sustained, not burst peak)")
    log(f"  Duration             : {br['duration_s']:.1f}s")
    log(f"  I/O errors           : {br['error_count']}")
    log(f"  Start (UTC)          : {br['start_wall']}")
    log(f"  End   (UTC)          : {br['end_wall']}")
    log("")
    log("  Op breakdown:")
    for op, count in ops.items():
        log(f"    {op.capitalize():<8} : {count:,}")

    if dedup_result:
        log("")
        log(f"  Dedup reads          : {dedup_result['reads_performed']:,}")
        log(f"  Dedup file           : {dedup_result['test_file_name']}")
        log(f"  Expected audit events: 1 create + 1 read + 1 delete")

    # ------------------------------------------------------------------
    # Post-dedup Falco event estimate
    # ------------------------------------------------------------------
    # Falco's audit pipeline collapses repeated reads of the same path
    # within the UniqueReadEventPeriodInMinutes window (default 60 min).
    # Our whole simulated session (~15 min active + cleanup) sits entirely
    # inside one dedup window, so repeated reads of the same file collapse
    # to a single audit event. Writes/creates/deletes are NOT deduped.
    #
    #   raw events  = write + delete + ALL reads
    #   post-dedup  = write + delete + UNIQUE reads
    #
    # The dedup phase (Phase 2) contributes a fixed 3 events regardless of
    # how many reads it fires (1 create + 1 deduped read + 1 delete).
    unique_reads = br.get("unique_reads_count", ops["read"])
    non_read_ops = ops["write"] + ops["delete"] + ops.get("rename", 0)
    falco_events_raw      = br["total_ops"]
    falco_events_dedup    = non_read_ops + unique_reads
    if dedup_result:
        falco_events_raw   += dedup_result["reads_performed"] + 2
        falco_events_dedup += 3   # 1 create + 1 deduped read + 1 delete

    collapse_ratio = (1.0 - falco_events_dedup / falco_events_raw) * 100 \
        if falco_events_raw else 0.0

    log("")
    log(f"  Unique read paths           : {unique_reads:,} "
        f"(of {ops['read']:,} total reads)")
    log(f"  Falco events (raw)          : ~{falco_events_raw:,}")
    log(f"  Falco events (post-60m-dedup): ~{falco_events_dedup:,} "
        f"(-{collapse_ratio:.0f}%)")
    log(f"  (multiply post-dedup by fleet size for pipeline pressure)")
    log("=" * 60)

    summary = {
        "workspace_id"           : os.environ.get("DOMINO_RUN_ID", "unknown"),
        "dataset_path"           : str(args.dataset_path),
        "duration_min"           : args.duration_min,
        "burst_count"            : br["burst_count"],
        "total_ops"              : br["total_ops"],
        "ops_per_sec"            : round(br["ops_per_sec"], 2),
        "duration_s"             : round(br["duration_s"], 1),
        "error_count"            : br["error_count"],
        "ops"                    : br["ops"],
        "unique_reads_count"     : unique_reads,
        "start_wall"             : br["start_wall"],
        "end_wall"               : br["end_wall"],
        # falco_events_est kept for back-compat with v3 uploaders; equals the
        # post-60min-dedup figure so dashboards don't over-estimate.
        "falco_events_est"       : falco_events_dedup,
        "falco_events_raw"       : falco_events_raw,
        "falco_events_post_dedup": falco_events_dedup,
        "dedup"                  : dedup_result,
        "profile_version"        : "v4-burst",
    }
    log("JSON_SUMMARY: " + json.dumps(summary))
    return summary


# ---------------------------------------------------------------------------
# Upload to safe project (unchanged from v3)
# ---------------------------------------------------------------------------
def upload_to_project(payload_bytes: bytes, domino_url: str, api_key: str,
                      project: str, remote_path: str) -> dict:
    """Upload raw bytes to a Domino project via the v1 Files REST API.
    Returns a dict describing the HTTP result."""
    if requests is None:
        raise RuntimeError(
            "The 'requests' library is required for --results-project. "
            "Install it in the workspace image: pip install requests"
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
    resp = requests.put(url, headers=headers,
                        data=payload_bytes, timeout=120)
    result = {
        "status_code" : resp.status_code,
        "url"         : url,
        "ok"          : resp.ok,
        "response"    : resp.text[:500],
    }
    # A 404 on this endpoint almost always means the target project does
    # not exist OR the calling user is not a collaborator. Domino returns
    # the generic "Not Found - Domino" HTML page for both cases (no
    # distinction between missing and forbidden in the public API).
    if resp.status_code == 404:
        result["hint"] = (
            f"HTTP 404 on PUT /v1/projects/{owner}/{name}/files/... - "
            f"verify (a) the project '{owner}/{name}' exists, and "
            f"(b) the API key owner is a collaborator with write access."
        )
    return result


def write_results_to_safe_project(summary: dict, args) -> dict:
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
        description="Domino Workspace File Access Audit Trail - Loadgen v4 "
                    "(burst/realistic profile)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "--dataset-path", required=True,
        help="Path to a mounted Domino Dataset or NetApp Volume"
    )
    p.add_argument(
        "--duration-min", type=int, default=DEFAULT_DURATION_MIN,
        help=f"Target active session duration in minutes "
             f"(default: {DEFAULT_DURATION_MIN}). Must be less than the "
             f"Loadgen kill-switch-delay minus {SAFETY_BUFFER_SEC}s safety "
             f"buffer (so <=18 min for the default 20-min kill switch)."
    )
    p.add_argument(
        "--file-size-kb", type=int, default=DEFAULT_FILE_SIZE_KB,
        help=f"File size in KB (default: {DEFAULT_FILE_SIZE_KB})"
    )
    p.add_argument(
        "--dedup-reads", type=int, default=DEFAULT_DEDUP_READS,
        help=f"Number of repeated reads for dedup validation "
             f"(default: {DEFAULT_DEDUP_READS} = disabled)."
    )

    # --- Safe-project upload flags (same as v3) ---------------------------
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

    # Clamp duration so we always leave the safety buffer intact
    duration_sec = args.duration_min * 60
    max_safe_sec = 20 * 60 - SAFETY_BUFFER_SEC      # 18 min with default switch
    if duration_sec > max_safe_sec:
        log(f"WARNING: --duration-min {args.duration_min} would exceed the "
            f"safe window of {max_safe_sec // 60} min; clamping down.")
        duration_sec = max_safe_sec

    log("Domino Workspace File Access Audit Trail - Loadgen v4")
    log(f"  Python        : {sys.version.split()[0]}")
    log(f"  Dataset path  : {dataset_path}")
    log(f"  Duration      : {duration_sec}s ({duration_sec/60:.1f} min)")
    log(f"  File size     : {args.file_size_kb} KB")
    log(f"  Dedup reads   : {args.dedup_reads:,} "
        f"({'disabled' if args.dedup_reads == 0 else 'enabled'})")
    log(f"  Workspace ID  : {os.environ.get('DOMINO_RUN_ID', 'unknown')}")
    log(f"  Results proj  : {args.results_project or '(upload disabled)'}")
    if args.results_project:
        log(f"  Results dir   : {args.results_dir}")

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

    # Phase 1 - burst-based programmer simulation
    burst_result = run_burst_phase(
        dataset_path = dataset_path,
        duration_sec = duration_sec,
        file_size_kb = args.file_size_kb,
    )

    # Phase 2 - dedup validation (optional, unchanged from v3)
    dedup_result = None
    if args.dedup_reads > 0:
        dedup_result = run_dedup_phase(
            dataset_path = dataset_path,
            dedup_reads  = args.dedup_reads,
            file_size_kb = args.file_size_kb,
        )

    summary = print_summary(burst_result, dedup_result, args)

    upload_result = write_results_to_safe_project(summary, args)
    if upload_result.get("enabled"):
        if upload_result.get("json_upload", {}).get("ok") and \
           upload_result.get("log_upload", {}).get("ok"):
            log("Upload to safe project: SUCCESS")
        else:
            log("Upload to safe project: completed with warnings "
                "(see messages above)")


if __name__ == "__main__":
    main()
