"""E19: controlled scale, latency, graph repair, and storage benchmark."""
from __future__ import annotations

import cProfile
import csv
import hashlib
import io
import json
import math
import os
import platform
import pstats
import random
import shutil
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
from scipy import sparse

from . import e07
from .core import certify
from .e13 import (
    Action, _hypothetical, _make_case, _sealed_outcome,
    fit_outcome_model, select_action,
)

ALPHA = 0.35
DEFAULT_SIZES = (1_000, 10_000, 100_000, 1_000_000)
ATTACK_BUDGETS = (1, 2, 3, 5)
ACTION_BUDGETS = (1, 2, 3, 5, 10)
LATENCY_SAMPLE_LIMIT = 2_000
PROPAGATION_TOLERANCE = 1e-12
PROPAGATION_MAX_ITERATIONS = 2_000
CSV_COLUMNS = {
    "scale": (
        "observed_urls", "status", "skip_reason", "workload", "seed",
        "graph_degree_mean", "graph_degree_max", "source_groups",
        "ancestor_count_mean", "ancestor_count_p95", "ingestion_seconds",
        "closure_seconds", "full_propagation_seconds",
        "incremental_propagation_seconds", "incremental_speedup",
        "incremental_max_abs_error", "incremental_iterations",
        "full_iterations", "action_selection_seconds", "proof_check_seconds",
        "storage_write_seconds", "storage_bytes", "storage_bytes_per_url",
        "peak_rss_mb", "rss_delta_mb", "cpu_seconds_per_url",
        "total_wall_seconds",
    ),
    "latency": (
        "observed_urls", "stage", "latency_unit", "sample_count",
        "p50_ms", "p95_ms", "p99_ms", "bulk_seconds",
    ),
    "certificates": (
        "observed_urls", "group_count", "attack_budget", "direction",
        "exact_status", "exact_seconds", "exact_damage", "relaxed_status",
        "relaxed_seconds", "relaxed_damage_bound", "relaxation_gap",
        "exact_certified", "relaxed_certified", "working_set_delta_mb",
    ),
    "incremental": (
        "observed_urls", "update_node", "full_seconds", "incremental_seconds",
        "speedup", "max_abs_error", "full_iterations",
        "incremental_iterations", "equivalent",
    ),
}


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest(out: Path) -> None:
    files = [
        path for path in out.rglob("*")
        if path.is_file() and path.name != "manifest_sha256.json"
    ]
    payload = {
        str(path.relative_to(out)): _sha256(path)
        for path in sorted(files)
    }
    (out / "manifest_sha256.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8",
    )


def _percentiles(samples: list[float]) -> tuple[float | None, float | None, float | None]:
    if not samples:
        return None, None, None
    return tuple(float(value) for value in np.percentile(samples, (50, 95, 99)))


def _latency_row(
    size: int, stage: str, unit: str, samples: list[float], bulk_seconds: float | None,
) -> dict[str, Any]:
    p50, p95, p99 = _percentiles(samples)
    return {
        "observed_urls": size,
        "stage": stage,
        "latency_unit": unit,
        "sample_count": len(samples),
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "bulk_seconds": bulk_seconds,
    }


def _windows_memory() -> dict[str, float | None]:
    if not sys.platform.startswith("win"):
        return {
            "physical_total_gb": None,
            "physical_available_gb": None,
            "process_peak_rss_mb": None,
            "process_working_set_mb": None,
            "memory_method": "Windows memory APIs unavailable on this platform",
        }

    import ctypes
    from ctypes import wintypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GlobalMemoryStatusEx.argtypes = (ctypes.POINTER(MemoryStatus),)
    kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError(ctypes.get_last_error())
    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD,
    )
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    if not psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    gib = 1024 ** 3
    return {
        "physical_total_gb": status.ullTotalPhys / gib,
        "physical_available_gb": status.ullAvailPhys / gib,
        "process_peak_rss_mb": counters.PeakWorkingSetSize / 1_000_000,
        "process_working_set_mb": counters.WorkingSetSize / 1_000_000,
        "memory_method": "GlobalMemoryStatusEx and GetProcessMemoryInfo",
    }


def _make_graph(size: int) -> sparse.csr_matrix:
    nodes = np.arange(size, dtype=np.int32)
    rows = np.repeat(nodes, 4)
    columns = np.column_stack((
        nodes,
        (nodes + 1) % size,
        (nodes + 17) % size,
        (nodes + 43) % size,
    )).ravel()
    values = np.full(len(rows), 0.25, dtype=np.float64)
    graph = sparse.csr_matrix((values, (rows, columns)), shape=(size, size))
    graph.sum_duplicates()
    graph.sort_indices()
    row_sums = np.asarray(graph.sum(axis=1)).ravel()
    if not np.allclose(row_sums, 1.0, atol=1e-12):
        raise AssertionError("synthetic graph is not row-stochastic")
    return graph


def _propagate(
    graph: sparse.csr_matrix, seed_values: np.ndarray,
) -> tuple[np.ndarray, int]:
    current = np.array(seed_values, dtype=np.float64, copy=True)
    for iteration in range(1, PROPAGATION_MAX_ITERATIONS + 1):
        updated = (1.0 - ALPHA) * seed_values + ALPHA * graph.dot(current)
        if np.max(np.abs(updated - current)) <= PROPAGATION_TOLERANCE:
            return updated, iteration
        current = updated
    raise RuntimeError(
        f"URLTrust propagation did not converge within {PROPAGATION_MAX_ITERATIONS} iterations"
    )


def _propagate_delta(
    graph: sparse.csr_matrix, prior: np.ndarray, delta_seed: np.ndarray,
) -> tuple[np.ndarray, int]:
    delta = np.zeros_like(prior)
    for iteration in range(1, PROPAGATION_MAX_ITERATIONS + 1):
        updated = (1.0 - ALPHA) * delta_seed + ALPHA * graph.dot(delta)
        if np.max(np.abs(updated - delta)) <= PROPAGATION_TOLERANCE:
            return prior + updated, iteration
        delta = updated
    raise RuntimeError(
        f"incremental trust update did not converge within {PROPAGATION_MAX_ITERATIONS} iterations"
    )


def _make_ancestry(size: int, seed: int) -> tuple[np.ndarray, np.ndarray, list[frozenset[int]]]:
    rng = np.random.default_rng(seed)
    group_count = min(8_192, max(64, int(math.sqrt(size) * 4)))
    direct_count = (np.arange(size, dtype=np.uint8) % 3) + 1
    direct_groups = rng.integers(
        0, group_count, size=(size, 3), dtype=np.int32,
    )
    closures: list[frozenset[int]] = []
    for group in range(group_count):
        ancestors = {group}
        if group > 1:
            ancestors.update(closures[group // 2])
            if group > 4:
                ancestors.update(closures[group // 3])
        closures.append(frozenset(ancestors))
    return direct_groups, direct_count, closures


def _close_record(groups: np.ndarray, count: int, closures: list[frozenset[int]]) -> frozenset[int]:
    result: set[int] = set()
    for group in groups[:count]:
        result.update(closures[int(group)])
    return frozenset(result)


def _ingest(
    size: int, seed_values: np.ndarray, direct_groups: np.ndarray,
    direct_count: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[float]]:
    values = np.empty(size, dtype=np.float64)
    roots = np.empty((size, 3), dtype=np.int32)
    counts = np.empty(size, dtype=np.uint8)
    samples = []
    for index in range(size):
        tic = time.perf_counter()
        line = json.dumps({
            "url_id": index,
            "value": float(seed_values[index]),
            "groups": direct_groups[index, :int(direct_count[index])].tolist(),
        }, separators=(",", ":"))
        record = json.loads(line)
        if record["url_id"] != index or not 0.0 <= record["value"] <= 1.0:
            raise ValueError(f"invalid synthetic evidence record at row {index}")
        row_groups = record["groups"]
        if not row_groups or len(row_groups) > 3:
            raise ValueError(f"invalid ancestor declaration at row {index}")
        values[index] = record["value"]
        counts[index] = len(row_groups)
        roots[index, :len(row_groups)] = row_groups
        samples.append((time.perf_counter() - tic) * 1000) if index < LATENCY_SAMPLE_LIMIT else None
    return values, roots, counts, samples


def _certificate_benchmarks(
    size: int, group_count: int, seed: int, time_limit: float,
) -> list[dict[str, Any]]:
    case = e07.make_case(seed, group_count, "medium", "sparse", False)
    rows = []
    for budget in ATTACK_BUDGETS:
        before_mb = _windows_memory()["process_working_set_mb"]
        solutions = {}
        for direction in ("down", "up"):
            exact = e07.solve_milp(case, direction, budget, integer=True, time_limit=time_limit)
            relaxed = e07.solve_milp(case, direction, budget, integer=False, time_limit=time_limit)
            solutions[direction] = (exact, relaxed)
            exact_damage = (
                exact["primal"] if exact["status"] == "optimal" else None
            )
            relaxed_damage = relaxed["bound"]
            gap = (
                max(0.0, float(relaxed_damage) - float(exact_damage))
                if exact_damage is not None and relaxed_damage is not None else None
            )
            gap_fraction = (
                gap / max(float(exact_damage), 1e-12)
                if gap is not None else None
            )
            rows.append({
                "observed_urls": size,
                "group_count": group_count,
                "attack_budget": budget,
                "direction": direction,
                "exact_status": exact["status"],
                "exact_seconds": exact["seconds"],
                "exact_damage": exact_damage,
                "relaxed_status": relaxed["status"],
                "relaxed_seconds": relaxed["seconds"],
                "relaxed_damage_bound": relaxed_damage,
                "relaxation_gap": gap_fraction,
                "exact_certified": None,
                "relaxed_certified": None,
            })
        exact_down, exact_up = solutions["down"][0], solutions["up"][0]
        relaxed_down, relaxed_up = solutions["down"][1], solutions["up"][1]
        exact_certified = (
            e07.certified(case, exact_down["bound"], exact_up["bound"])
            if exact_down["status"] == "optimal" and exact_up["status"] == "optimal"
            else None
        )
        relaxed_certified = (
            e07.certified(case, relaxed_down["bound"], relaxed_up["bound"])
            if relaxed_down["bound"] is not None and relaxed_up["bound"] is not None
            else None
        )
        for row in rows[-2:]:
            row["exact_certified"] = exact_certified
            row["relaxed_certified"] = relaxed_certified
            after_mb = _windows_memory()["process_working_set_mb"]
            row["working_set_delta_mb"] = (
                max(0.0, float(after_mb) - float(before_mb))
                if before_mb is not None and after_mb is not None else None
            )
    return rows


def _action_benchmarks(size: int, seed: int, model: dict) -> tuple[list[dict], list[dict]]:
    action_rows, latency_rows = [], []
    for budget in ACTION_BUDGETS:
        before_mb = _windows_memory()["process_working_set_mb"]
        samples = []
        for repeat in range(3):
            case, truth, actions = _make_case(
                random.Random(seed + repeat), f"e19-{size}-{budget}-{repeat}",
            )
            rng = random.Random(seed ^ repeat ^ budget)
            selector_model = model
            selected: list[Action] = []
            state = case
            label = truth["label"]
            outcomes = {
                action.action_id: _sealed_outcome(
                    random.Random(seed + repeat + index), action, label,
                )
                for index, action in enumerate(actions)
            }
            for _ in range(budget):
                tic = time.perf_counter()
                action = select_action(
                    "cer_guided", state, actions, selected, selector_model, rng,
                )
                samples.append((time.perf_counter() - tic) * 1000)
                if action is None:
                    break
                state = _hypothetical(state, action, outcomes[action.action_id])
                selected.append(action)
        action_rows.append({
            "observed_urls": size,
            "action_budget": budget,
            "replicates": 3,
            "selected_actions": len(samples),
            "total_selection_seconds": sum(samples) / 1000,
            "working_set_delta_mb": (
                max(
                    0.0,
                    float(_windows_memory()["process_working_set_mb"]) - float(before_mb),
                )
                if before_mb is not None
                and _windows_memory()["process_working_set_mb"] is not None
                else None
            ),
        })
        latency_rows.append(_latency_row(
            size, f"action_selection_b{budget}", "per selection", samples,
            sum(samples) / 1000,
        ))
    return action_rows, latency_rows


def _storage_write(
    path: Path, values: np.ndarray, closure_counts: np.ndarray,
) -> tuple[float, int, list[float]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    samples = []
    started = time.perf_counter()
    with path.open("w", newline="", encoding="utf-8", buffering=1024 * 1024) as stream:
        writer = csv.writer(stream)
        writer.writerow(("url_id", "trust_seed", "ancestor_closure_size"))
        for index, (value, ancestor_count) in enumerate(zip(values, closure_counts)):
            tic = time.perf_counter()
            writer.writerow((index, f"{value:.8f}", int(ancestor_count)))
            if index < LATENCY_SAMPLE_LIMIT:
                samples.append((time.perf_counter() - tic) * 1000)
        stream.flush()
        os.fsync(stream.fileno())
    return time.perf_counter() - started, path.stat().st_size, samples


def _profile_probe(size: int, seed: int) -> tuple[cProfile.Profile, int]:
    probe_size = min(size, 10_000)
    rng = np.random.default_rng(seed)
    graph = _make_graph(probe_size)
    values = rng.random(probe_size)
    groups, counts, closures = _make_ancestry(probe_size, seed)
    profiler = cProfile.Profile()
    profiler.enable()
    ingested, roots, root_counts, _ = _ingest(
        probe_size, values, groups, counts,
    )
    _ = np.fromiter(
        (len(_close_record(roots[index], int(root_counts[index]), closures))
         for index in range(probe_size)),
        dtype=np.int32, count=probe_size,
    )
    trust, _ = _propagate(graph, ingested)
    delta = np.zeros(probe_size)
    delta[0] = 0.1
    _propagate_delta(graph, trust, delta)
    profiler.disable()
    return profiler, probe_size


def _benchmark_size(
    out: Path, size: int, seed: int, repeats: int, certificate_time_limit: float,
    action_model: dict,
) -> tuple[dict[str, Any], list[dict], list[dict], list[dict], list[dict]]:
    rng = np.random.default_rng(seed)
    seed_values = rng.random(size)
    direct_groups, direct_count, closures = _make_ancestry(size, seed ^ 0xA19)
    graph = _make_graph(size)
    initial_rss = _windows_memory()["process_peak_rss_mb"]
    latency_rows = []
    started = time.perf_counter()
    values, roots, counts, ingest_samples = _ingest(
        size, seed_values, direct_groups, direct_count,
    )
    ingestion_seconds = time.perf_counter() - started
    latency_rows.append(_latency_row(
        size, "ingestion", "per synthetic JSON record", ingest_samples, ingestion_seconds,
    ))

    closure_samples = []
    closure_started = time.perf_counter()
    closure_counts = np.empty(size, dtype=np.int32)
    for index in range(size):
        tic = time.perf_counter()
        closure_counts[index] = len(
            _close_record(roots[index], int(counts[index]), closures),
        )
        if index < LATENCY_SAMPLE_LIMIT:
            closure_samples.append((time.perf_counter() - tic) * 1000)
    closure_seconds = time.perf_counter() - closure_started
    latency_rows.append(_latency_row(
        size, "ancestor_closure", "per URL", closure_samples, closure_seconds,
    ))

    propagation_samples = []
    full_iterations = 0
    trust = np.empty(size, dtype=np.float64)
    for _ in range(repeats):
        tic = time.perf_counter()
        trust, full_iterations = _propagate(graph, values)
        propagation_samples.append((time.perf_counter() - tic) * 1000)
    full_propagation_seconds = statistics.mean(propagation_samples) / 1000
    latency_rows.append(_latency_row(
        size, "full_propagation", "per complete graph solve", propagation_samples,
        sum(propagation_samples) / 1000,
    ))

    changed_seed = np.array(values, copy=True)
    changed_seed[size // 2] = min(1.0, changed_seed[size // 2] + 0.1)
    delta_seed = changed_seed - values
    full_update_samples, incremental_samples = [], []
    incremental_errors, full_update_iterations, incremental_iterations = [], 0, 0
    for _ in range(repeats):
        tic = time.perf_counter()
        full_updated, full_update_iterations = _propagate(graph, changed_seed)
        full_update_samples.append((time.perf_counter() - tic) * 1000)
        tic = time.perf_counter()
        incrementally_updated, incremental_iterations = _propagate_delta(
            graph, trust, delta_seed,
        )
        incremental_samples.append((time.perf_counter() - tic) * 1000)
        incremental_errors.append(float(np.max(np.abs(
            full_updated - incrementally_updated,
        ))))
    incremental_error = max(incremental_errors)
    incremental_equivalent = incremental_error <= 1e-9
    incremental_speedup = (
        statistics.mean(full_update_samples) / statistics.mean(incremental_samples)
        if statistics.mean(incremental_samples) > 0 else None
    )
    latency_rows.append(_latency_row(
        size, "full_recomputation_after_update", "per complete graph solve",
        full_update_samples, sum(full_update_samples) / 1000,
    ))
    latency_rows.append(_latency_row(
        size, "incremental_trust_update", "per update propagation",
        incremental_samples, sum(incremental_samples) / 1000,
    ))
    incremental_rows = [{
        "observed_urls": size,
        "update_node": size // 2,
        "full_seconds": statistics.mean(full_update_samples) / 1000,
        "incremental_seconds": statistics.mean(incremental_samples) / 1000,
        "speedup": incremental_speedup,
        "max_abs_error": incremental_error,
        "full_iterations": full_update_iterations,
        "incremental_iterations": incremental_iterations,
        "equivalent": incremental_equivalent,
    }]

    group_count = min(20, max(8, int(math.ceil(math.log2(size)))))
    certificate_started = time.perf_counter()
    certificate_rows = _certificate_benchmarks(
        size, group_count, seed ^ 0xCE47, certificate_time_limit,
    )
    exact_samples = [row["exact_seconds"] * 1000 for row in certificate_rows]
    relaxed_samples = [row["relaxed_seconds"] * 1000 for row in certificate_rows]
    latency_rows.append(_latency_row(
        size, "exact_certificate_solver", "per direction/budget solve",
        exact_samples, sum(exact_samples) / 1000,
    ))
    latency_rows.append(_latency_row(
        size, "relaxed_certificate_solver", "per direction/budget solve",
        relaxed_samples, sum(relaxed_samples) / 1000,
    ))
    proof_case, _, _ = _make_case(random.Random(seed ^ 0xBEEF), f"proof-{size}")
    proof_samples = []
    for _ in range(repeats):
        tic = time.perf_counter()
        certify(proof_case, 1)
        proof_samples.append((time.perf_counter() - tic) * 1000)
    proof_seconds = time.perf_counter() - certificate_started
    latency_rows.append(_latency_row(
        size, "certificate_proof_check", "per 4-node proof", proof_samples,
        sum(proof_samples) / 1000,
    ))

    action_started = time.perf_counter()
    action_rows, action_latency = _action_benchmarks(size, seed ^ 0xAC71, action_model)
    action_seconds = time.perf_counter() - action_started
    latency_rows.extend(action_latency)

    storage_path = out / "storage" / f"synthetic_evidence_{size}.csv"
    storage_seconds, storage_bytes, storage_samples = _storage_write(
        storage_path, values, closure_counts,
    )
    latency_rows.append(_latency_row(
        size, "storage_write", "per CSV record", storage_samples, storage_seconds,
    ))
    memory = _windows_memory()
    peak_rss = memory["process_peak_rss_mb"]
    rss_delta = (
        max(0.0, float(peak_rss) - float(initial_rss))
        if peak_rss is not None and initial_rss is not None else None
    )
    row = {
        "observed_urls": size,
        "status": "completed",
        "skip_reason": "",
        "workload": "controlled_synthetic",
        "seed": seed,
        "graph_degree_mean": float(np.mean(graph.getnnz(axis=1))),
        "graph_degree_max": int(np.max(graph.getnnz(axis=1))),
        "source_groups": len(closures),
        "ancestor_count_mean": float(np.mean(closure_counts)),
        "ancestor_count_p95": float(np.percentile(closure_counts, 95)),
        "ingestion_seconds": ingestion_seconds,
        "closure_seconds": closure_seconds,
        "full_propagation_seconds": full_propagation_seconds,
        "incremental_propagation_seconds": statistics.mean(incremental_samples) / 1000,
        "incremental_speedup": incremental_speedup,
        "incremental_max_abs_error": incremental_error,
        "incremental_iterations": incremental_iterations,
        "full_iterations": full_iterations,
        "action_selection_seconds": action_seconds,
        "proof_check_seconds": proof_seconds,
        "storage_write_seconds": storage_seconds,
        "storage_bytes": storage_bytes,
        "storage_bytes_per_url": storage_bytes / size,
        "peak_rss_mb": peak_rss,
        "rss_delta_mb": rss_delta,
        "cpu_seconds_per_url": (
            ingestion_seconds + closure_seconds + full_propagation_seconds
            + storage_seconds
        ) / size,
    }
    action_rows = [
        {**entry, "action_stage_seconds": action_seconds}
        for entry in action_rows
    ]
    return row, latency_rows, certificate_rows, incremental_rows, action_rows


def _write_plots(out: Path, scale_rows: list[dict], certificate_rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    completed = [row for row in scale_rows if row["status"] == "completed"]
    fig, axis = plt.subplots(figsize=(8, 5))
    for field, label in (
        ("ingestion_seconds", "Ingestion"),
        ("closure_seconds", "Ancestor closure"),
        ("full_propagation_seconds", "Full propagation"),
        ("incremental_propagation_seconds", "Incremental update"),
        ("storage_write_seconds", "Storage write"),
    ):
        axis.plot(
            [row["observed_urls"] for row in completed],
            [row[field] for row in completed],
            marker="o", label=label,
        )
    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("Observed URLs")
    axis.set_ylabel("Seconds")
    axis.set_title("E19 controlled workload stage runtimes")
    axis.grid(True, which="both", alpha=0.25)
    axis.legend()
    fig.tight_layout()
    fig.savefig(out / "scalability.png", dpi=160)
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(8, 5))
    certificate_sizes = sorted({row["observed_urls"] for row in certificate_rows})
    for size in certificate_sizes:
        rows = [
            row for row in certificate_rows
            if row["observed_urls"] == size and row["direction"] == "down"
        ]
        if rows:
            axis.plot(
                [row["attack_budget"] for row in rows],
                [row["exact_seconds"] for row in rows],
                marker="o", label=f"Exact, N={size}",
            )
            axis.plot(
                [row["attack_budget"] for row in rows],
                [row["relaxed_seconds"] for row in rows],
                marker="x", linestyle="--", label=f"Relaxed, N={size}",
            )
    axis.set_xlabel("Compromised-group budget b")
    axis.set_ylabel("Solver seconds")
    axis.set_title("E19 representative certificate solver costs")
    axis.grid(True, alpha=0.25)
    axis.legend()
    fig.tight_layout()
    fig.savefig(out / "certificate_costs.png", dpi=160)
    plt.close(fig)


def run_e19(
    out_dir: str = "results/E19",
    table_dir: str = "tables",
    sizes: tuple[int, ...] = DEFAULT_SIZES,
    seed: int = 20261919,
    repeats: int = 5,
    certificate_time_limit: float = 2.0,
) -> dict[str, Any]:
    """Run a controlled scale benchmark and explicitly mark resource-limited sizes."""
    sizes = tuple(sizes)
    if (
        not sizes or any(type(size) is not int or size < 64 for size in sizes)
        or tuple(sorted(set(sizes))) != sizes
    ):
        raise ValueError("sizes must be distinct, ascending integers >= 64")
    if type(seed) is not int:
        raise ValueError("seed must be an integer")
    if type(repeats) is not int or repeats < 3:
        raise ValueError("repeats must be an integer >= 3")
    if not math.isfinite(certificate_time_limit) or certificate_time_limit <= 0:
        raise ValueError("certificate_time_limit must be positive and finite")

    out = Path(out_dir)
    tables = Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    hardware = _windows_memory()
    disk_free = shutil.disk_usage(out).free
    requested_sizes = list(sizes)
    scale_rows, latency_rows, certificate_rows, incremental_rows, action_rows = (
        [], [], [], [], []
    )
    outcome_model = fit_outcome_model(seed ^ 0xCA11B, samples_per_class=100)
    skipped = []
    for index, size in enumerate(sizes):
        estimated_peak_bytes = size * 512
        reasons = []
        available = hardware["physical_available_gb"]
        if available is not None and estimated_peak_bytes > available * (1024 ** 3) * 0.5:
            reasons.append("estimated workload memory exceeds half of currently available physical RAM")
        if estimated_peak_bytes * 2 > shutil.disk_usage(out).free:
            reasons.append("estimated storage workload exceeds half of currently available disk")
        if reasons:
            skipped.append({
                "observed_urls": size,
                "status": "skipped_resource_limit",
                "reason": "; ".join(reasons),
                "estimated_peak_working_bytes": estimated_peak_bytes,
            })
            scale_rows.append({
                "observed_urls": size,
                "status": "skipped_resource_limit",
                "skip_reason": "; ".join(reasons),
                "workload": "controlled_synthetic",
                "seed": seed + index,
            })
            continue
        size_started = time.perf_counter()
        size_row, size_latency, size_certificates, size_incremental, size_actions = (
            _benchmark_size(
                out, size, seed + index * 1009, repeats,
                certificate_time_limit, outcome_model,
            )
        )
        size_row["total_wall_seconds"] = time.perf_counter() - size_started
        scale_rows.append(size_row)
        latency_rows.extend(size_latency)
        certificate_rows.extend(size_certificates)
        incremental_rows.extend(size_incremental)
        action_rows.extend(size_actions)

    completed_sizes = [
        row["observed_urls"] for row in scale_rows if row["status"] == "completed"
    ]
    profile_size = max((size for size in completed_sizes if size <= 10_000), default=None)
    profiler_rows = []
    if profile_size is not None:
        profiler, profiled_size = _profile_probe(profile_size, seed ^ 0xC0FFEE)
        profile_path = out / "e19_profile.prof"
        profiler.dump_stats(str(profile_path))
        output = io.StringIO()
        pstats.Stats(profiler, stream=output).sort_stats("cumulative").print_stats(30)
        (out / "e19_profile.txt").write_text(output.getvalue(), encoding="utf-8")
        profiler_rows.append({
            "profiled_urls": profiled_size,
            "profile_file": profile_path.name,
            "profile_scope": "ingestion, ancestry closure, full propagation, incremental update",
            "top_functions": 30,
        })

    _write_csv(out / "scale_summary.csv", scale_rows, CSV_COLUMNS["scale"])
    _write_csv(out / "stage_latency.csv", latency_rows, CSV_COLUMNS["latency"])
    _write_csv(out / "certificate_costs.csv", certificate_rows, CSV_COLUMNS["certificates"])
    _write_csv(out / "incremental_checks.csv", incremental_rows, CSV_COLUMNS["incremental"])
    _write_csv(out / "action_selection.csv", action_rows, (
        "observed_urls", "action_budget", "replicates", "selected_actions",
    "total_selection_seconds", "action_stage_seconds", "working_set_delta_mb",
    ))
    _write_plots(out, scale_rows, certificate_rows)
    row_by_size = {row["observed_urls"]: row for row in scale_rows}
    audit = {
        "experiment": "E19",
        "status": "pass" if (
            completed_sizes
            and all(row["equivalent"] for row in incremental_rows)
            and all(
                row["exact_damage"] is None or row["relaxed_damage_bound"] is None
                or row["relaxed_damage_bound"] + 1e-8 >= row["exact_damage"]
                for row in certificate_rows
            )
        ) else "fail",
        "workload_source": "controlled_synthetic; no external URL, network, or collector data",
        "field_performance_claim": False,
        "requested_sizes": requested_sizes,
        "completed_sizes": completed_sizes,
        "skipped_sizes": skipped,
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor() or "not reported by operating system",
            "logical_cpu_count": os.cpu_count(),
            **hardware,
            "available_disk_gb_at_start": disk_free / (1024 ** 3),
        },
        "workload_definition": {
            "observed_urls": "one synthetic evidence record and graph node per URL",
            "graph": "row-stochastic sparse ring-plus-shortcuts graph; nominal out-degree 4",
            "source_group_distribution": "1-3 direct groups per URL, deterministic cycling; group DAG closure with at most two parents",
            "solver": "representative E07 exact MILP and LP relaxation; group count 8-20 based on log2(URL count), not one solve per URL",
            "propagation": "sparse fixed-point iteration for (1-alpha)r + alpha P x",
            "incremental_update": "fixed-point solve on a localized seed delta against cached prior propagation",
            "latency_percentiles": "per-record sample (first at most 2000) or repeated full-operation timings as labeled; samples and units in stage_latency.csv",
            "solver_and_action_memory": "process working-set deltas before/after each source-group budget or action budget; allocator and process-wide effects prevent interpreting these as isolated peak allocations",
        },
        "certificate_solver_budgets": list(ATTACK_BUDGETS),
        "action_budgets": list(ACTION_BUDGETS),
        "certificate_time_limit_seconds": certificate_time_limit,
        "incremental_correctness": {
            "all_updates_match_full_recomputation": bool(incremental_rows) and all(
                row["equivalent"] for row in incremental_rows
            ),
            "max_absolute_error": max(
                (row["max_abs_error"] for row in incremental_rows), default=None,
            ),
            "tolerance": 1e-9,
        },
        "complexity_approximations": {
            "ingestion": "O(N) records",
            "ancestor_closure": "O(N*A + G+E_g) for N URLs, A direct ancestors and G-group closure DAG",
            "sparse_full_propagation": "O(I*(N+E)) time and O(N+E) graph storage per fixed-point solve",
            "incremental_propagation": "O(I_delta*(N+E)); current implementation iterates a full sparse vector and is not a localized-subgraph algorithm",
            "exact_certificate": "worst-case exponential in source groups; measured MILP runtime is workload/solver dependent",
            "relaxed_certificate": "LP relaxation; polynomial-time theoretical class, practical solver runtime depends on formulation",
            "action_selection": "O(B*A*C) here, where B is action budget, A candidate actions, and C per-candidate scoring/certificate work",
            "storage_write": "O(N) sequential CSV bytes",
        },
        "deployment_limits": {
            "network_collector_overhead": "not measured; benchmark performs no network acquisition",
            "cost_per_protected_url": "scaled ingestion, closure, propagation, and storage CPU seconds and durable CSV bytes per synthetic URL are reported; representative solver, proof-check, and action-selection costs are reported separately; monetary and network costs are unavailable",
            "million_url_rule": "reported only when a 1,000,000-row workload is actually completed; otherwise skipped with resource reason",
            "profiler": profiler_rows,
            "scales": {
                str(size): {
                    "status": row_by_size[size]["status"],
                    "runtime_seconds": row_by_size[size].get("total_wall_seconds"),
                    "storage_bytes": row_by_size[size].get("storage_bytes"),
                }
                for size in requested_sizes
            },
        },
        "pass_criteria": {
            "incremental_equals_full_within_tolerance": bool(incremental_rows) and all(
                row["equivalent"] for row in incremental_rows
            ),
            "relaxed_damage_bounds_dominate_exact": all(
                row["exact_damage"] is None or row["relaxed_damage_bound"] is None
                or row["relaxed_damage_bound"] + 1e-8 >= row["exact_damage"]
                for row in certificate_rows
            ),
            "only_completed_sizes_used_for_plots_and_claims": True,
            "unmeasured_network_overhead_explicit": True,
            "status": "pass" if (
                completed_sizes and incremental_rows
                and all(row["equivalent"] for row in incremental_rows)
            ) else "fail",
        },
        "runtime_seconds": sum(
            row.get("total_wall_seconds", 0.0) for row in scale_rows
        ),
    }
    (out / "audit.json").write_text(
        json.dumps(audit, indent=2, allow_nan=False) + "\n", encoding="utf-8",
    )
    _write_manifest(out)
    _write_csv(tables / "e19_scale_summary.csv", scale_rows, CSV_COLUMNS["scale"])
    return audit
