#!/usr/bin/env python3

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile_value
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(f"Usage: {sys.argv[0]} RESULTS_CSV [REPORT_CSV]", file=sys.stderr)
        return 2

    results_path = Path(sys.argv[1])
    report_path = (
        Path(sys.argv[2])
        if len(sys.argv) == 3
        else results_path.with_name("kpi-report.csv")
    )
    if not results_path.is_file():
        print(f"Results file not found: {results_path}", file=sys.stderr)
        return 1

    groups: dict[
        tuple[str, str, str, int, int], list[tuple[float, int, float]]
    ] = defaultdict(list)
    with results_path.open(newline="", encoding="utf-8") as results_file:
        for row in csv.DictReader(results_file):
            key = (
                row.get("dataset") or "unknown",
                row["phase"],
                row["codec"],
                int(row["chunk_size"]),
                int(row["workers"]),
            )
            groups[key].append(
                (
                    float(row["elapsed_ms"]),
                    int(row["stored_bytes"]),
                    float(row.get("cpu_util_pct") or math.nan),
                )
            )

    raw_by_dataset_phase: dict[tuple[str, str], tuple[float, float]] = {}
    for (dataset, phase, codec, _chunk_size, _workers), values in groups.items():
        if codec == "raw":
            raw_by_dataset_phase[(dataset, phase)] = (
                statistics.median(value[0] for value in values),
                statistics.fmean(value[1] for value in values),
            )

    fieldnames = [
        "dataset",
        "phase",
        "codec",
        "chunk_size",
        "workers",
        "runs",
        "mean_ms",
        "median_ms",
        "p95_ms",
        "median_cpu_util_pct",
        "stored_mib",
        "compression_ratio",
        "space_saving_pct",
        "speedup_vs_raw",
    ]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str | int]] = []
    for key in sorted(groups):
        dataset, phase, codec, chunk_size, workers = key
        values = groups[key]
        elapsed_values = [value[0] for value in values]
        cpu_values = [value[2] for value in values]
        stored_bytes = statistics.fmean(value[1] for value in values)
        median_ms = statistics.median(elapsed_values)
        raw_median_ms, raw_stored_bytes = raw_by_dataset_phase.get(
            (dataset, phase), (math.nan, math.nan)
        )
        compression_ratio = raw_stored_bytes / stored_bytes
        space_saving_pct = (1 - stored_bytes / raw_stored_bytes) * 100
        speedup = raw_median_ms / median_ms
        rows.append(
            {
                "dataset": dataset,
                "phase": phase,
                "codec": codec,
                "chunk_size": chunk_size,
                "workers": workers,
                "runs": len(values),
                "mean_ms": f"{statistics.fmean(elapsed_values):.3f}",
                "median_ms": f"{median_ms:.3f}",
                "p95_ms": f"{percentile(elapsed_values, 0.95):.3f}",
                "median_cpu_util_pct": f"{statistics.median(cpu_values):.1f}",
                "stored_mib": f"{stored_bytes / (1024 * 1024):.3f}",
                "compression_ratio": f"{compression_ratio:.3f}",
                "space_saving_pct": f"{space_saving_pct:.2f}",
                "speedup_vs_raw": f"{speedup:.3f}",
            }
        )

    phase_order = {"restore": 0, "snapshot": 1}
    rows.sort(
        key=lambda row: (
            str(row["dataset"]),
            phase_order.get(str(row["phase"]), len(phase_order)),
            float(row["median_ms"]),
            str(row["codec"]),
        )
    )

    with report_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    codec_width = max(len("codec"), *(len(str(row["codec"])) for row in rows))
    dataset_width = max(len("dataset"), *(len(str(row["dataset"])) for row in rows))
    print(
        f"{'dataset':<{dataset_width}} {'phase':<8} {'codec':<{codec_width}} "
        f"{'chunk':>9} {'workers':>7} "
        f"{'median ms':>11} {'p95 ms':>11} {'CPU %':>7} {'MiB':>11} {'ratio':>8} "
        f"{'saving %':>9} {'speedup':>8}"
    )
    for row in rows:
        print(
            f"{row['dataset']:<{dataset_width}} {row['phase']:<8} "
            f"{row['codec']:<{codec_width}} {row['chunk_size']:>9} "
            f"{row['workers']:>7} {row['median_ms']:>11} {row['p95_ms']:>11} "
            f"{row['median_cpu_util_pct']:>7} {row['stored_mib']:>11} {row['compression_ratio']:>8} "
            f"{row['space_saving_pct']:>9} {row['speedup_vs_raw']:>8}"
        )
    print(f"\nCSV report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())