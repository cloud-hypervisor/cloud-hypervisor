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
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} RESULTS_CSV", file=sys.stderr)
        return 2

    results_path = Path(sys.argv[1])
    if not results_path.is_file():
        print(f"Results file not found: {results_path}", file=sys.stderr)
        return 1

    groups: dict[tuple[str, str, str, str, str], list[tuple[float, float]]] = (
        defaultdict(list)
    )
    with results_path.open(newline="", encoding="utf-8") as results_file:
        for row in csv.DictReader(results_file):
            key = (
                row.get("dataset") or "unknown",
                row["phase"],
                row["codec"],
                row["chunk_size"],
                row["workers"],
            )
            groups[key].append(
                (float(row["elapsed_ms"]), float(row.get("cpu_util_pct") or math.nan))
            )

    dataset_width = max(len("dataset"), *(len(key[0]) for key in groups))
    codec_width = max(len("codec"), *(len(key[2]) for key in groups))
    print(
        f"{'dataset':<{dataset_width}} {'phase':<8} {'codec':<{codec_width}} "
        f"{'chunk':>10} {'workers':>7} "
        f"{'runs':>5} {'mean_ms':>12} {'median_ms':>12} {'p95_ms':>12} "
        f"{'min_ms':>12} {'max_ms':>12} {'cpu_med%':>10}"
    )
    phase_order = {"restore": 0, "snapshot": 1}
    sorted_groups = sorted(
        groups.items(),
        key=lambda item: (
            item[0][0],
            phase_order.get(item[0][1], len(phase_order)),
            statistics.median(value[0] for value in item[1]),
            item[0][2:],
        ),
    )
    for key, values in sorted_groups:
        dataset, phase, codec, chunk, workers = key
        elapsed_values = [value[0] for value in values]
        cpu_values = [value[1] for value in values]
        metrics = (
            statistics.fmean(elapsed_values),
            statistics.median(elapsed_values),
            percentile(elapsed_values, 0.95),
            min(elapsed_values),
            max(elapsed_values),
        )
        print(
            f"{dataset:<{dataset_width}} {phase:<8} {codec:<{codec_width}} "
            f"{chunk:>10} {workers:>7} "
            f"{len(values):>5} "
            + " ".join(f"{metric:12.3f}" for metric in metrics)
            + f" {statistics.median(cpu_values):10.1f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())