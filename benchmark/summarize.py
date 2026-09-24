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

    groups: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    with results_path.open(newline="", encoding="utf-8") as results_file:
        for row in csv.DictReader(results_file):
            key = (row["phase"], row["codec"], row["chunk_size"], row["workers"])
            groups[key].append(float(row["elapsed_ms"]))

    header = (
        "phase",
        "codec",
        "chunk",
        "workers",
        "runs",
        "mean_ms",
        "median_ms",
        "p95_ms",
        "min_ms",
        "max_ms",
    )
    print(" ".join(f"{column:>14}" for column in header))
    for key in sorted(groups):
        values = groups[key]
        fields = (*key, str(len(values)))
        metrics = (
            statistics.fmean(values),
            statistics.median(values),
            percentile(values, 0.95),
            min(values),
            max(values),
        )
        print(
            " ".join(f"{field:>14}" for field in fields)
            + " "
            + " ".join(f"{metric:14.3f}" for metric in metrics)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())