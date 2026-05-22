#!/usr/bin/env python3
#
# Copyright © 2025 Meta Platforms, Inc.
#
# SPDX-License-Identifier: Apache-2.0

"""Download workload assets for Cloud Hypervisor integration tests.

Reads scripts/test_assets.yaml, downloads missing files, and verifies
SHA-1 checksums.  Uses only the Python 3 standard library.

Usage:
    fetch_workloads.py [--arch ARCH] [--test TEST] [--workloads-dir DIR]
                       [--verify-only] [--asset-file FILE] [-j JOBS]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import os
import platform
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_print_lock = threading.Lock()


def parse_yaml(path: Path) -> list[dict]:
    """Minimal parser for the flat asset list in test_assets.yaml.

    Handles only the subset of YAML used by this project: a top-level
    ``assets:`` key containing a list of mappings with scalar and
    flow-sequence values.  Does not handle nested structures, multi-line
    strings, or anchors.
    """
    assets: list[dict] = []
    current: dict | None = None

    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped == "assets:":
                continue
            if stripped.startswith("- "):
                if current is not None:
                    assets.append(current)
                current = {}
                stripped = stripped[2:].strip()
                if not stripped:
                    continue

            if current is None:
                continue

            m = re.match(r"([a-zA-Z_]\w*):\s*(.*)", stripped)
            if not m:
                continue
            key, value = m.group(1), m.group(2)

            # Flow-sequence: [a, b, c]
            seq = re.match(r"\[([^\]]*)\]", value)
            if seq:
                items = [s.strip() for s in seq.group(1).split(",") if s.strip()]
                current[key] = items
            else:
                current[key] = value if value else None

    if current is not None:
        assets.append(current)

    return assets


def sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _fmt_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def _log(msg: str, **kwargs) -> None:
    with _print_lock:
        print(msg, **kwargs)


def _log_err(msg: str) -> None:
    with _print_lock:
        print(msg, file=sys.stderr)


def download(url: str, dest: Path, auth_token: str | None = None,
             retries: int = 3, delay: float = 5.0,
             show_progress: bool = True) -> bool:
    """Download *url* to *dest* with retries.  Returns True on success."""
    tmp = dest.parent / (dest.name + ".part")
    headers = {}
    host = urllib.parse.urlparse(url).hostname or ""
    if auth_token and (host == "github.com" or host.endswith(".github.com")):
        headers["Authorization"] = f"token {auth_token}"

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            _log(f"  Downloading {url} (attempt {attempt}/{retries})")
            t0 = time.monotonic()
            with urllib.request.urlopen(req, timeout=300) as resp, \
                 open(tmp, "wb") as out:
                total = resp.headers.get("Content-Length")
                total = int(total) if total else None
                downloaded = 0
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
                    downloaded += len(chunk)
                    if show_progress:
                        with _print_lock:
                            if total:
                                pct = downloaded * 100 // total
                                print(f"\r  {_fmt_size(downloaded)} / "
                                      f"{_fmt_size(total)}  ({pct}%)",
                                      end="", flush=True)
                            else:
                                print(f"\r  {_fmt_size(downloaded)}",
                                      end="", flush=True)
                elapsed = time.monotonic() - t0
                if show_progress:
                    with _print_lock:
                        print()
                _log(f"  {_fmt_size(downloaded)} in {elapsed:.1f}s")
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            _log_err(f"  Attempt {attempt} failed: {e}")
            tmp.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(delay)
            continue

        tmp.rename(dest)
        return True

    return False


def process_asset(asset: dict, workloads: Path, auth_token: str | None,
                  verify_only: bool, show_progress: bool) -> bool:
    """Process a single asset.  Returns True on success."""
    filename = asset["filename"]
    if ".." in Path(filename).parts:
        _log(f"SKIPPED  {filename}: path traversal in filename")
        return False
    url = asset.get("url")
    expected_sha1 = asset.get("sha1")
    dest = workloads / filename

    if dest.exists():
        if expected_sha1:
            actual = sha1_file(dest)
            if actual != expected_sha1:
                _log(f"MISMATCH {filename}: expected {expected_sha1}, got {actual}")
                if verify_only:
                    return False
                dest.unlink()
            else:
                _log(f"OK       {filename}")
                return True
        else:
            _log(f"OK       {filename} (no checksum)")
            return True

    if verify_only:
        _log(f"MISSING  {filename}")
        return False

    if not url:
        _log(f"MISSING  {filename} (no URL to download from)")
        return False

    if not download(url, dest, auth_token, show_progress=show_progress):
        _log(f"FAILED   {filename}")
        return False

    if expected_sha1:
        actual = sha1_file(dest)
        if actual != expected_sha1:
            _log(f"CORRUPT  {filename}: expected {expected_sha1}, got {actual}")
            dest.unlink()
            return False

    if (asset.get("executable") or "").lower() == "true":
        dest.chmod(0o755)

    _log(f"FETCHED  {filename}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", default=platform.machine(),
                        help="Target architecture (default: host arch)")
    parser.add_argument("--test", dest="test_filter", default=None,
                        help="Only fetch assets for this test group")
    parser.add_argument("--workloads-dir", default=None,
                        help="Directory to store assets (default: ~/workloads)")
    parser.add_argument("--verify-only", action="store_true",
                        help="Check existing files without downloading")
    parser.add_argument("--asset-file", default=None,
                        help="Path to test_assets.yaml (default: alongside this script)")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1,
                        help="Parallel downloads (default: number of CPUs, use 1 to disable)")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    asset_file = Path(args.asset_file) if args.asset_file else script_dir / "test_assets.yaml"

    if not asset_file.exists():
        print(f"Error: asset file not found: {asset_file}", file=sys.stderr)
        return 1

    if args.workloads_dir:
        workloads = Path(args.workloads_dir)
    else:
        workloads = Path.home() / "workloads"

    workloads.mkdir(parents=True, exist_ok=True)

    assets = parse_yaml(asset_file)
    auth_token = os.environ.get("AUTH_DOWNLOAD_TOKEN")

    filtered = []
    for asset in assets:
        arch_list = asset.get("arch") or []
        if arch_list and args.arch not in arch_list:
            continue
        if args.test_filter:
            test_list = asset.get("test") or []
            if test_list and args.test_filter not in test_list:
                continue
        filtered.append(asset)

    if not filtered:
        print(f"No assets match arch={args.arch}"
              + (f" test={args.test_filter}" if args.test_filter else ""))
        return 0

    jobs = max(1, args.jobs)
    show_progress = jobs == 1

    errors = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(process_asset, asset, workloads, auth_token,
                        args.verify_only, show_progress): asset
            for asset in filtered
        }
        for f in concurrent.futures.as_completed(futures):
            try:
                if not f.result():
                    errors += 1
            except Exception as e:
                asset = futures[f]
                _log_err(f"EXCEPTION {asset.get('filename', '?')}: {e}")
                errors += 1

    if errors:
        print(f"\n{errors} error(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
