#!/usr/bin/env python3
"""
Force re-run of BOFuzz static feature extraction over all fuzzer binaries in
manifest.json. Copy of oss-fuzz/scripts/extract_features_batch.py with an
added --force flag: when set, existing *_statistics.json files are ignored
so every binary is re-extracted (needed after the I03 const-data fix).
"""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple


def load_tasks(binaries_dir: Path) -> List[Tuple[str, str]]:
    manifest = binaries_dir / "manifest.json"
    if not manifest.exists():
        print(f"[ERROR] manifest not found: {manifest}", file=sys.stderr)
        return []

    data = json.loads(manifest.read_text())
    tasks = []
    for project in sorted(data):
        for fuzzer in data[project]:
            tasks.append((project, fuzzer))
    return tasks


def run_one(
    project: str,
    fuzzer: str,
    binaries_dir: Path,
    results_dir: Path,
    extractor: Path,
    ida_dir: Path,
    timeout: int,
    force: bool,
) -> Tuple[str, str, int, str, float]:
    binary = binaries_dir / project / fuzzer
    out_dir = results_dir / project / fuzzer
    stats_file = out_dir / f"{fuzzer}_statistics.json"

    if stats_file.exists() and not force:
        return project, fuzzer, 0, "skipped", 0.0

    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "extract.log"

    import time
    t0 = time.time()

    cmd = [
        sys.executable,
        str(extractor),
        "--idapro",
        "--ida-dir",
        str(ida_dir),
        "--input-file",
        str(binary),
        "--output-dir",
        str(out_dir),
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        elapsed = time.time() - t0
        log_file.write_text(proc.stdout or "")
        if proc.returncode != 0:
            return project, fuzzer, proc.returncode, "failed", elapsed
        if not stats_file.exists():
            return project, fuzzer, 0, "no_stats", elapsed
        return project, fuzzer, 0, "ok", elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        log_file.write_text(f"[TIMEOUT] exceeded {timeout}s\n")
        return project, fuzzer, 124, "timeout", elapsed
    except Exception as e:
        elapsed = time.time() - t0
        log_file.write_text(f"[EXCEPTION] {e}\n")
        return project, fuzzer, 1, "exception", elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--extractor",
        default="/data/zym/BOFuzz/static_analysis/features_extractor.py",
    )
    parser.add_argument("--ida-dir", default="/data/zym/ida-pro-9.3")
    parser.add_argument("--binaries-dir", default="/data/zym/oss-fuzz/temp")
    parser.add_argument("--results-dir", default="/data/zym/oss-fuzz/temp/results")
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--project",
        action="append",
        dest="only_projects",
        help="Only process one project. Can be used multiple times.",
    )
    args = parser.parse_args()

    binaries_dir = Path(args.binaries_dir)
    results_dir = Path(args.results_dir)
    extractor = Path(args.extractor)
    ida_dir = Path(args.ida_dir)

    if not extractor.exists():
        print(f"[ERROR] extractor not found: {extractor}", file=sys.stderr)
        return 1

    tasks = load_tasks(binaries_dir)
    if args.only_projects:
        tasks = [t for t in tasks if t[0] in args.only_projects]

    print(f"[INFO] Tasks: {len(tasks)}")
    print(f"[INFO] Workers: {args.workers}")
    print(f"[INFO] Force: {args.force}")

    counts = {"ok": 0, "failed": 0, "timeout": 0, "skipped": 0, "no_stats": 0, "exception": 0}
    failed_list = []

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                run_one,
                project,
                fuzzer,
                binaries_dir,
                results_dir,
                extractor,
                ida_dir,
                args.timeout,
                args.force,
            ): (project, fuzzer)
            for project, fuzzer in tasks
        }

        for future in as_completed(futures):
            project, fuzzer = futures[future]
            try:
                p, f, rc, status, elapsed = future.result()
            except Exception as e:
                print(f"[EXCEPTION] {project}/{fuzzer}: {e}")
                counts["exception"] += 1
                failed_list.append(f"{project}/{fuzzer}")
                continue

            counts[status] = counts.get(status, 0) + 1
            if status == "ok":
                print(f"[OK {elapsed:6.1f}s] {p}/{f}")
            elif status == "skipped":
                print(f"[SKIP] {p}/{f}")
            else:
                print(f"[{status.upper()} {elapsed:6.1f}s] {p}/{f}")
                failed_list.append(f"{p}/{f}")

    print("\n========== SUMMARY ==========")
    for k in sorted(counts):
        print(f"{k:10s}: {counts[k]}")
    if failed_list:
        print("\nFailed:")
        for x in failed_list:
            print(f"  - {x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
