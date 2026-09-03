#!/usr/bin/env python3
"""Re-run fixed features_extractor.py over the benchs/ fuzzer targets."""
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

BENCHS = Path("/data/zym/BOFuzz/benchs")
EXTRACTOR = Path("/data/zym/BOFuzz/static_analysis/features_extractor.py")
IDA_DIR = "/data/zym/ida-pro-9.3"

TARGETS = [
    ("bloaty", "fuzz_target"),
    ("curl", "curl_fuzzer_http"),
    ("freetype2", "ftfuzzer"),
    ("harfbuzz", "hb-shape-fuzzer"),
    ("lcms", "cms_transform_fuzzer"),
    ("libpng", "libpng_read_fuzzer"),
    ("libxml2", "xml"),
    ("mbedtls", "fuzz_dtlsclient"),
    ("openssl", "x509"),
    ("openthread", "ot-ip6-send-fuzzer"),
    ("proj4", "proj_crs_to_crs_fuzzer"),
    ("re2", "fuzzer"),
    ("sqlite3", "ossfuzz"),
    ("vorbis", "decode_fuzzer"),
    ("zlib", "zlib_uncompress_fuzzer"),
]


def run_one(project, fuzzer):
    binary = BENCHS / project / fuzzer
    out_dir = BENCHS / project
    log_file = out_dir / f"{fuzzer}_extract.log"
    t0 = time.time()
    cmd = [
        sys.executable, str(EXTRACTOR), "--idapro", "--ida-dir", IDA_DIR,
        "--input-file", str(binary), "--output-dir", str(out_dir),
    ]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=3600,
        )
        elapsed = time.time() - t0
        log_file.write_text(proc.stdout or "")
        status = "ok" if proc.returncode == 0 else "failed"
        return project, fuzzer, status, elapsed, proc.returncode
    except subprocess.TimeoutExpired:
        return project, fuzzer, "timeout", time.time() - t0, 124
    except Exception as e:
        return project, fuzzer, "exception", time.time() - t0, str(e)


def main():
    results = []
    with ProcessPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(run_one, p, f): (p, f)
            for p, f in TARGETS
        }
        for fut in as_completed(futures):
            p, f = futures[fut]
            p2, f2, status, elapsed, rc = fut.result()
            results.append((p2, f2, status, elapsed, rc))
            print(f"[{status.upper()} {elapsed:6.1f}s] {p2}/{f2} rc={rc}", flush=True)

    bad = [(p, f, st) for p, f, st, _, _ in results if st != "ok"]
    print("\n=== SUMMARY ===")
    print("ok:", sum(1 for r in results if r[2] == "ok"))
    if bad:
        print("bad:", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
