#!/usr/bin/env python3
"""Regenerate eval/results/gini_statistics_table.md and refresh
eval/statistics/*_statistics.json from the re-extracted benchs outputs."""
import json
import shutil
from pathlib import Path

BENCHS = Path("/data/zym/BOFuzz/benchs")
RESULTS_DIR = Path("/data/zym/BOFuzz/eval/results")
STATISTICS_DIR = Path("/data/zym/BOFuzz/eval/statistics")

FEATURE_LABELS = [f"I{i}" for i in range(8)] + [f"S{i}" for i in range(8)]

ROWS = [
    ("bloaty", "fuzz_target", "bloaty_fuzz_target"),
    ("curl", "curl_fuzzer_http", "curl_curl_fuzzer_http"),
    ("freetype2", "ftfuzzer", "freetype2_ftfuzzer"),
    ("harfbuzz", "hb-shape-fuzzer", "harfbuzz_hb-shape-fuzzer"),
    ("lcms", "cms_transform_fuzzer", "lcms_cms_transform_fuzzer"),
    ("mbedtls", "fuzz_dtlsclient", "mbedtls_fuzz_dtlsclient"),
    ("openthread", "ot-ip6-send-fuzzer", "openthread_ot-ip6-send-fuzzer"),
    ("proj4", "proj_crs_to_crs_fuzzer", "proj4_proj_crs_to_crs_fuzzer"),
    ("re2", "fuzzer", "re2_fuzzer"),
    ("sqlite3", "ossfuzz", "sqlite3_ossfuzz"),
    ("vorbis", "decode_fuzzer", "vorbis_decode_fuzzer"),
    ("zlib", "zlib_uncompress_fuzzer", "zlib_zlib_uncompress_fuzzer"),
    ("libpng", "libpng_read_fuzzer", "libpng_libpng_read_fuzzer"),
    ("libxml2", "xml", "libxml2_xml"),
    ("openssl", "x509", "openssl_x509"),
]


def ginis_from_stats(stats_path: Path):
    data = json.loads(stats_path.read_text())
    out = {}
    for feature in data.get("features", []):
        fid = feature.get("feature_id", "")
        label = fid
        if len(str(fid)) >= 2 and str(fid)[0] in {"I", "S"}:
            try:
                label = f"{fid[0]}{int(fid[1:])}"
            except ValueError:
                pass
        if label in FEATURE_LABELS:
            out[label] = float(feature.get("gini_strength", 0.0))
    return out


def main():
    lines = ["# Gini Statistics", ""]
    header = "| Benchmark | " + " | ".join(FEATURE_LABELS) + " |"
    sep = "| --- |" + " --- |" * len(FEATURE_LABELS)
    lines.append(header)
    lines.append(sep)

    for project, binary, fuzzbench_name in ROWS:
        stats_path = BENCHS / project / f"{binary}_statistics.json"
        if not stats_path.exists():
            print(f"[WARN] missing {stats_path}")
            continue
        g = ginis_from_stats(stats_path)
        cells = [f"{g.get(f, 0.0):.6f}" for f in FEATURE_LABELS]
        lines.append(f"| {project} | " + " | ".join(cells) + " |")

        dest = STATISTICS_DIR / f"{fuzzbench_name}_statistics.json"
        shutil.copyfile(stats_path, dest)
        print(f"[copy] {stats_path} -> {dest}")

    out_path = RESULTS_DIR / "gini_statistics_table.md"
    out_path.write_text("\n".join(lines) + "\n")
    print(f"[+] Wrote {out_path}")


if __name__ == "__main__":
    main()
