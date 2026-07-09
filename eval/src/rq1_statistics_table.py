#!/usr/bin/env python3
"""
Generate the RQ1 statistics table for BOFuzz coverage evaluation.

Run from BOFuzz/eval/src:
  python rq1_statistics_table.py

Inputs:
  ../data/merged_report_data.csv
  ../data/baselines_report_data_alpha.csv

Outputs:
  ../results/rq1_statistics_table.md
  ../results/rq1_final_coverage_summary.csv
  ../results/rq1_statistics_pairwise.csv

Final markdown table layout:
  - First row: fuzzers.
  - First column: targets.
  - Each fuzzer-target cell: final edge coverage mean ± std near 24h.
  - Last statistic columns: p_adj and A12 for BOFuzz vs the strongest baseline
    on that target, where "strongest baseline" means the non-BOFuzz fuzzer with
    the largest mean final edge coverage.

Statistical interpretation:
  - p_adj: one-sided permutation-test p-value for H1: BOFuzz > baseline,
    Holm-adjusted across all BOFuzz-vs-baseline comparisons within the same target.
  - A12: Vargha-Delaney effect size, P(BOFuzz > baseline) + 0.5 P(equal).
  - BOFuzz is considered statistically supported on a target only when it has the
    largest mean final coverage, p_adj < ALPHA, and A12 > 0.5 against the strongest baseline.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
from itertools import combinations
from math import comb
from typing import Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd


# =========================
# Config
# =========================

report_data_paths = [
    "../data/merged_report_data.csv",
    "../data/baselines_report_data_alpha.csv",
    "../data/libafl_report_data.csv",
]

ALPHA = 0.05
MIN_N_REQUIRED = 12

# Use final coverage near the 24h horizon.
# FuzzBench logs are usually every 900s. MAX_FINAL_HOURS=24.25 matches rq1_eval_coverage_charts.py.
MIN_FINAL_HOURS = 23.0
MAX_FINAL_HOURS = 24.25

# Pairwise comparison direction: BOFuzz should be greater than each baseline.
# Exact permutation is used when feasible; otherwise deterministic Monte Carlo is used.
PERMUTATION_RESAMPLES = 10000
EXACT_PERMUTATION_MAX = 50000
RANDOM_SEED = 42

ordered_fuzzers = [
    "AFL++",
    "TortoiseFuzz",
    "K-Schd",
    "WingFuzz",
    "FunFuzz",
    "LibAFL",
    "BOFuzz",
]

fuzzer_whitelist = [
    "aflplusplus",
    "tortoisefuzz",
    "kscheduler_libfuzzer",
    "wingfuzz",
    "funfuzz",
    "libfuzzer",
    "libafl",
    "libfun",
    "bofuzz",
    "funafl",
]

mapping_norm_names = {
    "aflplusplus": "AFL++",
    "tortoisefuzz": "TortoiseFuzz",
    "kscheduler_libfuzzer": "K-Schd",
    "libfuzzer": "K-Schd",
    "wingfuzz": "WingFuzz",
    "funfuzz": "FunFuzz",
    "libafl": "LibAFL",
    "libfun": "BOFuzz",
    "bofuzz": "BOFuzz",
    "funafl": "BOFuzz",
}

benchmark_whitelist = [
    "bloaty_fuzz_target",
    "curl_curl_fuzzer_http",
    "mbedtls_fuzz_dtlsclient",
    "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer",
    "proj4_proj_crs_to_crs_fuzzer",
    "lcms_cms_transform_fuzzer",
    "openthread_ot-ip6-send-fuzzer",
    "zlib_zlib_uncompress_fuzzer",
    "re2_fuzzer",
    "sqlite3_ossfuzz",
    "vorbis_decode_fuzzer",
]

benchmark_display_names = {
    "bloaty_fuzz_target": "bloaty",
    "curl_curl_fuzzer_http": "curl",
    "mbedtls_fuzz_dtlsclient": "mbedtls",
    "freetype2_ftfuzzer": "freetype2",
    "harfbuzz_hb-shape-fuzzer": "harfbuzz",
    "proj4_proj_crs_to_crs_fuzzer": "proj4",
    "lcms_cms_transform_fuzzer": "lcms",
    "openthread_ot-ip6-send-fuzzer": "openthread",
    "zlib_zlib_uncompress_fuzzer": "zlib",
    "re2_fuzzer": "re2",
    "sqlite3_ossfuzz": "sqlite3",
    "vorbis_decode_fuzzer": "vorbis",
}


# =========================
# Statistical helpers
# =========================

def stable_seed(*parts: object) -> int:
    """Deterministic seed independent of Python hash randomization."""
    key = "::".join(str(part) for part in parts)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return RANDOM_SEED + int(digest[:8], 16) % 100000


def vargha_delaney_a12(x: Iterable[float], y: Iterable[float]) -> float:
    """A12 = P(x > y) + 0.5 * P(x == y). x is BOFuzz, y is a baseline."""
    x_arr = np.asarray(list(x), dtype=float)
    y_arr = np.asarray(list(y), dtype=float)
    if len(x_arr) == 0 or len(y_arr) == 0:
        return np.nan

    greater = (x_arr[:, None] > y_arr[None, :]).sum()
    equal = (x_arr[:, None] == y_arr[None, :]).sum()
    return float((greater + 0.5 * equal) / (len(x_arr) * len(y_arr)))


def permutation_pvalue_greater(
    x: Iterable[float],
    y: Iterable[float],
    *,
    n_resamples: int = PERMUTATION_RESAMPLES,
    exact_max: int = EXACT_PERMUTATION_MAX,
    seed: int = RANDOM_SEED,
) -> float:
    """
    One-sided permutation test for H1: mean(x) > mean(y).
    x is BOFuzz, y is a baseline.
    """
    x_arr = np.asarray(list(x), dtype=float)
    y_arr = np.asarray(list(y), dtype=float)
    n_x, n_y = len(x_arr), len(y_arr)
    if n_x < 2 or n_y < 2:
        return np.nan

    observed = float(np.mean(x_arr) - np.mean(y_arr))
    pooled = np.concatenate([x_arr, y_arr])
    n_total = n_x + n_y
    total_combinations = comb(n_total, n_x)

    # Exact permutation test for small cases.
    if total_combinations <= exact_max:
        count = 0
        total = 0
        for idx_tuple in combinations(range(n_total), n_x):
            idx = np.fromiter(idx_tuple, dtype=int)
            mask = np.zeros(n_total, dtype=bool)
            mask[idx] = True
            diff = float(np.mean(pooled[mask]) - np.mean(pooled[~mask]))
            if diff >= observed - 1e-12:
                count += 1
            total += 1
        return float(count / total)

    # Monte Carlo permutation test for larger cases.
    rng = np.random.default_rng(seed)
    count = 0
    for _ in range(n_resamples):
        perm = rng.permutation(pooled)
        diff = float(np.mean(perm[:n_x]) - np.mean(perm[n_x:]))
        if diff >= observed - 1e-12:
            count += 1

    # Pseudocount avoids p=0 from finite Monte Carlo samples.
    return float((count + 1) / (n_resamples + 1))


def holm_adjust(p_values: List[float]) -> List[float]:
    """Holm-Bonferroni adjusted p-values. NaNs are preserved."""
    adjusted = [np.nan] * len(p_values)
    valid = [(idx, p) for idx, p in enumerate(p_values) if not pd.isna(p)]
    if not valid:
        return adjusted

    m = len(valid)
    valid_sorted = sorted(valid, key=lambda item: item[1])

    running_max = 0.0
    for rank, (idx, p) in enumerate(valid_sorted):
        raw_adjusted = (m - rank) * p
        running_max = max(running_max, raw_adjusted)
        adjusted[idx] = min(1.0, running_max)

    return adjusted


def fmt_int(value: float) -> str:
    if pd.isna(value):
        return "—"
    return f"{int(round(float(value))):,}"


def fmt_coverage(mean: float, std: float) -> str:
    if pd.isna(mean):
        return "—"
    if pd.isna(std):
        std = 0.0
    return f"{fmt_int(mean)} ± {fmt_int(std)}"


def fmt_p(p_value: float) -> str:
    if pd.isna(p_value):
        return "—"
    if p_value < 0.001:
        return "<0.001"
    return f"{p_value:.3f}"


def fmt_a12(a12: float) -> str:
    if pd.isna(a12):
        return "—"
    return f"{a12:.2f}"


def markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|")


# =========================
# Data loading and reduction
# =========================

def load_report_data(paths: List[str], script_dir: Path) -> pd.DataFrame:
    frames = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.is_absolute():
            path = (script_dir / path).resolve()

        if not path.exists():
            print(f"[WARN] Missing input CSV: {path}")
            continue

        temp = pd.read_csv(path)
        temp["_input_csv"] = str(path)
        if "source_path" not in temp.columns:
            temp["source_path"] = str(path)
        temp["source_path"] = temp["source_path"].fillna(str(path)).astype(str)
        frames.append(temp)
        print(f"[INFO] Loaded {path} shape={temp.shape}")

    if not frames:
        raise SystemExit("No report data CSV could be loaded.")

    df = pd.concat(frames, ignore_index=True)

    required_cols = {"fuzzer", "benchmark", "time", "edges_covered"}
    missing = required_cols - set(df.columns)
    if missing:
        raise SystemExit(f"Missing required columns in input CSV(s): {sorted(missing)}")

    df["fuzzer"] = df["fuzzer"].astype(str)
    df["benchmark"] = df["benchmark"].astype(str)
    df["time"] = pd.to_numeric(df["time"], errors="coerce")
    df["edges_covered"] = pd.to_numeric(df["edges_covered"], errors="coerce")

    df = df.dropna(subset=["time", "edges_covered"])
    df = df[df["fuzzer"].isin(fuzzer_whitelist)].copy()
    df = df[df["benchmark"].isin(benchmark_whitelist)].copy()

    if df.empty:
        raise SystemExit("No rows left after filtering fuzzers and targets.")

    df["fuzzer_norm"] = df["fuzzer"].map(mapping_norm_names)
    df["target"] = df["benchmark"].map(benchmark_display_names)
    df["_source_id"] = df["source_path"].fillna(df["_input_csv"]).astype(str)

    return df


def select_final_coverage_samples(df: pd.DataFrame) -> pd.DataFrame:
    """Return one final 24h-ish coverage sample per run."""
    min_final_sec = int(round(MIN_FINAL_HOURS * 3600))
    max_final_sec = int(round(MAX_FINAL_HOURS * 3600))

    within_horizon = df[df["time"] <= max_final_sec].copy()
    if within_horizon.empty:
        raise SystemExit("No rows are within the configured final-time horizon.")

    candidate_run_cols = [
        "_source_id",
        "experiment",
        "fuzzer",
        "benchmark",
        "trial_id",
        "time_started",
        "time_ended",
    ]
    run_cols = [col for col in candidate_run_cols if col in within_horizon.columns]

    # Deduplicate exact repeated samples when the same report data is accidentally appended twice.
    dedup_cols = run_cols + ["time", "edges_covered"]
    within_horizon = within_horizon.drop_duplicates(subset=dedup_cols)

    within_horizon = within_horizon.sort_values(run_cols + ["time"])
    final_rows = within_horizon.groupby(run_cols, dropna=False).tail(1).copy()
    final_rows = final_rows[final_rows["time"] >= min_final_sec].copy()

    if final_rows.empty:
        raise SystemExit(
            f"No final samples satisfy time >= {MIN_FINAL_HOURS}h and time <= {MAX_FINAL_HOURS}h."
        )

    return final_rows


# =========================
# Statistics and table construction
# =========================

def compute_coverage_summary(final_rows: pd.DataFrame) -> pd.DataFrame:
    summary = (
        final_rows.groupby(["benchmark", "target", "fuzzer_norm"], dropna=False)["edges_covered"]
        .agg(mean="mean", std="std", n="count")
        .reset_index()
    )
    summary["std"] = summary["std"].fillna(0.0)
    return summary


def compute_pairwise_stats(final_rows: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []

    for benchmark in benchmark_whitelist:
        target = benchmark_display_names[benchmark]
        target_df = final_rows[final_rows["benchmark"] == benchmark]
        bofuzz_values = target_df[target_df["fuzzer_norm"] == "BOFuzz"]["edges_covered"].to_numpy(dtype=float)

        target_rows: List[Dict[str, object]] = []
        raw_p_values: List[float] = []

        for baseline in ordered_fuzzers:
            if baseline == "BOFuzz":
                continue

            baseline_values = target_df[target_df["fuzzer_norm"] == baseline]["edges_covered"].to_numpy(dtype=float)
            a12 = vargha_delaney_a12(bofuzz_values, baseline_values)
            p_raw = permutation_pvalue_greater(
                bofuzz_values,
                baseline_values,
                seed=stable_seed(target, baseline),
            )

            target_rows.append(
                {
                    "benchmark": benchmark,
                    "target": target,
                    "baseline": baseline,
                    "n_bofuzz": int(len(bofuzz_values)),
                    "n_baseline": int(len(baseline_values)),
                    "mean_bofuzz": float(np.mean(bofuzz_values)) if len(bofuzz_values) else np.nan,
                    "mean_baseline": float(np.mean(baseline_values)) if len(baseline_values) else np.nan,
                    "p_raw": p_raw,
                    "A12": a12,
                }
            )
            raw_p_values.append(p_raw)

        adjusted = holm_adjust(raw_p_values)
        for row, p_adjusted in zip(target_rows, adjusted):
            row["p_holm"] = p_adjusted
            row["significant"] = bool(
                not pd.isna(p_adjusted)
                and not pd.isna(row["A12"])
                and p_adjusted < ALPHA
                and row["A12"] > 0.5
            )
            rows.append(row)

    return pd.DataFrame(rows)


def get_summary_value(summary: pd.DataFrame, benchmark: str, fuzzer: str, field: str) -> float:
    row = summary[(summary["benchmark"] == benchmark) & (summary["fuzzer_norm"] == fuzzer)]
    if row.empty:
        return np.nan
    return float(row.iloc[0][field])


def best_fuzzer_for_target(summary: pd.DataFrame, benchmark: str) -> Tuple[str, float]:
    target_summary = summary[summary["benchmark"] == benchmark]
    if target_summary.empty:
        return "—", np.nan
    idx = target_summary["mean"].idxmax()
    row = target_summary.loc[idx]
    return str(row["fuzzer_norm"]), float(row["mean"])


def best_baseline_for_target(summary: pd.DataFrame, benchmark: str) -> Tuple[str, float]:
    target_summary = summary[
        (summary["benchmark"] == benchmark)
        & (summary["fuzzer_norm"] != "BOFuzz")
    ]
    if target_summary.empty:
        return "—", np.nan
    idx = target_summary["mean"].idxmax()
    row = target_summary.loc[idx]
    return str(row["fuzzer_norm"]), float(row["mean"])


def claim_symbol(
    *,
    best_fuzzer: str,
    p_holm: float,
    a12: float,
) -> str:
    if best_fuzzer != "BOFuzz":
        return "✗"
    if pd.isna(p_holm) or pd.isna(a12):
        return "—"
    if p_holm < ALPHA and a12 > 0.5:
        return "✓"
    if a12 > 0.5:
        return "↑"
    return "✗"


def build_markdown_table(summary: pd.DataFrame, pairwise: pd.DataFrame) -> str:
    # Put statistic columns at the end. "Best baseline" is included so p/A12 are unambiguous.
    header = [
        "Target",
        *ordered_fuzzers,
        "Best baseline",
        "p_adj vs best",
        "A12 vs best",
        "Claim",
    ]

    lines = []
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")

    for benchmark in benchmark_whitelist:
        target = benchmark_display_names[benchmark]
        best_fuzzer, best_mean = best_fuzzer_for_target(summary, benchmark)
        best_baseline, _ = best_baseline_for_target(summary, benchmark)

        row = [target]
        for fuzzer in ordered_fuzzers:
            mean = get_summary_value(summary, benchmark, fuzzer, "mean")
            std = get_summary_value(summary, benchmark, fuzzer, "std")
            cell = fmt_coverage(mean, std)
            # Bold the target's highest mean coverage to make the coverage result readable.
            if not pd.isna(mean) and fuzzer == best_fuzzer:
                cell = f"**{cell}**"
            row.append(cell)

        if best_baseline == "—":
            p_holm = np.nan
            a12 = np.nan
        else:
            stat_row = pairwise[
                (pairwise["benchmark"] == benchmark)
                & (pairwise["baseline"] == best_baseline)
            ]
            if stat_row.empty:
                p_holm = np.nan
                a12 = np.nan
            else:
                p_holm = float(stat_row.iloc[0]["p_holm"])
                a12 = float(stat_row.iloc[0]["A12"])

        symbol = claim_symbol(best_fuzzer=best_fuzzer, p_holm=p_holm, a12=a12)
        if symbol == "✓":
            claim = "✓ supported"
        elif symbol == "↑":
            claim = "↑ higher, not significant"
        elif symbol == "✗" and best_fuzzer != "BOFuzz":
            claim = f"✗ best={best_fuzzer}"
        elif symbol == "✗":
            claim = "✗ not supported"
        else:
            claim = "—"

        row.extend([best_baseline, fmt_p(p_holm), fmt_a12(a12), claim])
        lines.append("| " + " | ".join(markdown_escape(x) for x in row) + " |")

    notes = [
        "",
        "Note: fuzzer cells report final edge coverage as mean ± std near 24h. The bold value is the highest mean coverage for that target.",
        f"p_adj is a one-sided permutation test for BOFuzz > the strongest baseline, Holm-adjusted within each target. A12 is Vargha-Delaney effect size for BOFuzz over that baseline.",
        f"Claim is supported only when BOFuzz has the highest mean coverage, p_adj < {ALPHA}, and A12 > 0.5. Run counts are intentionally not shown in the table; the script prints the n-threshold check separately.",
    ]
    return "\n".join(lines + notes)


def print_n_requirement(final_rows: pd.DataFrame) -> None:
    counts = (
        final_rows.groupby(["target", "fuzzer_norm"], dropna=False)
        .size()
        .reset_index(name="n")
    )

    if counts.empty:
        print(f"[N] Recommended minimum n >= {MIN_N_REQUIRED}; no usable groups were found.")
        return

    min_n = int(counts["n"].min())
    insufficient = int((counts["n"] < MIN_N_REQUIRED).sum())
    total = int(len(counts))
    status = "OK" if insufficient == 0 else "WARNING"
    print(
        f"[N] Recommended minimum n >= {MIN_N_REQUIRED} final runs per fuzzer-target; "
        f"current minimum n = {min_n}; groups below threshold = {insufficient}/{total}. [{status}]"
    )


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    out_dir = (script_dir / "../results").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_report_data(report_data_paths, script_dir)
    final_rows = select_final_coverage_samples(df)
    summary = compute_coverage_summary(final_rows)
    pairwise = compute_pairwise_stats(final_rows)
    markdown = build_markdown_table(summary, pairwise)

    md_path = out_dir / "rq1_statistics_table.md"
    summary_csv_path = out_dir / "rq1_final_coverage_summary.csv"
    pairwise_csv_path = out_dir / "rq1_statistics_pairwise.csv"

    md_path.write_text(markdown + "\n", encoding="utf-8")
    summary.to_csv(summary_csv_path, index=False)
    pairwise.to_csv(pairwise_csv_path, index=False)

    print_n_requirement(final_rows)
    print(f"[INFO] Markdown table written to: {md_path}")
    print(f"[INFO] Final coverage summary CSV written to: {summary_csv_path}")
    print(f"[INFO] Pairwise statistics CSV written to: {pairwise_csv_path}")
    print("\n" + markdown)


if __name__ == "__main__":
    main()
