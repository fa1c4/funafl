#!/usr/bin/env python3
"""
Plot Gini heatmap for BB-level static features.

Input:
    eval/results/gini_statistics_table.md

Outputs:
    eval/results/features_heatmap.svg
    eval/results/features_heatmap.pdf

Run from BOFuzz root:
    python3 eval/src/plot_gini_heatmap.py
"""

from pathlib import Path
import sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize, ListedColormap
from matplotlib.patches import Rectangle


FEATURES = [f"I{i}" for i in range(8)] + [f"S{i}" for i in range(8)]
DISPLAY_FEATURES = [f"I{i:01d}" for i in range(8)] + [f"S{i:01d}" for i in range(8)]

# Selected Gini-derived guiding core.
SELECTED_FEATURES = {"I1", "I4", "I5", "I6", "S5", "S6", "S7"}

TARGET_DISPLAY_NAMES = {
    "bloaty": "bloaty",
    "curl": "curl",
    "freetype2": "freetype2",
    "harfbuzz": "harfbuzz",
    "lcms": "lcms",
    "mbedtls": "mbedtls",
    "openthread": "openthread",
    "proj4": "proj4",
    "re2": "re2",
    "sqlite3": "sqlite3",
    "vorbis": "vorbis",
    "zlib": "zlib",
}


def desaturate_colormap(base_cmap, gray_ratio: float = 0.95, gray_color=(0.82, 0.82, 0.82)):
    """
    Desaturate a colormap by mixing each RGB color with neutral gray.

    gray_ratio:
        0.00 -> original colormap
        0.30 -> mildly desaturated
        0.45 -> paper-like muted style
        0.60 -> strongly gray, less distinguishable
    """
    colors = base_cmap(np.linspace(0.0, 1.0, 256))

    gray = np.array(gray_color, dtype=float)
    colors[:, :3] = (1.0 - gray_ratio) * colors[:, :3] + gray_ratio * gray

    return ListedColormap(colors, name=f"{base_cmap.name}_gray{gray_ratio:.2f}")


def parse_markdown_table(md_path: Path):
    """Parse a GitHub-style markdown table into target names and numeric matrix."""
    if not md_path.exists():
        raise FileNotFoundError(f"Input markdown file not found: {md_path}")

    lines = md_path.read_text(encoding="utf-8").splitlines()

    header = None
    targets = []
    values = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith("|"):
            continue

        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells:
            continue

        # Header row.
        if cells[0].lower() == "benchmark":
            header = cells
            continue

        # Separator row: | --- | --- | ...
        if all(set(cell.replace(":", "").strip()) <= {"-"} for cell in cells):
            continue

        if header is None:
            continue

        if len(cells) != len(header):
            raise ValueError(
                f"Malformed markdown row with {len(cells)} cells, "
                f"expected {len(header)}:\n{raw_line}"
            )

        target = cells[0]
        row = []
        for cell in cells[1:]:
            try:
                row.append(float(cell))
            except ValueError as exc:
                raise ValueError(f"Cannot parse numeric Gini value: {cell}") from exc

        targets.append(target)
        values.append(row)

    if header is None:
        raise ValueError("No markdown table header found. Expected first column: Benchmark")

    parsed_features = header[1:]
    if parsed_features != FEATURES:
        raise ValueError(
            "Unexpected feature columns.\n"
            f"Expected: {FEATURES}\n"
            f"Found:    {parsed_features}"
        )

    if not values:
        raise ValueError("No Gini rows parsed from markdown table.")

    return targets, np.asarray(values, dtype=float)


def make_ylgnbu_colormap(data: np.ndarray):
    """
    Build a desaturated sequential yellow-green-blue colormap.

    Low Gini  -> pale yellow-gray
    Mid Gini  -> muted green/cyan
    High Gini -> muted deep blue

    This keeps the same semantic direction as YlGnBu, but reduces saturation
    for a more serious paper-style figure.
    """
    global_avg = float(np.mean(data))

    base_cmap = plt.get_cmap("YlGnBu")

    # Increase gray_ratio for a more muted, serious style.
    # Recommended: 0.30--0.45.
    cmap = desaturate_colormap(
        base_cmap,
        gray_ratio=0.29,
        gray_color=(0.82, 0.82, 0.82),
    )

    norm = Normalize(vmin=0.0, vmax=1.0)

    return cmap, norm, global_avg


def plot_heatmap(targets, data, out_svg: Path, out_pdf: Path):
    n_targets, n_features = data.shape

    fig_width = 10.2
    fig_height = max(5.2, 0.38 * n_targets + 1.8)

    plt.rcParams.update({
        "font.size": 9,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })

    cmap, norm, global_avg = make_ylgnbu_colormap(data)

    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    im = ax.imshow(
        data,
        aspect="auto",
        interpolation="nearest",
        cmap=cmap,
        norm=norm,
    )

    ax.set_xticks(np.arange(n_features))
    ax.set_xticklabels(
        DISPLAY_FEATURES,
        rotation=45,
        ha="right",
        rotation_mode="anchor",
        fontsize=10,
    )

    y_labels = [TARGET_DISPLAY_NAMES.get(t, t) for t in targets]
    ax.set_yticks(np.arange(n_targets))
    ax.set_yticklabels(y_labels, fontsize=10)

    ax.set_xlabel("Static Features", fontsize=14, fontweight="bold", labelpad=8)
    ax.set_ylabel("FuzzBench Targets", fontsize=14, fontweight="bold", labelpad=8)

    # Bold selected feature tick labels.
    for tick_label, feature in zip(ax.get_xticklabels(), FEATURES):
        if feature in SELECTED_FEATURES:
            tick_label.set_fontweight("bold")

    # Sequential colorbar.
    cbar = fig.colorbar(
        im,
        ax=ax,
        fraction=0.035,
        pad=0.02,
    )

    # Show min theoretical value, global average, and max theoretical value.
    cbar.set_ticks([0.0, global_avg, 1.0])
    cbar.set_ticklabels([
        "0.00",
        f"avg={global_avg:.2f}",
        "1.00",
    ])

    fig.tight_layout()

    out_svg.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_svg, format="svg", bbox_inches="tight")
    fig.savefig(out_pdf, format="pdf", bbox_inches="tight")
    plt.close(fig)


def main():
    script_path = Path(__file__).resolve()
    eval_dir = script_path.parents[1]
    results_dir = eval_dir / "results"

    input_md = results_dir / "gini_statistics_table.md"
    out_svg = results_dir / "features_heatmap.svg"
    out_pdf = results_dir / "features_heatmap.pdf"

    try:
        targets, data = parse_markdown_table(input_md)
        plot_heatmap(targets, data, out_svg, out_pdf)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] Wrote {out_svg}")
    print(f"[OK] Wrote {out_pdf}")


if __name__ == "__main__":
    main()

