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
from matplotlib.colors import ListedColormap, BoundaryNorm
from matplotlib.patches import Rectangle


FEATURES = [f"I{i}" for i in range(8)] + [f"S{i}" for i in range(8)]
DISPLAY_FEATURES = [f"I{i:02d}" for i in range(8)] + [f"S{i:02d}" for i in range(8)]

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


def hex_to_rgb01(hex_color: str):
    """Convert #RRGGBB to RGB values in [0, 1]."""
    hex_color = hex_color.lstrip("#")
    return np.array(
        [int(hex_color[i:i + 2], 16) / 255.0 for i in (0, 2, 4)],
        dtype=float,
    )


def rgb01_to_hex(rgb):
    """Convert RGB values in [0, 1] to #RRGGBB."""
    rgb = np.clip(rgb, 0.0, 1.0)
    return "#" + "".join(f"{int(round(v * 255)):02x}" for v in rgb)


def mix_with_gray(hex_color: str, gray_ratio: float = 0.88, gray_color: str = "#d9d9d9"):
    """
    Desaturate a color by mixing it with gray.

    Larger gray_ratio means more gray and less saturated color.
    Recommended range for paper figures: 0.20--0.35.
    """
    color_rgb = hex_to_rgb01(hex_color)
    gray_rgb = hex_to_rgb01(gray_color)
    mixed_rgb = (1.0 - gray_ratio) * color_rgb + gray_ratio * gray_rgb
    return rgb01_to_hex(mixed_rgb)


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


def make_average_centered_colormap(data: np.ndarray):
    """
    Build a discrete red-white-blue colormap centered at the global average Gini.

    Below average:
        light red -> medium red -> dark red

    Near average:
        off-white

    Above average:
        light blue -> medium blue -> dark blue

    All non-white colors are mixed with gray to reduce saturation and make the
    figure more suitable for paper publication.
    """
    global_avg = float(np.mean(data))
    data_min = float(np.min(data))
    data_max = float(np.max(data))

    lower_span = max(global_avg - data_min, 1e-12)
    upper_span = max(data_max - global_avg, 1e-12)

    # Values within this absolute distance from the global average are shown as off-white.
    # Larger value means a wider "near average" band.
    white_band = 0.06

    lower_white = max(data_min, global_avg - white_band)
    upper_white = min(data_max, global_avg + white_band)

    boundaries = [
        data_min - 1e-9,
        global_avg - 2.0 * lower_span / 3.0,
        global_avg - 1.0 * lower_span / 3.0,
        lower_white,
        upper_white,
        global_avg + 1.0 * upper_span / 3.0,
        global_avg + 2.0 * upper_span / 3.0,
        data_max + 1e-9,
    ]

    # Ensure boundaries are strictly increasing.
    boundaries = np.asarray(boundaries, dtype=float)
    boundaries = np.maximum.accumulate(boundaries + np.arange(len(boundaries)) * 1e-10)

    # Base red-white-blue colors.
    base_colors = [
        "#8b0000",  # dark red: far below average
        "#c43c39",  # medium red
        "#f4a3a3",  # light red
        "#eeeeee",  # near average / "#ffffff"
        "#9ecae1",  # light blue
        "#4292c6",  # medium blue
        "#084594",  # dark blue: far above average
    ]

    # Increase this for more gray / less saturation.
    # Recommended range: 0.20--0.35.
    gray_ratio = 0.6
    gray_color = "#d9d9d9"

    colors = [
        mix_with_gray(base_colors[0], gray_ratio, gray_color),
        mix_with_gray(base_colors[1], gray_ratio, gray_color),
        mix_with_gray(base_colors[2], gray_ratio, gray_color),
        "#eeeeee",  # near average: off-white instead of pure white
        mix_with_gray(base_colors[4], gray_ratio, gray_color),
        mix_with_gray(base_colors[5], gray_ratio, gray_color),
        mix_with_gray(base_colors[6], gray_ratio, gray_color),
    ]

    cmap = ListedColormap(colors)
    norm = BoundaryNorm(boundaries, cmap.N)

    return cmap, norm, global_avg, boundaries


def plot_heatmap(targets, data, out_svg: Path, out_pdf: Path):
    n_targets, n_features = data.shape

    fig_width = 10.2
    fig_height = max(5.2, 0.38 * n_targets + 1.8)

    plt.rcParams.update({
        "font.size": 9,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })

    cmap, norm, global_avg, boundaries = make_average_centered_colormap(data)

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

    # ax.set_title(
    #     "Gini Coefficients of BB-level Static Features",
    #     fontsize=16,
    #     fontweight="bold",
    #     pad=12,
    # )

    # Light grid lines between cells.
    ax.set_xticks(np.arange(-0.5, n_features, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n_targets, 1), minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=0.7)
    ax.tick_params(which="minor", bottom=False, left=False)

    # Highlight selected core features.
    selected_indices = [i for i, f in enumerate(FEATURES) if f in SELECTED_FEATURES]
    for idx in selected_indices:
        ax.add_patch(
            Rectangle(
                (idx - 0.5, -0.5),
                1,
                n_targets,
                fill=False,
                edgecolor="black",
                linewidth=1.4,
            )
        )

    # Bold selected feature tick labels.
    for tick_label, feature in zip(ax.get_xticklabels(), FEATURES):
        if feature in SELECTED_FEATURES:
            tick_label.set_fontweight("bold")

    # Discrete colorbar.
    cbar = fig.colorbar(
        im,
        ax=ax,
        fraction=0.035,
        pad=0.02,
        boundaries=boundaries,
    )
    # cbar.set_label("Gini coefficient", fontsize=11, fontweight="bold")
    # cbar.ax.tick_params(labelsize=9)

    # Show min, global average, and max.
    cbar.set_ticks([data.min(), global_avg, data.max()])
    cbar.set_ticklabels([
        f"{data.min():.2f}",
        f"avg={global_avg:.2f}",
        f"{data.max():.2f}",
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

