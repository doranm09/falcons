"""
component_bar_chart.py

A tiny utility to generate a single bar chart of component counts.

- Pure matplotlib (no seaborn).
- One plot per figure.
- No explicit colors set.

Usage (from shell):
    python3 component_bar_chart.py

Or import and call:
    from component_bar_chart import plot_component_counts
"""

from typing import Dict, Optional
import matplotlib.pyplot as plt


def plot_component_counts(
    data: Dict[str, int],
    title: str = "Component Counts",
    out_path: Optional[str] = None,
) -> None:
    """Plot a simple bar chart of component counts.

    Args:
        data: Mapping of component name -> count.
        title: Chart title.
        out_path: If provided, save the figure to this path instead of showing it.
    """
    # --- one plot, matplotlib only, no explicit colors ---
    labels = list(data.keys())
    values = list(data.values())

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values)
    plt.title(title)
    plt.ylabel("Count")
    plt.xlabel("Component")
    plt.xticks(rotation=20, ha="right")

    # annotate bars with their values
    for idx, v in enumerate(values):
        plt.text(idx, v, f"{v}", ha="center", va="bottom")

    plt.tight_layout()

    if out_path:
        plt.savefig(out_path, dpi=150)
        plt.close()
    else:
        plt.show()


if __name__ == "__main__":
    # Example data from the conversation
    counts = {
        "GPWR Workstation": 179,
        "Historian": 77,
        "Pentest": 3261,
        "Control Server": 2195,
    }
    plot_component_counts(
        counts,
        title="Number of Installed Packages",
        out_path="./component_counts.png",
    )
    print("Saved chart to ./component_counts.png")
