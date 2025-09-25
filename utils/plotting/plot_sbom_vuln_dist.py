#!/usr/bin/env python3
"""
sbom_stacked.py — make a stacked bar chart of vulnerabilities by host.

Input CSV columns (header required):
  Target,OS,Total,Critical,High,Medium,Low

Examples
--------
# use built-in sample (your numbers from chat)
python sbom_stacked.py -o sbom_stacked_clean.png

# read from CSV and include inconsistent rows anyway
python sbom_stacked.py --input vulns.csv --include-inconsistent -o fig.png

# plot only specific hosts
python sbom_stacked.py --input vulns.csv --only "Control Server" "Pentest" -o fig.png
"""
from __future__ import annotations
import argparse
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from typing import List

SEVERITIES = ["Critical", "High", "Medium", "Low"]
COLORS = {
    "Critical": "tab:red",
    "High":     "tab:orange",
    "Medium":   "tab:green",
    "Low":      "tab:blue",
}


def sample_df() -> pd.DataFrame:
    return pd.DataFrame([
        {"Target":"Control Server",   "OS":"Ubuntu 24.04", "Total":65,  "Critical":0, "High":0,   "Medium":33,  "Low":32},
        {"Target":"Pentest",          "OS":"Ubuntu 20.04", "Total":342, "Critical":0, "High":2,   "Medium":325, "Low":15},
        {"Target":"GPWR Workstation", "OS":"Windows 10",   "Total":776, "Critical":9, "High":546, "Medium":197, "Low":24},
        {"Target": "Historian",       "OS":"Windows 10",   "Total":838, "Critical":12,"High": 592, "Medium":210, "Low": 24}
    ])

def load_df(path: str|None) -> pd.DataFrame:
    if path:
        return pd.read_csv(path).fillna(0)
    return sample_df()

def filter_df(df: pd.DataFrame, only: List[str]|None) -> pd.DataFrame:
    if only:
        df = df[df["Target"].isin(only)]
    return df

def validate(df: pd.DataFrame, include_inconsistent: bool) -> pd.DataFrame:
    sums = df[SEVERITIES].sum(axis=1)
    df = df.copy()
    df["SumOfSeverities"] = sums
    inconsistent = df[df["SumOfSeverities"] != df["Total"]]
    if not inconsistent.empty:
        print("\n[!] Inconsistent rows (SumOfSeverities != Total):")
        print(inconsistent[["Target","OS","Total","SumOfSeverities"]].to_string(index=False))
        if not include_inconsistent:
            print("\n[i] Excluding inconsistent rows from the plot. Use --include-inconsistent to keep them.")
            df = df[df["SumOfSeverities"] == df["Total"]]
    return df

def plot_stacked(df: pd.DataFrame, out_path: str, title: str):
    if df.empty:
        raise SystemExit("No rows to plot after filtering/validation.")

    labels = df["Target"].tolist()
    x = range(len(labels))
    bottoms = [0]*len(labels)

    plt.figure(figsize=(9, 5.5), dpi=150)
    for sev in SEVERITIES:
        vals = df[sev].tolist()
        plt.bar(x, vals, bottom=bottoms, edgecolor="white", linewidth=0.7, label=sev, color=COLORS.get(sev))
        # annotate segment counts
        for i, v in enumerate(vals):
            if v and v >= max(1, 0.03 * df["Total"].iloc[i]):  # skip tiny slivers
                plt.text(i, bottoms[i] + v/2, f"{v}", ha="center", va="center", fontsize=8)
        bottoms = [b+v for b, v in zip(bottoms, vals)]

    # total labels on top
    for i, tot in enumerate(df["Total"].tolist()):
        plt.text(i, tot + max(1, 0.01*tot), f"{tot}", ha="center", va="bottom", fontsize=8)

    # x tick labels: Target (OS)
    xtick_labels = [f"{t}\n({os})" for t, os in zip(df["Target"], df["OS"])]
    plt.xticks(list(x), xtick_labels, rotation=10, ha="right")
    plt.ylabel("Count of vulnerabilities")
    plt.title(title)
    plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    plt.legend(ncol=4, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.12))
    plt.tight_layout()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, bbox_inches="tight")
    print(f"[✓] Saved figure to: {out_path}")

def main():
    ap = argparse.ArgumentParser(description="Stacked bar chart of vulnerabilities by host")
    ap.add_argument("--input", "-i", help="CSV file with columns Target,OS,Total,Critical,High,Medium,Low")
    ap.add_argument("--only", nargs="*", help="Optional list of Target names to include")
    ap.add_argument("--include-inconsistent", action="store_true",
                    help="Keep rows where Critical+High+Medium+Low != Total")
    ap.add_argument("--title", default="Vulnerabilities by Severity per Host")
    ap.add_argument("--output", "-o", default="sbom_stacked_clean.png")
    args = ap.parse_args()

    df = load_df(args.input)
    df = filter_df(df, args.only)
    df = validate(df, include_inconsistent=args.include_inconsistent)
    plot_stacked(df, args.output, args.title)

if __name__ == "__main__":
    main()
