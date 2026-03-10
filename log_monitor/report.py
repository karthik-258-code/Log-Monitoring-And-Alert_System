"""Reporting and visualization helpers."""

from __future__ import annotations

import matplotlib.pyplot as plt


def plot_error_trend(series, title: str = "Error Trend"):
    """Plot a simple error trend chart using matplotlib."""

    if series.empty:
        print("No error data to plot.")
        return

    ax = series.plot(kind="line", marker="o")
    ax.set_title(title)
    ax.set_xlabel("Time")
    ax.set_ylabel("Error Count")

    # Avoid a singular x-axis when only one timestamp exists
    ax.margins(x=0.05)

    plt.tight_layout()
    plt.show()
