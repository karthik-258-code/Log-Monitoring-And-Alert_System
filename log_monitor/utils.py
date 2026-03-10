"""Utility helpers used across the project."""

from pathlib import Path


def ensure_data_dir() -> Path:
    """Ensure that the data directory exists and return its path."""

    workspace_root = Path(__file__).resolve().parents[1]
    data_dir = workspace_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def read_file_lines(path: Path):
    """Yield stripped lines from a file."""

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n")
