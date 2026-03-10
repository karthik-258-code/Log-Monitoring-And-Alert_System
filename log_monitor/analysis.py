"""Analysis routines for detecting suspicious activity and summarizing logs."""

from collections import Counter
from datetime import datetime
from typing import Iterable, Dict, List

import pandas as pd


def load_logs_to_dataframe(rows: Iterable[Dict]) -> pd.DataFrame:
    """Load log rows (e.g., sqlite Row objects) into a pandas DataFrame."""

    # sqlite3.Row behaves like a sequence, so convert to dict first for proper column names.
    if rows and hasattr(rows[0], "keys"):
        rows = [dict(r) for r in rows]

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # Parse timestamps that might be stored as ISO strings
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df


def summarize_logs(df: pd.DataFrame) -> Dict:
    """Generate summary statistics for a log dataset."""

    if df.empty:
        return {
            "total": 0,
            "errors": 0,
            "top_ips": [],
        }

    total = len(df)
    errors = int((df.get("status", 0) >= 400).sum())
    top_ips = (
        df["ip"].dropna().value_counts().head(10).to_dict() if "ip" in df else {}
    )

    return {
        "total": total,
        "errors": errors,
        "top_ips": top_ips,
    }


def detect_failed_logins(df: pd.DataFrame, threshold: int = 5, window_minutes: int = 10) -> List[Dict]:
    """Detect repeated failed login attempts from a single IP.

    This uses heuristics based on HTTP 401/403 responses for web logs.
    """

    if df.empty or "status" not in df or "ip" not in df:
        return []

    window = pd.Timedelta(minutes=window_minutes)

    df = df.copy()
    df = df[df["status"].isin([401, 403])].dropna(subset=["ip", "timestamp"]) 
    df = df.sort_values("timestamp")

    alerts = []
    for ip, group in df.groupby("ip"):
        group = group.reset_index(drop=True)
        for start in range(len(group)):
            end = start + threshold
            if end > len(group):
                break

            start_time = group.loc[start, "timestamp"]
            end_time = group.loc[end - 1, "timestamp"]
            if end_time - start_time <= window:
                alerts.append(
                    {
                        "type": "failed_login",
                        "ip": ip,
                        "count": threshold,
                        "window_minutes": window_minutes,
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                    }
                )
                break

    return alerts


def detect_suspicious_ip_activity(df: pd.DataFrame, threshold: int = 20) -> List[Dict]:
    """Detect IP addresses that generate a high number of log entries."""

    if df.empty or "ip" not in df:
        return []

    counts = df["ip"].value_counts()
    suspects = counts[counts >= threshold]

    return [
        {"type": "high_volume_ip", "ip": ip, "count": int(count)}
        for ip, count in suspects.items()
    ]


def error_trend(df: pd.DataFrame, period: str | None = None) -> pd.Series:
    """Return a time series of error counts aggregated by a time period.

    If `period` is None, the function will pick a reasonable time bin size
    based on the span of the data to avoid a single-point trend chart.
    """

    if df.empty or "timestamp" not in df:
        return pd.Series(dtype=int)

    errors = df[df.get("status", 0) >= 400]
    if errors.empty:
        return pd.Series(dtype=int)

    if period is None:
        span = errors["timestamp"].max() - errors["timestamp"].min()
        if span <= pd.Timedelta(minutes=1):
            period = "10s"
        elif span <= pd.Timedelta(minutes=15):
            period = "1T"
        elif span <= pd.Timedelta(hours=3):
            period = "5T"
        elif span <= pd.Timedelta(hours=12):
            period = "15T"
        elif span <= pd.Timedelta(days=1):
            period = "1H"
        else:
            period = "1D"

    series = (
        errors.set_index("timestamp")
        .resample(period)["status"]
        .count()
        .rename("errors")
    )
    return series
