"""Command line dashboard for the Server Log Monitoring and Alert System."""

import argparse
import sys
from pathlib import Path

from . import database, parser, analysis, report, utils


def ingest_logs(log_file: Path, db_path: Path = None):
    """Read a log file, parse lines, and store them in the database."""

    conn = database.get_connection(db_path)
    parsed = []

    for line in utils.read_file_lines(log_file):
        if not line.strip():
            continue

        record = parser.parse_apache_log_line(line) or parser.parse_syslog_line(line)
        if record:
            parsed.append(record)

    inserted = database.insert_logs(conn, parsed)
    print(f"Ingested {inserted} records from {log_file}")


def show_stats(db_path: Path = None):
    conn = database.get_connection(db_path)
    rows = database.query_logs(conn)
    df = analysis.load_logs_to_dataframe(rows)

    summary = analysis.summarize_logs(df)
    print("\n=== Summary ===")
    print(f"Total logs processed: {summary['total']}")
    print(f"Total errors (HTTP >= 400): {summary['errors']}")

    print("\nTop IP addresses:")
    for ip, count in summary["top_ips"].items():
        print(f"  {ip}: {count}")

    # Plot a simple error trend chart
    series = analysis.error_trend(df)
    if not series.empty:
        print("\nDisplaying error trend chart (close window to continue)...")
        report.plot_error_trend(series)


def show_alerts(db_path: Path = None):
    conn = database.get_connection(db_path)
    rows = database.query_logs(conn)
    df = analysis.load_logs_to_dataframe(rows)

    failed_logins = analysis.detect_failed_logins(df)
    suspicious_ips = analysis.detect_suspicious_ip_activity(df)

    print("\n=== Alerts ===")
    if not failed_logins and not suspicious_ips:
        print("No alerts detected. Continue monitoring.")
        return

    if failed_logins:
        print("\n-- Possible failed login attacks --")
        for alert in failed_logins:
            print(
                f"IP {alert['ip']} had {alert['count']} failed login attempts "
                f"from {alert['start']} to {alert['end']} ({alert['window_minutes']} min window)"
            )

    if suspicious_ips:
        print("\n-- Suspicious IP activity --")
        for item in suspicious_ips:
            print(f"IP {item['ip']} generated {item['count']} log entries")


def main(argv=None):
    parser_ = argparse.ArgumentParser(
        description="Server Log Monitoring and Alert System",
    )

    subparsers = parser_.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Parse log file(s) and insert into the database")
    ingest.add_argument("--log-file", required=True, type=Path, help="Path to a log file")

    subparsers.add_parser("stats", help="Show summary statistics and error trend chart")
    subparsers.add_parser("alerts", help="Show detected alerts")

    args = parser_.parse_args(argv)

    try:
        if args.command == "ingest":
            ingest_logs(args.log_file)
        elif args.command == "stats":
            show_stats()
        elif args.command == "alerts":
            show_alerts()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
