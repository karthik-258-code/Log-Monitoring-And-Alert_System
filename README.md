# Server Log Monitoring and Alert System

A beginner-to-intermediate Python project to read, parse, store, analyze, and alert on server log data.

## 🚀 Features

- Reads common log formats (Apache access logs, system logs)
- Parses log entries to extract timestamps, IP addresses, error codes, and messages
- Stores parsed log records in a SQLite database (`data/logs.db`)
- Detects suspicious patterns, including:
  - Repeated failed login attempts
  - High error rates
  - Suspicious IP activity
- Provides summary statistics:
  - Total logs processed
  - Error frequency over time
  - Most common IP addresses
- Offers a simple CLI dashboard to query logs and view alerts
- Generates alerts when suspicious patterns are detected

## 📁 Project Structure

```
/log_monitor
  ├── __init__.py
  ├── cli.py
  ├── parser.py
  ├── database.py
  ├── analysis.py
  ├── report.py
  └── utils.py

/logs
  ├── sample_apache.log
  └── sample_syslog.log

/data
  └── logs.db

README.md
requirements.txt
```

## ▶️ Getting Started

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

2. Run the CLI dashboard:

```bash
python -m log_monitor.cli --help
```

3. Parse sample logs and store them in the database:

```bash
python -m log_monitor.cli ingest --log-file logs/sample_apache.log
python -m log_monitor.cli ingest --log-file logs/sample_syslog.log
```

4. View summary statistics and alerts:

```bash
python -m log_monitor.cli stats
python -m log_monitor.cli alerts
```

## 🧪 Sample Logs

The `logs/` folder contains example Apache and syslog entries for testing.

## 🧩 Extending the Project

You can add additional parsers, integrate with real-time log streams, or build a small web dashboard with Flask.
