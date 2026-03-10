"""SQLite database helpers for storing parsed log records."""

import sqlite3
from pathlib import Path
from typing import Iterable, Dict, Optional

from .utils import ensure_data_dir

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "logs.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Get a SQLite connection and ensure the schema exists."""

    # Ensure the data directory is present before connecting
    ensure_data_dir()

    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row

    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create database tables if they do not exist."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            timestamp TEXT,
            ip TEXT,
            host TEXT,
            process TEXT,
            request TEXT,
            status INTEGER,
            size INTEGER,
            message TEXT,
            raw TEXT
        );
        """
    )
    conn.commit()


def insert_logs(conn: sqlite3.Connection, records: Iterable[Dict]) -> int:
    """Insert multiple parsed log records into the database."""

    insert_sql = """
        INSERT INTO logs (source, timestamp, ip, host, process, request, status, size, message, raw)
        VALUES (:source, :timestamp, :ip, :host, :process, :request, :status, :size, :message, :raw)
        """

    cursor = conn.cursor()
    inserted = 0

    expected_keys = [
        "source",
        "timestamp",
        "ip",
        "host",
        "process",
        "request",
        "status",
        "size",
        "message",
        "raw",
    ]

    for record in records:
        # Ensure all expected keys are present (SQLite binding requires them)
        insert_record = {k: record.get(k) for k in expected_keys}
        cursor.execute(insert_sql, insert_record)
        inserted += 1

    conn.commit()
    return inserted


def query_logs(conn: sqlite3.Connection, where: str = "", params: Optional[dict] = None):
    """Query the logs table with optional filters."""

    sql = "SELECT * FROM logs"
    if where:
        sql += f" WHERE {where}"

    cursor = conn.cursor()
    cursor.execute(sql, params or {})
    return cursor.fetchall()
