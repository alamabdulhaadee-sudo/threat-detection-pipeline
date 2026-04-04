import sqlite3
from datetime import datetime
from typing import Optional


class AlertDatabase:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                rule_name TEXT,
                severity TEXT,
                source_ip TEXT,
                username TEXT,
                raw_log TEXT,
                description TEXT,
                alerted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS events_processed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                processed_at TEXT,
                file_path TEXT,
                event_count INTEGER
            );
        """)
        self._conn.commit()

    def save_alert(self, alert: dict) -> None:
        self._conn.execute(
            """INSERT INTO alerts
               (timestamp, rule_name, severity, source_ip, username, raw_log, description, alerted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("timestamp", ""),
                alert.get("rule_name", ""),
                alert.get("severity", ""),
                alert.get("source_ip", ""),
                alert.get("username", ""),
                alert.get("raw_log", ""),
                alert.get("description", ""),
                datetime.utcnow().isoformat(),
            ),
        )
        self._conn.commit()

    def get_alerts(self, since: Optional[datetime] = None) -> list:
        if since:
            cursor = self._conn.execute(
                "SELECT * FROM alerts WHERE alerted_at >= ? ORDER BY alerted_at DESC",
                (since.isoformat(),),
            )
        else:
            cursor = self._conn.execute("SELECT * FROM alerts ORDER BY alerted_at DESC")
        return [dict(row) for row in cursor.fetchall()]

    def get_summary_stats(self, since: Optional[datetime] = None) -> dict:
        where = f"WHERE alerted_at >= '{since.isoformat()}'" if since else ""

        total = self._conn.execute(f"SELECT COUNT(*) FROM alerts {where}").fetchone()[0]

        by_rule = {
            row[0]: row[1]
            for row in self._conn.execute(
                f"SELECT rule_name, COUNT(*) FROM alerts {where} GROUP BY rule_name ORDER BY COUNT(*) DESC"
            ).fetchall()
        }

        by_severity = {
            row[0]: row[1]
            for row in self._conn.execute(
                f"SELECT severity, COUNT(*) FROM alerts {where} GROUP BY severity ORDER BY COUNT(*) DESC"
            ).fetchall()
        }

        top_ips = [
            {"source_ip": row[0], "count": row[1]}
            for row in self._conn.execute(
                f"SELECT source_ip, COUNT(*) as cnt FROM alerts {where} GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        ]

        return {
            "total_alerts": total,
            "by_rule": by_rule,
            "by_severity": by_severity,
            "top_source_ips": top_ips,
        }

    def log_processing_run(self, file_path: str, event_count: int) -> None:
        self._conn.execute(
            "INSERT INTO events_processed (processed_at, file_path, event_count) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat(), file_path, event_count),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
