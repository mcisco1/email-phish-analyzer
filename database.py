import sqlite3
import json
import time
from datetime import datetime, timezone
from config import DATABASE_PATH


def get_conn(db_path=None):
    path = db_path or DATABASE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    conn = get_conn(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            filename TEXT,
            analyzed_at REAL,
            from_address TEXT,
            subject TEXT,
            threat_level TEXT,
            threat_score INTEGER,
            report_json TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyzed_at ON analyses(analyzed_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_level ON analyses(threat_level)")
    conn.commit()
    conn.close()


def save_report(report_dict, db_path=None):
    conn = get_conn(db_path)
    try:
        headers = report_dict.get("headers", {})
        score = report_dict.get("score", {})
        conn.execute("""
            INSERT OR REPLACE INTO analyses
            (id, filename, analyzed_at, from_address, subject, threat_level, threat_score, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_dict["report_id"],
            report_dict["filename"],
            time.time(),
            headers.get("from_address", ""),
            headers.get("subject", ""),
            score.get("level", "clean"),
            score.get("total", 0),
            json.dumps(report_dict),
        ))
        conn.commit()
    finally:
        conn.close()


def get_report(report_id, db_path=None):
    conn = get_conn(db_path)
    try:
        row = conn.execute("SELECT report_json FROM analyses WHERE id=?", (report_id,)).fetchone()
        if row:
            return json.loads(row["report_json"])
        return None
    finally:
        conn.close()


def get_history(limit=50, db_path=None):
    conn = get_conn(db_path)
    try:
        rows = conn.execute("""
            SELECT id, filename, analyzed_at, from_address, subject, threat_level, threat_score
            FROM analyses ORDER BY analyzed_at DESC LIMIT ?
        """, (limit,)).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            # Convert epoch timestamp to human-readable format
            try:
                d["analyzed_at_display"] = datetime.fromtimestamp(
                    d["analyzed_at"], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
            except (TypeError, ValueError, OSError):
                d["analyzed_at_display"] = "Unknown"
            results.append(d)
        return results
    finally:
        conn.close()


def delete_report(report_id, db_path=None):
    conn = get_conn(db_path)
    try:
        cursor = conn.execute("DELETE FROM analyses WHERE id=?", (report_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_stats(db_path=None):
    conn = get_conn(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) as c FROM analyses").fetchone()["c"]
        by_level = {}
        rows = conn.execute("SELECT threat_level, COUNT(*) as c FROM analyses GROUP BY threat_level").fetchall()
        for r in rows:
            by_level[r["threat_level"]] = r["c"]
        avg_score = conn.execute("SELECT AVG(threat_score) as avg FROM analyses").fetchone()["avg"]
        return {
            "total": total,
            "by_level": by_level,
            "avg_score": round(avg_score, 1) if avg_score else 0,
        }
    finally:
        conn.close()


def search_history(query, db_path=None):
    conn = get_conn(db_path)
    try:
        pattern = f"%{query}%"
        rows = conn.execute("""
            SELECT id, filename, analyzed_at, from_address, subject, threat_level, threat_score
            FROM analyses
            WHERE filename LIKE ? OR from_address LIKE ? OR subject LIKE ?
            ORDER BY analyzed_at DESC LIMIT 100
        """, (pattern, pattern, pattern)).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["analyzed_at_display"] = datetime.fromtimestamp(
                    d["analyzed_at"], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
            except (TypeError, ValueError, OSError):
                d["analyzed_at_display"] = "Unknown"
            results.append(d)
        return results
    finally:
        conn.close()


def get_trend_data(days=30, db_path=None):
    conn = get_conn(db_path)
    try:
        cutoff = time.time() - (days * 86400)
        rows = conn.execute("""
            SELECT date(analyzed_at, 'unixepoch') as day, threat_level, COUNT(*) as cnt
            FROM analyses WHERE analyzed_at >= ?
            GROUP BY day, threat_level ORDER BY day
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
