#!/usr/bin/env python3
"""Automated PostgreSQL backup script for PhishGuard.

Usage:
    python backup_db.py [backup_dir]

Reads DATABASE_URL from environment (or .env file), runs pg_dump, and
retains only the most recent backups (default: 7).
"""

import os
import sys
import subprocess
import glob
from datetime import datetime
from urllib.parse import urlparse

# Load .env if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MAX_BACKUPS = int(os.environ.get("BACKUP_RETENTION", 7))


def parse_database_url(url):
    """Extract connection params from a PostgreSQL DATABASE_URL."""
    parsed = urlparse(url)
    return {
        "host": parsed.hostname or "localhost",
        "port": str(parsed.port or 5432),
        "user": parsed.username or "phishguard",
        "password": parsed.password or "",
        "dbname": parsed.path.lstrip("/") or "phishguard",
    }


def run_backup(backup_dir):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or not db_url.startswith("postgresql"):
        print("ERROR: DATABASE_URL is not set or is not a PostgreSQL URL.", file=sys.stderr)
        sys.exit(1)

    params = parse_database_url(db_url)
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"phishguard_{timestamp}.dump"
    filepath = os.path.join(backup_dir, filename)

    env = os.environ.copy()
    env["PGPASSWORD"] = params["password"]

    cmd = [
        "pg_dump",
        "--host", params["host"],
        "--port", params["port"],
        "--username", params["user"],
        "--format=custom",
        "--compress=6",
        "--file", filepath,
        params["dbname"],
    ]

    print(f"Backing up {params['dbname']}@{params['host']}:{params['port']} -> {filepath}")

    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: pg_dump failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"Backup complete: {filename} ({size_mb:.1f} MB)")

    # Prune old backups
    existing = sorted(glob.glob(os.path.join(backup_dir, "phishguard_*.dump")))
    if len(existing) > MAX_BACKUPS:
        to_remove = existing[: len(existing) - MAX_BACKUPS]
        for old in to_remove:
            os.remove(old)
            print(f"Pruned old backup: {os.path.basename(old)}")

    print(f"Retaining {min(len(existing), MAX_BACKUPS)} backups in {backup_dir}")


if __name__ == "__main__":
    backup_directory = sys.argv[1] if len(sys.argv) > 1 else "./backups"
    run_backup(backup_directory)
