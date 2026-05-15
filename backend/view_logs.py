# ============================================================
# DLP LOG VIEWER — CLI
# Run from project root:  python backend/view_logs.py [options]
# ============================================================

import os
import sys
import argparse
import sqlite3

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
os.chdir(PROJECT_DIR)
sys.path.insert(0, BACKEND_DIR)

from dlp_engine import CONFIG

ACTION_PREFIX = {
    "BLOCK":      "[BLOCK     ]",
    "QUARANTINE": "[QUARANTINE]",
    "ENCRYPT":    "[ENCRYPT   ]",
    "ALERT":      "[ALERT     ]",
    "ALLOW":      "[ALLOW     ]",
}


def view_logs(action_filter=None, limit=100):
    db_path = CONFIG["db"]
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)

    query = "SELECT time, type, action, source, details FROM logs"
    params = []

    if action_filter and action_filter != "ALL":
        query += " WHERE action = ?"
        params.append(action_filter.upper())

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    if not rows:
        print("No log entries found.")
        return

    print(f"\n{'TIME':<26} {'TYPE':<10} {'ACTION':<12} {'SOURCE':<40} CLASSIFICATION")
    print("-" * 110)

    for time_, type_, action, source, details in rows:
        prefix = ACTION_PREFIX.get(action, f"[{action:<10}]")
        print(f"{time_:<26} {type_:<10} {prefix} {source:<40} {details or ''}")

    print(f"\n{len(rows)} entries shown.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View DLP event logs")
    parser.add_argument("--action", help="Filter: BLOCK, QUARANTINE, ENCRYPT, ALERT, ALLOW")
    parser.add_argument("--limit", type=int, default=100, help="Max rows (default 100)")
    args = parser.parse_args()
    view_logs(action_filter=args.action, limit=args.limit)
