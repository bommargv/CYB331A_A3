import sqlite3
from typing import Optional


def get_user_by_username(db_path: str, username: str) -> Optional[sqlite3.Row]:
    """Look up a user by username and return their row, or None if not found."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # lets you access columns by name
    try:
        cursor = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        )
        return cursor.fetchone()
    finally:
        conn.close()