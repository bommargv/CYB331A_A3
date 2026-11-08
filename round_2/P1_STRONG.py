import logging
import re
import sqlite3
from typing import Optional

logger = logging.getLogger(__name__)

# fullmatch + \Z semantics: avoids the trailing-newline quirk of "$"
_USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,32}", re.ASCII)


class UserLookupError(Exception):
    """Generic error raised for database failures (no internal details exposed)."""


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    """
    Look up a user by username and return their row, or None if not found.

    Raises:
        ValueError: if the username is not a string of 3-32 letters, digits, or underscores.
        UserLookupError: if a database error occurs (details are logged, not exposed).
    """
    # --- Input validation ---
    if not isinstance(username, str) or not _USERNAME_RE.fullmatch(username):
        # Log a bounded, repr()'d version to prevent log injection / log flooding
        logger.warning("Rejected invalid username input: %r", str(username)[:64])
        raise ValueError("Invalid username: use 3-32 letters, numbers, or underscores.")

    # --- Parameterized query: user data is never concatenated into the SQL ---
    query = "SELECT * FROM users WHERE username = ?"

    cursor = None
    try:
        previous_factory = conn.row_factory
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(query, (username,))
            return cursor.fetchone()
        finally:
            conn.row_factory = previous_factory
    except sqlite3.Error:
        # Full details (including traceback) go to the log only
        logger.exception("Database error while looking up user")
        raise UserLookupError("Unable to complete the request.") from None
    finally:
        if cursor is not None:
            cursor.close()