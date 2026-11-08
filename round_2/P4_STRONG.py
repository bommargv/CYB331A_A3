#!/usr/bin/env python3
"""Register a new user, storing an Argon2id password hash in SQLite.

Requirements (Python 3.11+):
    pip install argon2-cffi

Usage:
    python register_user.py                 # prompts for everything
    python register_user.py alice_01        # prompts for the password
    python register_user.py --db users.db alice_01
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import re
import sqlite3
import sys

from argon2 import PasswordHasher
from argon2.exceptions import HashingError

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,32}")
PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128

logger = logging.getLogger("registration")

# Argon2id with the library's current recommended default parameters.
# The salt is generated randomly per hash and embedded in the encoded output,
# along with the parameters, so no separate salt column is needed.
_hasher = PasswordHasher()


class RegistrationError(Exception):
    """Raised for any registration failure; the message is safe to show the user."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason  # short code used for logging


def validate_username(username: str) -> None:
    # fullmatch (not match/$) so a trailing newline can't slip through.
    if not USERNAME_RE.fullmatch(username):
        raise RegistrationError(
            "Invalid username: use 3-32 characters, limited to letters "
            "(A-Z, a-z), numbers (0-9), and underscores (_).",
            reason="invalid_username",
        )


def validate_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LEN:
        raise RegistrationError(
            f"Invalid password: must be at least {PASSWORD_MIN_LEN} characters.",
            reason="password_too_short",
        )
    if len(password) > PASSWORD_MAX_LEN:
        raise RegistrationError(
            f"Invalid password: must be at most {PASSWORD_MAX_LEN} characters.",
            reason="password_too_long",
        )


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    try:
        os.chmod(db_path, 0o600)  # owner-only access (best effort on non-POSIX)
    except OSError:
        pass
    return conn


def register_user(conn: sqlite3.Connection, username: str, password: str) -> int:
    """Validate input, hash the password, and insert the user. Returns the new user id."""
    validate_username(username)
    validate_password(password)

    try:
        password_hash = _hasher.hash(password)
    except HashingError as exc:
        # Log only the exception type, never its contents.
        logger.error(
            "Registration failed: reason=hashing_error username=%s error_type=%s",
            username,
            type(exc).__name__,
        )
        raise RegistrationError(
            "Registration failed due to an internal error. Please try again.",
            reason="hashing_error",
        ) from None

    try:
        # Parameterized query prevents SQL injection.
        with conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        raise RegistrationError(
            "That username is already taken. Please choose another.",
            reason="username_taken",
        ) from None
    except sqlite3.Error as exc:
        logger.error(
            "Registration failed: reason=database_error username=%s error_type=%s",
            username,
            type(exc).__name__,
        )
        raise RegistrationError(
            "Registration failed due to a database error. Please try again.",
            reason="database_error",
        ) from None

    return cur.lastrowid


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a new user.")
    parser.add_argument("username", nargs="?", help="desired username")
    parser.add_argument("--db", default="users.db", help="SQLite database path")
    parser.add_argument("--log", default="registration.log", help="log file path")
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    username = args.username if args.username is not None else input("Username: ")
    password = getpass.getpass("Password: ")  # not echoed to the terminal
    confirm = getpass.getpass("Confirm password: ")

    conn = None
    try:
        if password != confirm:
            raise RegistrationError("Passwords do not match.", reason="password_mismatch")
        conn = init_db(args.db)
        user_id = register_user(conn, username, password)
    except RegistrationError as exc:
        # The username is logged only when it is syntactically valid, which
        # prevents log injection through arbitrary user-supplied strings.
        # Passwords and hashes are never logged.
        if exc.reason in ("hashing_error", "database_error"):
            pass  # already logged with details at the point of failure
        elif exc.reason == "invalid_username":
            logger.warning(
                "Registration failed: reason=%s username_length=%d",
                exc.reason,
                len(username),
            )
        elif USERNAME_RE.fullmatch(username):
            logger.warning("Registration failed: reason=%s username=%s", exc.reason, username)
        else:
            logger.warning("Registration failed: reason=%s", exc.reason)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()

    logger.info("Registration succeeded: user_id=%d username=%s", user_id, username)
    print(f"User '{username}' registered successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())