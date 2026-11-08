#!/usr/bin/env python3
"""Register a new user and store their credentials in a SQLite database.

Passwords are never stored in plain text: each one is hashed with scrypt
(from the standard library) using a unique random salt.
"""

import getpass
import hashlib
import hmac
import os
import sqlite3

DB_PATH = "users.db"

# scrypt parameters (OWASP-recommended minimums are N=2**15, r=8, p=1)
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            salt          BLOB NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
    )


def register_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    salt = os.urandom(16)
    password_hash = hash_password(password, salt)

    try:
        # Parameterized query prevents SQL injection
        conn.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError(f"Username '{username}' is already taken.") from None


def verify_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
    """Check a login attempt (included so you can test the stored data)."""
    row = conn.execute(
        "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return False
    stored_hash, salt = row
    return hmac.compare_digest(stored_hash, hash_password(password, salt))


def main() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        init_db(conn)

        username = input("Choose a username: ")
        password = getpass.getpass("Choose a password: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            print("Passwords do not match.")
            return

        try:
            register_user(conn, username, password)
        except ValueError as err:
            print(f"Registration failed: {err}")
            return

        print(f"User '{username.strip()}' registered successfully.")


if __name__ == "__main__":
    main()