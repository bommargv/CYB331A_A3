#!/usr/bin/env python3
"""Console greeter with strict input validation (Python 3.11+).

Accepts only well-formed UTF-8 text of 1-64 characters with no control
characters. Rejections are logged by reason only; the raw input is never
written to the log.
"""

from __future__ import annotations

import logging
import sys
import unicodedata

MIN_CHARS = 1
MAX_CHARS = 64
MAX_BYTES_PER_CHAR = 4                       # UTF-8 worst case
MAX_LINE_BYTES = MAX_CHARS * MAX_BYTES_PER_CHAR + 2   # + room for "\r\n"
MAX_DRAIN_BYTES = 1024 * 1024                # cap on discarded excess input

LOG_FILE = "greeter.log"

# Rejection reasons (safe to log: they never contain user data).
TOO_LONG_BYTES = "input exceeds maximum byte length"
INVALID_UTF8 = "invalid UTF-8 encoding"
EMPTY = "empty or whitespace-only input"
TOO_LONG_CHARS = "input exceeds maximum character length"
CONTROL_CHARS = "contains control or line/paragraph separator characters"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    encoding="utf-8",
)
log = logging.getLogger("greeter")


def read_line_bounded() -> tuple[bytes, bool]:
    """Read one line from stdin without ever buffering more than a fixed limit.

    Returns (raw_bytes_without_newline, overflowed). If the line is longer than
    MAX_LINE_BYTES, the remainder is discarded in small chunks so it cannot
    exhaust memory or leak into the next read.
    """
    raw = sys.stdin.buffer.readline(MAX_LINE_BYTES)
    overflowed = len(raw) >= MAX_LINE_BYTES and not raw.endswith(b"\n")

    if overflowed:
        drained = 0
        while drained < MAX_DRAIN_BYTES:
            chunk = sys.stdin.buffer.readline(4096)
            drained += len(chunk)
            if not chunk or chunk.endswith(b"\n"):
                break

    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    return raw, overflowed


def has_forbidden_chars(text: str) -> bool:
    """True if text contains control chars (Unicode category Cc) or
    line/paragraph separators (Zl, Zp)."""
    return any(unicodedata.category(ch) in {"Cc", "Zl", "Zp"} for ch in text)


def validate(raw: bytes, overflowed: bool) -> tuple[str | None, str | None]:
    """Validate raw input. Returns (name, None) on success or (None, reason)."""
    if overflowed:
        return None, TOO_LONG_BYTES

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, INVALID_UTF8

    if not text.strip():
        return None, EMPTY
    if len(text) < MIN_CHARS:
        return None, EMPTY
    if len(text) > MAX_CHARS:
        return None, TOO_LONG_CHARS
    if has_forbidden_chars(text):
        return None, CONTROL_CHARS

    return text, None


def main() -> int:
    # Make sure output is UTF-8 so valid non-ASCII names print correctly.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

    sys.stdout.write(f"Enter your name ({MIN_CHARS}-{MAX_CHARS} characters): ")
    sys.stdout.flush()

    try:
        raw, overflowed = read_line_bounded()
    except (KeyboardInterrupt, EOFError):
        print("\nInput cancelled.")
        return 130
    except OSError as exc:
        log.error("stdin read failed: %s", type(exc).__name__)
        print("Error: could not read input.")
        return 1

    if not raw and not overflowed and sys.stdin.closed:
        print("Error: no input received.")
        return 1

    name, reason = validate(raw, overflowed)

    if name is None:
        # Log only the reason and the byte length, never the content.
        log.warning("input rejected: %s (bytes read=%d)", reason, len(raw))
        print(
            f"Error: invalid name. Please enter {MIN_CHARS}-{MAX_CHARS} "
            "characters of valid UTF-8 text with no control characters."
        )
        return 1

    print(f"Hello, {name}! Nice to meet you.")
    return 0


if __name__ == "__main__":
    sys.exit(main())