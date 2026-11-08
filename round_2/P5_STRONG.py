"""Secure file upload endpoint (Python 3.11, Flask 3).

Run:   flask --app upload_app run
Test:  curl -F "file=@report.pdf" http://127.0.0.1:5000/upload
"""
import logging
import os
import re
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FILENAME_LEN = 64
CHUNK_SIZE = 64 * 1024
# Extra headroom so multipart boundaries/headers don't trip the request-level
# cap before the exact per-file size check below.
MULTIPART_OVERHEAD = 64 * 1024

# fullmatch (not match/$) so a trailing newline can't sneak through.
FILENAME_RE = re.compile(r"[A-Za-z0-9._-]+")

# Client-facing messages: explain the problem, never reveal server paths.
MESSAGES = {
    "missing_file": "No file was provided.",
    "empty_filename": "Filename must not be empty.",
    "null_byte": "Filename contains an invalid character.",
    "path_separator": "Filename must not contain path separators.",
    "dot_dot": "Filename must not contain '..'.",
    "too_long": f"Filename must be at most {MAX_FILENAME_LEN} characters.",
    "invalid_characters": (
        "Filename may only contain letters, numbers, periods, "
        "underscores, and hyphens."
    ),
    "leading_dot": "Filename must not start with a period.",
    "empty_file": "File is empty.",
    "file_too_large": "File exceeds the 10 MB limit.",
    "path_escape": "Invalid filename.",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + MULTIPART_OVERHEAD

# Resolve once at startup so later containment checks compare like with like.
UPLOAD_DIR = Path(
    os.environ.get("UPLOAD_DIR", Path(app.root_path) / "uploads")
).resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("uploads")


class _TooLarge(Exception):
    pass


def _reject(reason: str, filename: str | None = None):
    """Log the rejection (no server paths) and return an HTTP 400 response."""
    # %r escapes control characters (prevents log injection); truncate so an
    # attacker can't flood the log with a giant filename.
    shown = filename[:100] if isinstance(filename, str) else None
    logger.warning(
        "Upload rejected: reason=%s client=%s filename=%r",
        reason,
        request.remote_addr,
        shown,
    )
    return jsonify(error=MESSAGES[reason]), 400


def validate_filename(name: str | None) -> str | None:
    """Return a rejection reason, or None if the filename is acceptable."""
    if not name:
        return "empty_filename"
    if "\x00" in name:
        return "null_byte"
    if "/" in name or "\\" in name:
        return "path_separator"
    if ".." in name:
        return "dot_dot"
    if len(name) > MAX_FILENAME_LEN:
        return "too_long"
    if not FILENAME_RE.fullmatch(name):
        return "invalid_characters"
    if name.startswith("."):  # also rules out "." and hidden files
        return "leading_dot"
    return None


def resolve_inside_upload_dir(name: str) -> Path | None:
    """Build the target path; return None unless it sits directly in UPLOAD_DIR."""
    target = (UPLOAD_DIR / name).resolve()
    if target.parent != UPLOAD_DIR:
        return None
    return target


def _stream_size(stream) -> int:
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    return size


@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(_exc):
    # Flask raises 413 for oversized requests; the spec asks for 400.
    return _reject("file_too_large")


@app.post("/upload")
def upload():
    file = request.files.get("file")
    if file is None:
        return _reject("missing_file")

    filename = file.filename
    reason = validate_filename(filename)
    if reason:
        return _reject(reason, filename)

    target = resolve_inside_upload_dir(filename)
    if target is None:
        return _reject("path_escape", filename)

    size = _stream_size(file.stream)
    if size == 0:
        return _reject("empty_file", filename)
    if size > MAX_FILE_BYTES:
        return _reject("file_too_large", filename)

    # O_EXCL: never overwrite an existing file (or follow a pre-planted
    # symlink at that name). O_NOFOLLOW adds defense in depth on POSIX.
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(target, flags, 0o640)
    except FileExistsError:
        logger.warning(
            "Upload rejected: reason=already_exists client=%s filename=%r",
            request.remote_addr,
            filename,
        )
        return jsonify(error="A file with that name already exists."), 409
    except OSError as exc:
        # Log only the exception class: messages/tracebacks contain paths.
        logger.error("Upload failed: open error type=%s", type(exc).__name__)
        return jsonify(error="Could not save file."), 500

    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := file.stream.read(CHUNK_SIZE):
                written += len(chunk)
                if written > MAX_FILE_BYTES:  # belt and braces
                    raise _TooLarge
                out.write(chunk)
    except _TooLarge:
        target.unlink(missing_ok=True)
        return _reject("file_too_large", filename)
    except OSError as exc:
        target.unlink(missing_ok=True)
        logger.error("Upload failed: write error type=%s", type(exc).__name__)
        return jsonify(error="Could not save file."), 500

    logger.info(
        "Upload saved: client=%s filename=%r bytes=%d",
        request.remote_addr,
        filename,
        written,
    )
    return jsonify(filename=filename, size=written), 201


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run()