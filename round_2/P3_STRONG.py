"""Admin-only hostname reachability check (Python 3.11, Flask 3).

Run:
    export ADMIN_API_TOKEN="a-long-random-secret"
    flask --app ping_service run

Call:
    curl -X POST http://127.0.0.1:5000/admin/ping \
         -H "Authorization: Bearer $ADMIN_API_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"hostname": "example.com"}'
"""

import hmac
import logging
import os
import re
import shutil
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)
logger = logging.getLogger("ping_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63
PING_TIMEOUT_SECONDS = 5

# Whitelist: letters, digits, periods, hyphens only (ASCII). fullmatch() is used
# so a trailing newline can never slip through, as it can with "$".
HOSTNAME_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?")

# Resolve the ping binary once so PATH manipulation at runtime has no effect.
PING_BIN = shutil.which("ping")


def is_valid_hostname(value: object) -> bool:
    """Return True only for a well-formed hostname made of allowed characters."""
    if not isinstance(value, str) or len(value) > MAX_HOSTNAME_LENGTH:
        return False
    if HOSTNAME_RE.fullmatch(value) is None:
        return False
    # Each label must be 1-63 chars and must not start or end with a hyphen.
    # This also blocks values like "-f" that ping would parse as an option.
    for label in value.split("."):
        if len(label) > MAX_LABEL_LENGTH or LABEL_RE.fullmatch(label) is None:
            return False
    return True


def is_authorized() -> bool:
    """Constant-time bearer token check. Fails closed if no token is configured."""
    expected = os.environ.get("ADMIN_API_TOKEN", "")
    if not expected:
        logger.error("ADMIN_API_TOKEN is not configured; denying all requests")
        return False
    header = request.headers.get("Authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(supplied.encode(), expected.encode())


def log_safe(value: object, limit: int = 100) -> str:
    """repr() escapes newlines/control characters, preventing log forging."""
    return repr(value)[:limit]


@app.post("/admin/ping")
def ping_host():
    if not is_authorized():
        logger.warning("Unauthorized ping request from %s", request.remote_addr)
        return jsonify(error="Unauthorized"), 401

    payload = request.get_json(silent=True)
    hostname = payload.get("hostname") if isinstance(payload, dict) else None

    if not is_valid_hostname(hostname):
        logger.warning(
            "Rejected ping request from %s: invalid hostname %s",
            request.remote_addr,
            log_safe(hostname),
        )
        return jsonify(error="Invalid hostname"), 400

    if PING_BIN is None:
        logger.error("ping executable not found on this system")
        return jsonify(error="Unable to perform check"), 500

    # Argument list + shell=False: the hostname is a single argv element and is
    # never interpreted by a shell. "--" ends option parsing as defence in depth.
    cmd = [PING_BIN, "-c", "1", "-W", "2", "--", hostname]

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("Ping execution timed out for host %s", log_safe(hostname))
        return jsonify(error="Unable to perform check"), 500
    except OSError:
        logger.exception("Ping execution failed for host %s", log_safe(hostname))
        return jsonify(error="Unable to perform check"), 500

    if result.returncode > 1:
        # iputils: 1 = no reply, 2 = other error (e.g. name resolution failure).
        # Log for operators; the client only learns the host was not reachable.
        logger.warning(
            "Ping exited with code %d for host %s", result.returncode, log_safe(hostname)
        )

    return jsonify(hostname=hostname, reachable=result.returncode == 0), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)