import hmac
import ipaddress
import os
import platform
import re
import subprocess
from functools import wraps

from flask import Flask, jsonify, request, abort

app = Flask(__name__)

ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]  # set this in your environment

# RFC 1123 hostname: labels of letters/digits/hyphens, no leading/trailing hyphen
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(token, ADMIN_TOKEN):
            abort(401)
        return f(*args, **kwargs)
    return wrapper


def is_valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


@app.post("/admin/ping")
@admin_required
def ping_host():
    data = request.get_json(silent=True) or {}
    host = str(data.get("hostname", "")).strip()

    if not is_valid_host(host):
        return jsonify(error="Invalid hostname or IP address"), 400

    count_flag = "-n" if platform.system() == "Windows" else "-c"
    # List args + no shell=True means the input is never interpreted by a shell.
    # Hostnames matching the regex can't start with "-", so they can't be
    # mistaken for ping options.
    cmd = ["ping", count_flag, "2", host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=False
        )
    except subprocess.TimeoutExpired:
        return jsonify(hostname=host, reachable=False, error="Timed out"), 200
    except FileNotFoundError:
        return jsonify(error="ping is not available on this server"), 500

    return jsonify(
        hostname=host,
        reachable=result.returncode == 0,
        output=result.stdout[-1000:],
    )


if __name__ == "__main__":
    app.run()