"""Minimal Flask 3 comment app (Python 3.11).

- Accepts a comment from a form and displays it back.
- XSS defence: Jinja2 autoescaping (enabled for render_template_string).
- Validation: 1-500 characters, valid UTF-8, no control characters.
- Validation failures return HTTP 400 and are logged WITHOUT the comment text.

Run:
    pip install "flask>=3,<4"
    python app.py
"""

import logging
import unicodedata

from flask import Flask, render_template_string, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

MIN_LENGTH = 1
MAX_LENGTH = 500
MAX_BODY_BYTES = 16 * 1024  # hard cap on request size (500 chars * 4 bytes fits easily)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("comments")


class ValidationError(Exception):
    """Raised when a submitted comment is invalid.

    `message` is a static, user-safe string. `detail` is for logs only and
    must never contain the comment text itself.
    """

    def __init__(self, code: str, message: str, detail: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def validate_comment(raw: str | None) -> str:
    """Return the comment if valid, otherwise raise ValidationError."""
    if raw is None:
        raise ValidationError("missing_field", "No comment was submitted.")

    # Werkzeug decodes form data as UTF-8 with errors="replace", so invalid
    # byte sequences surface as U+FFFD. Treat that as an encoding failure.
    if "\ufffd" in raw:
        raise ValidationError(
            "invalid_utf8", "Comment must be valid UTF-8 text."
        )

    length = len(raw)  # length in Unicode code points
    if length < MIN_LENGTH:
        raise ValidationError(
            "too_short", f"Comment must be at least {MIN_LENGTH} character."
        )
    if length > MAX_LENGTH:
        raise ValidationError(
            "too_long",
            f"Comment must be at most {MAX_LENGTH} characters.",
            detail=f"length={length}",
        )

    # Reject any Unicode control character (category Cc: U+0000-001F,
    # U+007F-009F), which includes tabs, newlines and NUL.
    for index, ch in enumerate(raw):
        if unicodedata.category(ch) == "Cc":
            raise ValidationError(
                "control_character",
                "Comment must not contain control characters.",
                detail=f"codepoint=U+{ord(ch):04X} index={index}",
            )

    if not raw.strip():
        raise ValidationError("blank", "Comment must not be blank.")

    return raw


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Comments</title>
</head>
<body>
  <h1>Leave a comment</h1>

  {% if error %}
    <p role="alert"><strong>Error:</strong> {{ error }}</p>
  {% endif %}

  <form method="post" action="/" accept-charset="utf-8">
    <label for="comment">Comment (1&ndash;500 characters, single line)</label><br>
    <input id="comment" name="comment" type="text" size="60" required>
    <button type="submit">Submit</button>
  </form>

  {% if comment is not none %}
    <h2>Your comment</h2>
    {# Autoescaping is ON: <, >, &, ' and " are converted to HTML entities. #}
    <p>{{ comment }}</p>
  {% endif %}
</body>
</html>
"""


def render_page(comment: str | None = None, error: str | None = None):
    return render_template_string(PAGE, comment=comment, error=error)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_page()

    raw = request.form.get("comment")
    try:
        comment = validate_comment(raw)
    except ValidationError as exc:
        logger.warning(
            "Rejected comment: reason=%s remote=%s length=%s %s",
            exc.code,
            request.remote_addr,
            len(raw) if raw is not None else "n/a",
            exc.detail,
        )
        return render_page(error=exc.message), 400

    return render_page(comment=comment), 200


@app.errorhandler(BadRequest)
def handle_bad_request(exc: BadRequest):
    # Malformed requests (e.g. unparseable form data) that never reach validation.
    logger.warning(
        "Rejected submission: reason=bad_request remote=%s", request.remote_addr
    )
    return render_page(error="Bad request."), 400


@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(exc: RequestEntityTooLarge):
    logger.warning(
        "Rejected submission: reason=body_too_large remote=%s limit=%d",
        request.remote_addr,
        MAX_BODY_BYTES,
    )
    return render_page(error="Request is too large."), 413


@app.after_request
def set_security_headers(response):
    # Defence in depth on top of output escaping.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)