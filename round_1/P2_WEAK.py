from flask import Flask, request, render_template_string

app = Flask(__name__)

MAX_COMMENT_LENGTH = 500

# render_template_string uses Jinja2 with autoescaping enabled, so any HTML
# or JavaScript in the comment is displayed as plain text rather than executed.
PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Comment Box</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 3rem auto; padding: 0 1rem; }
    textarea { width: 100%; box-sizing: border-box; padding: .5rem; font: inherit; }
    button { margin-top: .5rem; padding: .5rem 1rem; font: inherit; cursor: pointer; }
    .comment { margin-top: 2rem; padding: 1rem; background: #f4f4f5; border-left: 4px solid #3b82f6; white-space: pre-wrap; }
    .error { color: #b91c1c; margin-top: .5rem; }
  </style>
</head>
<body>
  <h1>Leave a comment</h1>
  <form method="post" action="{{ url_for('index') }}">
    <label for="comment">Your comment</label><br>
    <textarea id="comment" name="comment" rows="4" maxlength="{{ max_length }}" required></textarea>
    <button type="submit">Submit</button>
  </form>

  {% if error %}
    <p class="error">{{ error }}</p>
  {% endif %}

  {% if comment %}
    <h2>You said:</h2>
    <div class="comment">{{ comment }}</div>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    comment = None
    error = None

    if request.method == "POST":
        text = request.form.get("comment", "").strip()
        if not text:
            error = "Please enter a comment."
        elif len(text) > MAX_COMMENT_LENGTH:
            error = f"Comment must be {MAX_COMMENT_LENGTH} characters or fewer."
        else:
            comment = text

    return render_template_string(
        PAGE, comment=comment, error=error, max_length=MAX_COMMENT_LENGTH
    )


if __name__ == "__main__":
    app.run(debug=True)