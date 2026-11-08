import os
import uuid
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "csv"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB limit

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload_file():
    # The form field must be named "file"
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "error": f"File type not allowed. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
        }), 400

    # Sanitize the name, then prefix with a UUID to avoid collisions/overwrites
    original_name = secure_filename(file.filename)
    if not original_name:
        return jsonify({"error": "Invalid filename"}), 400

    stored_name = f"{uuid.uuid4().hex}_{original_name}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))

    return jsonify({
        "message": "File uploaded successfully",
        "original_filename": original_name,
        "stored_filename": stored_name,
    }), 201


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "File exceeds the 16 MB size limit"}), 413


if __name__ == "__main__":
    app.run(debug=True)