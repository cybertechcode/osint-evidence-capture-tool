import os
import hashlib
import requests
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
import exifread

import database as db

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-later"

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_exif(filepath):
    metadata = {}
    try:
        with open(filepath, "rb") as f:
            tags = exifread.process_file(f, details=False)
            for tag, value in tags.items():
                if tag not in ("JPEGThumbnail", "TIFFThumbnail"):
                    metadata[tag] = str(value)
    except Exception as e:
        metadata["error"] = str(e)
    return metadata

CALENDAR_URLS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
]

def stamp_with_ots(filepath):
    """Stamps the file via OpenTimestamps calendar server HTTP API. Returns (status, proof_path)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        file_hash = hashlib.sha256(data).digest()

        timestamp = Timestamp(file_hash)
        stamped = False

        for url in CALENDAR_URLS:
            try:
                resp = requests.post(
                    f"{url}/digest",
                    data=file_hash,
                    headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "osint-tool"},
                    timeout=15
                )
                if resp.status_code == 200 and resp.content:
                    ctx = BytesDeserializationContext(resp.content)
                    calendar_ts = Timestamp.deserialize(ctx, file_hash)
                    timestamp.merge(calendar_ts)
                    stamped = True
                    break
            except Exception:
                continue

        if not stamped:
            return "failed", None

        detached = DetachedTimestampFile(OpSHA256(), timestamp)
        ser_ctx = BytesSerializationContext()
        detached.serialize(ser_ctx)

        proof_path = filepath + ".ots"
        with open(proof_path, "wb") as pf:
            pf.write(ser_ctx.getbytes())

        return "stamped", proof_path
    except Exception:
        return "failed", None


@app.route("/")
def index():
    evidence_list = db.get_all_evidence()
    return render_template("index.html", evidence_list=evidence_list)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        source_url = request.form.get("source_url", "")
        description = request.form.get("description", "")
        admiralty_source = request.form.get("admiralty_source", "")
        admiralty_info = request.form.get("admiralty_info", "")

        if not file or file.filename == "":
            flash("No file selected")
            return redirect(url_for("upload"))

        original_filename = secure_filename(file.filename)
        timestamp_prefix = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        stored_filename = f"{timestamp_prefix}_{original_filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)
        file.save(filepath)

        file_hash = compute_sha256(filepath)
        file_size = os.path.getsize(filepath)
        mime_type = file.mimetype

        evidence_id = db.add_evidence(
            original_filename, stored_filename, file_hash, file_size,
            mime_type, source_url, description, admiralty_source, admiralty_info
        )
        db.log_action(evidence_id, "UPLOAD", f"File uploaded, SHA-256: {file_hash}")

        # Extract EXIF if it's an image
        if mime_type and mime_type.startswith("image"):
            metadata = extract_exif(filepath)
            if metadata:
                db.log_action(evidence_id, "METADATA_EXTRACTED", str(metadata))

        # Timestamp with OpenTimestamps
        status, proof_path = stamp_with_ots(filepath)
        db.update_ots_status(evidence_id, status, proof_path)
        db.log_action(evidence_id, "OTS_STAMP", f"Status: {status}")

        flash(f"Evidence #{evidence_id} logged successfully")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))

    return render_template("upload.html")


@app.route("/evidence/<int:evidence_id>")
def evidence_detail(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    audit_entries = db.get_audit_log(evidence_id)
    return render_template("evidence_detail.html", evidence=evidence, audit_entries=audit_entries)


@app.route("/audit-log")
def full_audit_log():
    entries = db.get_audit_log()
    return render_template("audit_log.html", entries=entries) if os.path.exists("templates/audit_log.html") else str([dict(e) for e in entries])


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, port=5000)