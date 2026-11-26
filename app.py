"""
app.py - Forensically-oriented OSINT acquisition tool (Flask).

Workflow: authenticate -> acquire (file upload OR URL capture) -> SHA-256 ->
OpenTimestamps -> hash-chained audit log -> verify / export.
"""
import os
import io
import json
import sys
import shutil
import socket
import zipfile
import getpass
import hashlib
import ipaddress
import subprocess
import importlib.util
from functools import wraps
from urllib.parse import urlparse, urljoin

import requests
import exifread
from flask import (Flask, request, render_template, redirect, url_for,
                   flash, session, send_file, abort)
from werkzeug.utils import secure_filename
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.notary import PendingAttestation, BitcoinBlockHeaderAttestation
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext

import database as db
import netguard

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ANCHOR_FOLDER = os.path.join(BASE_DIR, "anchors")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ANCHOR_FOLDER, exist_ok=True)


def local_path(stored, folder):
    """Return a usable path for a stored proof/anchor path.

    Older records hold absolute paths from the machine where they were created.
    If that path does not exist (project moved to another folder or computer),
    look for the same file name inside the project's own folder.
    """
    if not stored:
        return None
    if os.path.exists(stored):
        return stored
    name = stored.replace("\\", "/").split("/")[-1]
    candidate = os.path.join(folder, name)
    return candidate if os.path.exists(candidate) else None

MAX_CAPTURE_BYTES = 10 * 1024 * 1024          # 10 MB cap for URL capture
MAX_REDIRECTS = 5
ALLOW_PRIVATE_URLS = os.environ.get("OSINT_ALLOW_PRIVATE", "0") == "1"  # for local testing only
TOOL_NAME = "OSINT-Acquisition-Tool/1.2"

app = Flask(__name__)
# Set OSINT_SECRET_KEY in your environment for real use.
app.secret_key = os.environ.get("OSINT_SECRET_KEY", "dev-secret-key-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

ADMIRALTY_SOURCE = [
    ("A", "A - Completely reliable"), ("B", "B - Usually reliable"),
    ("C", "C - Fairly reliable"), ("D", "D - Not usually reliable"),
    ("E", "E - Unreliable"), ("F", "F - Reliability cannot be judged"),
]
ADMIRALTY_INFO = [
    ("1", "1 - Confirmed by other sources"), ("2", "2 - Probably true"),
    ("3", "3 - Possibly true"), ("4", "4 - Doubtful"),
    ("5", "5 - Improbable"), ("6", "6 - Truth cannot be judged"),
]
EVIDENCE_TYPES = ["Screenshot", "Photograph", "Web page (HTML)", "HTTP headers",
                  "Screenshot (rendered)", "PDF (rendered)", "Document", "Other"]


@app.context_processor
def inject_globals():
    return dict(ADMIRALTY_SOURCE=ADMIRALTY_SOURCE, ADMIRALTY_INFO=ADMIRALTY_INFO,
                EVIDENCE_TYPES=EVIDENCE_TYPES, current_user=session.get("full_name"))


# ------------------------------------------------------------------ helpers
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


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


def valid_admiralty(source, info):
    return source in dict(ADMIRALTY_SOURCE) and info in dict(ADMIRALTY_INFO)


# --------------------------------------------------------------- OpenTimestamps
CALENDAR_URLS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
]


def stamp_with_ots(filepath):
    """Submit the SHA-256 of a file to OpenTimestamps calendars. Returns (status, proof_path)."""
    try:
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).digest()
        timestamp = Timestamp(file_hash)
        stamped = False
        for url in CALENDAR_URLS:
            try:
                resp = requests.post(
                    f"{url}/digest", data=file_hash,
                    headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "osint-tool"},
                    timeout=15,
                )
                if resp.status_code == 200 and resp.content:
                    ctx = BytesDeserializationContext(resp.content)
                    timestamp.merge(Timestamp.deserialize(ctx, file_hash))
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


# Calendars the tool will contact when upgrading a proof. A proof file names its
# own calendar, so only these known OpenTimestamps calendars are trusted (SSRF guard).
TRUSTED_CALENDAR_SUFFIXES = (
    ".calendar.opentimestamps.org",
    ".calendar.eternitywall.com",
    ".calendar.catallaxy.com",
)


def _calendar_allowed(uri):
    u = urlparse(uri)
    host = (u.hostname or "").lower()
    return u.scheme == "https" and any(host.endswith(sfx) for sfx in TRUSTED_CALENDAR_SUFFIXES)


def _walk_attestations(stamp):
    """Yield (sub_timestamp, attestation) for every attestation in a timestamp tree."""
    for att in list(stamp.attestations):
        yield stamp, att
    for _op, sub in list(stamp.ops.items()):
        yield from _walk_attestations(sub)


def _has_bitcoin_attestation(stamp):
    return any(isinstance(a, BitcoinBlockHeaderAttestation) for _s, a in _walk_attestations(stamp))


def upgrade_proof(proof_path):
    """Upgrade a pending .ots proof by asking its calendar(s) for the Bitcoin-anchored path.

    Implemented directly with the `opentimestamps` library (the same way stamping works),
    because the official `ots` client fails to load OpenSSL on Windows (python-bitcoinlib bug).
    Returns (status, message): status is "confirmed", "stamped" (still pending) or None on error.
    """
    try:
        with open(proof_path, "rb") as f:
            detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(f.read()))
    except Exception as e:
        return None, f"Could not read the proof file: {e}"

    if _has_bitcoin_attestation(detached.timestamp):
        return "confirmed", "Proof already contains a Bitcoin block attestation."

    changed, notes = False, []
    pending = [(st, a) for st, a in _walk_attestations(detached.timestamp)
               if isinstance(a, PendingAttestation)]
    for sub, att in pending:
        uri = att.uri if isinstance(att.uri, str) else att.uri.decode()
        if not _calendar_allowed(uri):
            notes.append(f"skipped untrusted calendar {uri}")
            continue
        try:
            resp = requests.get(f"{uri.rstrip('/')}/timestamp/{sub.msg.hex()}",
                                headers={"Accept": "application/vnd.opentimestamps.v1",
                                         "User-Agent": TOOL_NAME}, timeout=15)
        except Exception as e:
            notes.append(f"{uri}: {e.__class__.__name__}")
            continue
        if resp.status_code == 200 and resp.content:
            try:
                sub.merge(Timestamp.deserialize(BytesDeserializationContext(resp.content), sub.msg))
                changed = True
            except Exception as e:
                notes.append(f"{uri}: bad response ({e})")
        elif resp.status_code == 404:
            notes.append(f"{uri}: still pending")
        else:
            notes.append(f"{uri}: HTTP {resp.status_code}")

    if changed:
        backup = proof_path + ".pending.bak"
        if not os.path.exists(backup):          # keep the original pending proof, like `ots upgrade`
            shutil.copy2(proof_path, backup)
        ctx = BytesSerializationContext()
        detached.serialize(ctx)
        tmp = proof_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(ctx.getbytes())
        os.replace(tmp, proof_path)

    if _has_bitcoin_attestation(detached.timestamp):
        return "confirmed", "Proof upgraded: it now contains a Bitcoin block attestation."
    detail = "; ".join(notes) if notes else "no calendar response"
    return "stamped", f"Still pending: not yet included in a Bitcoin block (can take hours). [{detail}]"


# ------------------------------------------------------------ SSRF-safe fetch
def is_allowed_url(url):
    return netguard.is_allowed_url(url, allow_private=ALLOW_PRIVATE_URLS)


def fetch_url(url):
    """Fetch a URL, following up to MAX_REDIRECTS redirects, recording every hop."""
    hops, current = [], url
    for _ in range(MAX_REDIRECTS + 1):
        if not is_allowed_url(current):
            raise ValueError(f"URL not allowed (must be public http/https): {current}")
        resp = requests.get(current, headers={"User-Agent": TOOL_NAME}, timeout=20,
                            stream=True, allow_redirects=False)
        hops.append({"url": current, "status": resp.status_code})
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                raise ValueError("Redirect without Location header")
            current = urljoin(current, location)
            continue
        body = bytearray()
        for chunk in resp.iter_content(65536):
            body.extend(chunk)
            if len(body) > MAX_CAPTURE_BYTES:
                resp.close()
                raise ValueError("Page larger than 10 MB capture limit")
        info = {"status": resp.status_code, "headers": dict(resp.headers),
                "content_type": resp.headers.get("Content-Type", "")}
        resp.close()
        return current, info, bytes(body), hops
    raise ValueError("Too many redirects")


# ------------------------------------------------- rendered (browser) capture
def render_available():
    import importlib.util
    return importlib.util.find_spec("playwright") is not None


def render_page(url, prefix):
    """Run render_worker.py in a separate process. Returns the worker's result dict."""
    env = dict(os.environ, OSINT_ALLOW_PRIVATE="1" if ALLOW_PRIVATE_URLS else "0")
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(BASE_DIR, "render_worker.py"), url, UPLOAD_FOLDER, prefix],
            capture_output=True, text=True, timeout=120, env=env, cwd=BASE_DIR)
        lines = [ln for ln in proc.stdout.strip().splitlines() if ln.startswith("{")]
        return json.loads(lines[-1]) if lines else {"ok": False, "error": (proc.stderr or "no output")[-300:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Rendering timed out after 120 seconds"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# -------------------------------------------------------- core registration
def register_file(filepath, original_filename, stored_filename, mime_type, info, action):
    """Hash, record, log and timestamp one stored file. Returns the evidence id."""
    user = session["username"]
    file_hash = compute_sha256(filepath)
    file_size = os.path.getsize(filepath)

    metadata, preserved = info.get("metadata") or {}, info.get("metadata_preserved")
    if preserved is None:
        if mime_type and mime_type.startswith("image"):
            metadata = extract_exif(filepath)
            tags = [k for k in metadata if k != "error"]
            preserved = (f"EXIF present ({len(tags)} tags extracted); original bytes stored unmodified"
                         if tags else "No EXIF present; original bytes stored unmodified")
        else:
            preserved = "Not an image; original bytes stored unmodified"

    evidence_id = db.add_evidence(
        original_filename=original_filename, stored_filename=stored_filename,
        file_hash=file_hash, file_size=file_size, mime_type=mime_type,
        source_url=info.get("source_url", ""), description=info.get("description", ""),
        admiralty_source=info.get("admiralty_source", ""), admiralty_info=info.get("admiralty_info", ""),
        investigator=session["full_name"], evidence_type=info.get("evidence_type", ""),
        capture_method=info.get("capture_method", ""), metadata_preserved=preserved,
        metadata_json=json.dumps(metadata, indent=2) if metadata else "",
        retrieved_at=info.get("retrieved_at", ""), capture_group=info.get("capture_group", ""),
    )
    db.log_action(evidence_id, action,
                  f"{info.get('capture_method', '')}; file={original_filename}; SHA-256={file_hash}", user)
    if metadata:
        db.log_action(evidence_id, "METADATA_EXTRACTED", f"{len(metadata)} metadata fields stored", user)

    status, proof_path = stamp_with_ots(filepath)
    db.update_ots_status(evidence_id, status, proof_path)
    db.log_action(evidence_id, "OTS_STAMP", f"Status: {status}", user)
    return evidence_id


# ------------------------------------------------------------------- routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        row = db.verify_user(username, request.form.get("password", ""))
        if row:
            session.clear()
            session.update(username=row["username"], full_name=row["full_name"])
            db.log_action(None, "LOGIN", "Successful login", row["username"])
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
        db.log_action(None, "LOGIN_FAILED", f"Failed login for '{username[:50]}'", None)
        flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "username" in session:
        db.log_action(None, "LOGOUT", "User logged out", session["username"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", evidence_list=db.get_all_evidence())


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("No file selected")
            return redirect(url_for("upload"))
        source, info_rating = request.form.get("admiralty_source", ""), request.form.get("admiralty_info", "")
        if not valid_admiralty(source, info_rating):
            flash("Choose a valid Admiralty source (A-F) and information (1-6) rating")
            return redirect(url_for("upload"))

        original_filename = secure_filename(file.filename) or "unnamed"
        prefix = db.utcnow().replace(":", "").replace("-", "").replace("+0000", "")[:15]
        stored_filename = f"{prefix}_{original_filename}"
        filepath = os.path.join(UPLOAD_FOLDER, stored_filename)
        file.save(filepath)

        evidence_id = register_file(filepath, original_filename, stored_filename, file.mimetype, {
            "source_url": request.form.get("source_url", ""),
            "description": request.form.get("description", ""),
            "admiralty_source": source, "admiralty_info": info_rating,
            "evidence_type": request.form.get("evidence_type", ""),
            "capture_method": "Manual file upload",
        }, "UPLOAD")
        flash(f"Evidence #{evidence_id} logged successfully")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))
    return render_template("upload.html")


@app.route("/capture", methods=["GET", "POST"])
@login_required
def capture():
    """Automated acquisition of a web page: raw HTML + HTTP headers + retrieval time."""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        source, info_rating = request.form.get("admiralty_source", ""), request.form.get("admiralty_info", "")
        if not valid_admiralty(source, info_rating):
            flash("Choose a valid Admiralty source (A-F) and information (1-6) rating")
            return redirect(url_for("capture"))
        try:
            final_url, resp_info, body, hops = fetch_url(url)
        except Exception as e:
            db.log_action(None, "CAPTURE_FAILED", f"{url[:200]} -> {e}", session["username"])
            flash(f"Capture failed: {e}")
            return redirect(url_for("capture"))

        retrieved_at = db.utcnow()
        host = secure_filename(urlparse(final_url).hostname or "page")
        prefix = retrieved_at.replace(":", "").replace("-", "").replace("+0000", "")[:15] + "_" + host
        group = hashlib.sha256((url + retrieved_at).encode()).hexdigest()[:12]

        # Optional second acquisition: how the page actually LOOKS in a real browser.
        render = None
        if request.form.get("render") == "1":
            render = render_page(final_url, prefix)
            if not render.get("ok"):
                db.log_action(None, "RENDER_FAILED", f"{final_url[:200]} -> {render.get('error', '')}",
                              session["username"])
                flash(f"Rendered screenshot not captured: {render.get('error', 'unknown error')} "
                      "(raw HTML and headers were still captured)")

        capture_record = {
            "requested_url": url, "final_url": final_url, "retrieved_at_utc": retrieved_at,
            "http_status": resp_info["status"], "redirect_chain": hops,
            "response_headers": resp_info["headers"], "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body), "tool": TOOL_NAME, "investigator": session["full_name"],
            "rendered_capture": ({k: render[k] for k in ("final_url", "title", "http_status", "rendered_at_utc",
                                                          "browser", "blocked_requests")}
                                 if render and render.get("ok") else None),
        }
        html_name, hdr_name = f"{prefix}_page.html", f"{prefix}_headers.json"
        with open(os.path.join(UPLOAD_FOLDER, html_name), "wb") as f:
            f.write(body)
        with open(os.path.join(UPLOAD_FOLDER, hdr_name), "w", encoding="utf-8") as f:
            json.dump(capture_record, f, indent=2, sort_keys=True)

        common = {"source_url": final_url, "description": request.form.get("description", ""),
                  "admiralty_source": source, "admiralty_info": info_rating,
                  "capture_method": "Automated URL capture (HTTP GET)",
                  "retrieved_at": retrieved_at, "capture_group": group,
                  "metadata_preserved": "Raw response bytes stored unmodified"}
        html_id = register_file(os.path.join(UPLOAD_FOLDER, html_name), html_name, html_name,
                                resp_info["content_type"] or "text/html",
                                {**common, "evidence_type": "Web page (HTML)",
                                 "metadata": {"http_status": resp_info["status"], "content_type": resp_info["content_type"]}},
                                "CAPTURE")
        register_file(os.path.join(UPLOAD_FOLDER, hdr_name), hdr_name, hdr_name, "application/json",
                      {**common, "evidence_type": "HTTP headers", "metadata": {"capture_group": group}}, "CAPTURE")
        extra = ""
        if render and render.get("ok"):
            rcommon = {**common, "capture_method": "Automated rendered capture (headless Chromium)",
                       "retrieved_at": render["rendered_at_utc"], "metadata_preserved": "Rendered output stored unmodified"}
            rmeta = {"page_title": render["title"], "browser": render["browser"],
                     "http_status": render["http_status"],
                     "requests_blocked_by_safety_check": len(render["blocked_requests"])}
            png_name = os.path.basename(render["png"])
            png_id = register_file(render["png"], png_name, png_name, "image/png",
                                   {**rcommon, "evidence_type": "Screenshot (rendered)", "metadata": rmeta}, "CAPTURE")
            extra = f" + rendered screenshot #{png_id}"
            if render.get("pdf"):
                pdf_name = os.path.basename(render["pdf"])
                register_file(render["pdf"], pdf_name, pdf_name, "application/pdf",
                              {**rcommon, "evidence_type": "PDF (rendered)", "metadata": rmeta}, "CAPTURE")
                extra += " + PDF"
        flash(f"Captured {final_url} (evidence #{html_id} page + headers{extra})")
        return redirect(url_for("evidence_detail", evidence_id=html_id))
    return render_template("capture.html", render_available=render_available())


@app.route("/evidence/<int:evidence_id>")
@login_required
def evidence_detail(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        abort(404)
    try:
        metadata = json.loads(evidence["metadata_json"]) if evidence["metadata_json"] else {}
    except ValueError:
        metadata = {}
    return render_template("evidence_detail.html", evidence=evidence, metadata=metadata,
                           audit_entries=db.get_audit_log(evidence_id))


@app.route("/evidence/<int:evidence_id>/file")
@login_required
def evidence_file(evidence_id):
    """Serve a stored evidence file. Only PNG/JPEG are shown inline; anything else (e.g. captured
    HTML, which could contain scripts) is always a download, so evidence can never run in the app's origin."""
    ev = db.get_evidence_by_id(evidence_id)
    if not ev:
        abort(404)
    path = os.path.join(UPLOAD_FOLDER, ev["stored_filename"])
    if not os.path.exists(path):
        abort(404)
    inline = ev["mime_type"] in ("image/png", "image/jpeg")
    resp = send_file(path, mimetype=ev["mime_type"] if inline else "application/octet-stream",
                     as_attachment=not inline, download_name=ev["original_filename"])
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/evidence/<int:evidence_id>/ots-upgrade", methods=["POST"])
@login_required
def ots_upgrade(evidence_id):
    ev = db.get_evidence_by_id(evidence_id)
    if not ev:
        abort(404)
    proof = local_path(ev["ots_proof_path"], UPLOAD_FOLDER)
    if not proof:
        flash("No timestamp proof exists for this item. Use 'Re-stamp'.")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))
    status, msg = upgrade_proof(proof)
    if status is None:
        flash(msg)
    else:
        db.update_ots_status(evidence_id, status)
        db.log_action(evidence_id, "OTS_UPGRADE", f"Status: {status}", session["username"])
        flash(f"Timestamp status: {status}. {msg}")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/evidence/<int:evidence_id>/restamp", methods=["POST"])
@login_required
def restamp(evidence_id):
    ev = db.get_evidence_by_id(evidence_id)
    if not ev:
        abort(404)
    path = os.path.join(UPLOAD_FOLDER, ev["stored_filename"])
    if compute_sha256(path) != ev["file_hash"]:
        flash("Stored file no longer matches its recorded hash - NOT re-stamping.")
        db.log_action(evidence_id, "RESTAMP_REFUSED", "Stored file hash mismatch", session["username"])
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))
    status, proof = stamp_with_ots(path)
    db.update_ots_status(evidence_id, status, proof)
    db.log_action(evidence_id, "OTS_RESTAMP", f"Status: {status}", session["username"])
    flash(f"Re-stamp status: {status}")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    """Re-upload a file; recompute its hash; compare with the stored record."""
    result = None
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("No file selected")
            return redirect(url_for("verify"))
        h = hashlib.sha256()
        for chunk in iter(lambda: file.stream.read(8192), b""):
            h.update(chunk)
        digest = h.hexdigest()
        matches = db.get_evidence_by_hash(digest)

        selected = request.form.get("evidence_id", "").strip()
        target = db.get_evidence_by_id(int(selected)) if selected.isdigit() else None
        stored_ok = None
        if target:
            stored_path = os.path.join(UPLOAD_FOLDER, target["stored_filename"])
            stored_ok = os.path.exists(stored_path) and compute_sha256(stored_path) == target["file_hash"]

        verdict = "MATCH" if (target and target["file_hash"] == digest) or (not target and matches) else "NO MATCH"
        result = {"digest": digest, "matches": matches, "target": target, "verdict": verdict,
                  "stored_ok": stored_ok, "filename": secure_filename(file.filename)}
        db.log_action(target["id"] if target else (matches[0]["id"] if matches else None), "VERIFY",
                      f"{result['filename']} -> {verdict} (SHA-256 {digest})", session["username"])
    return render_template("verify.html", result=result, evidence_list=db.get_all_evidence())


@app.route("/audit-log")
@login_required
def full_audit_log():
    return render_template("audit_log.html", entries=db.get_audit_log(),
                           chain=db.verify_chain(), anchors=db.get_anchors())


@app.route("/audit-log/anchor", methods=["POST"])
@login_required
def anchor_audit_log():
    """Timestamp the current chain head with OpenTimestamps so the log itself is externally anchored."""
    chain = db.verify_chain()
    if not chain["ok"]:
        flash("Chain is broken - refusing to anchor a corrupted log.")
        return redirect(url_for("full_audit_log"))
    head, count = db.get_chain_head()
    stamp = db.utcnow().replace(":", "").replace("-", "").replace("+0000", "")[:15]
    path = os.path.join(ANCHOR_FOLDER, f"anchor_{stamp}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(head)
    status, proof = stamp_with_ots(path)
    anchor_id = db.add_anchor(head, count, session["username"], path, proof, status)
    db.log_action(None, "AUDIT_ANCHOR", f"Anchor #{anchor_id}: head={head} entries={count} status={status}",
                  session["username"])
    flash(f"Audit log anchored (anchor #{anchor_id}, status: {status})")
    return redirect(url_for("full_audit_log"))


@app.route("/anchor/<int:anchor_id>/upgrade", methods=["POST"])
@login_required
def anchor_upgrade(anchor_id):
    a = db.get_anchor(anchor_id)
    proof = local_path(a["proof_path"], ANCHOR_FOLDER) if a else None
    if not proof:
        abort(404)
    status, msg = upgrade_proof(proof)
    if status is None:
        flash(msg)
    else:
        db.update_anchor_status(anchor_id, status)
        db.log_action(None, "ANCHOR_UPGRADE", f"Anchor #{anchor_id}: {status}", session["username"])
        flash(f"Anchor #{anchor_id}: {status}. {msg}")
    return redirect(url_for("full_audit_log"))


@app.route("/evidence/<int:evidence_id>/export")
@login_required
def export_bundle(evidence_id):
    """ZIP: evidence file + timestamp proof + record + audit trail + verification instructions."""
    ev = db.get_evidence_by_id(evidence_id)
    if not ev:
        abort(404)
    path = os.path.join(UPLOAD_FOLDER, ev["stored_filename"])
    if not os.path.exists(path):
        abort(404)
    intact = compute_sha256(path) == ev["file_hash"]
    record = {k: ev[k] for k in ev.keys()}
    audit = [dict(r) for r in reversed(db.get_audit_log(evidence_id))]
    chain = db.verify_chain()
    readme = (
        f"EVIDENCE BUNDLE - item #{evidence_id}\n"
        f"Exported (UTC): {db.utcnow()} by {session['full_name']}\n"
        f"Stored file matches recorded SHA-256 at export time: {intact}\n"
        f"Audit chain intact at export time: {chain['ok']} ({chain['checked']} entries)\n\n"
        "HOW TO VERIFY INDEPENDENTLY\n"
        f"1. Compute the SHA-256 of {ev['stored_filename']}. It must equal:\n"
        f"   {ev['file_hash']}\n"
        f"   Windows PowerShell: Get-FileHash \"{ev['stored_filename']}\" -Algorithm SHA256\n"
        f"   Linux / macOS:      sha256sum \"{ev['stored_filename']}\"\n"
        "2. Check the timestamp proof (either option):\n"
        "   a) Website: open https://opentimestamps.org, drag in the .ots file, then the evidence file.\n"
        f"   b) Command line: ots verify \"{ev['stored_filename']}.ots\"  (original file must be beside it)\n"
        "   A proof that is still pending has not yet been included in a Bitcoin block.\n"
        "   Upgrade it later (ots upgrade, or the tool's Check / upgrade button) and verify again.\n"
        "3. record.json holds the evidence record; audit_trail.json lists every logged action\n"
        "   on this item with its chained entry hash.\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(path, ev["stored_filename"])
        proof = local_path(ev["ots_proof_path"], UPLOAD_FOLDER)
        if proof:
            z.write(proof, ev["stored_filename"] + ".ots")
        z.writestr("record.json", json.dumps(record, indent=2, default=str))
        z.writestr("audit_trail.json", json.dumps(audit, indent=2, default=str))
        z.writestr("README_VERIFY.txt", readme)
    buf.seek(0)
    db.log_action(evidence_id, "EXPORT", "Evidence bundle exported", session["username"])
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"evidence_{evidence_id}_bundle.zip")


# ---------------------------------------------------------------------- main
db.init_db()

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "createuser":
        # python app.py createuser <username> "<Full Name>"
        pwd = getpass.getpass("Password: ")
        try:
            db.create_user(sys.argv[2], pwd, sys.argv[3] if len(sys.argv) > 3 else sys.argv[2])
        except db.UserAlreadyExistsError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        print("User created.")
    elif len(sys.argv) >= 3 and sys.argv[1] == "resetpassword":
        # python app.py resetpassword <username>
        pwd = getpass.getpass("New password: ")
        if not pwd or pwd != getpass.getpass("Repeat new password: "):
            print("Error: passwords empty or do not match.", file=sys.stderr)
            sys.exit(1)
        if not db.reset_password(sys.argv[2], pwd):
            print(f"Error: no user called '{sys.argv[2]}'.", file=sys.stderr)
            sys.exit(1)
        db.log_action(None, "PASSWORD_RESET", f"Password reset from command line for '{sys.argv[2]}'",
                      user="admin-cli")
        print("Password reset.")
    elif len(sys.argv) >= 2 and sys.argv[1] == "listusers":
        for u in db.list_users():
            print(f"{u['username']}\t{u['full_name']}")
    else:
        app.run(debug=os.environ.get("OSINT_DEBUG", "0") == "1", port=5000)
