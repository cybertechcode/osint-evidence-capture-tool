"""
run_checks.py - automated checks of the tool, run against a TEMPORARY database
(your real data is not touched).   Usage:  python run_checks.py
Screenshot the final summary for the dissertation.
"""
import os, io, sys, tempfile, threading, http.server, socketserver, sqlite3, zipfile, functools

TMP = tempfile.mkdtemp(prefix="osint_checks_")
os.environ["OSINT_DB"] = os.path.join(TMP, "check.db")
os.environ["OSINT_ALLOW_PRIVATE"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as A, database as db
A.UPLOAD_FOLDER = os.path.join(TMP, "uploads"); os.makedirs(A.UPLOAD_FOLDER)
A.ANCHOR_FOLDER = os.path.join(TMP, "anchors"); os.makedirs(A.ANCHOR_FOLDER)

site = os.path.join(TMP, "site"); os.makedirs(site)
open(os.path.join(site, "index.html"), "w").write("<html><body>Test page v1</body></html>")
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=site)
handler.log_message = lambda *a, **k: None
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a, **k): pass
srv = socketserver.TCPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=site))
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

results = []
def check(name, cond):
    results.append(bool(cond)); print(("[PASS] " if cond else "[FAIL] ") + name)

db.create_user("tester", "pw12345", "Test Investigator")
try:
    db.create_user("tester", "another-password", "Duplicate Investigator")
    check("Duplicate username rejected with a clear error", False)
except db.UserAlreadyExistsError:
    check("Duplicate username rejected with a clear error", True)
c = A.app.test_client()
def up(data, name, **extra):
    return c.post("/upload", data={"file": (io.BytesIO(data), name), "admiralty_source": "B",
                  "admiralty_info": "2", "evidence_type": "Document", **extra},
                  content_type="multipart/form-data", follow_redirects=True)

print("--- access control ---")
r = c.get("/"); check("Unauthenticated user is redirected to login", r.status_code == 302 and "/login" in r.location)
r = c.post("/login", data={"username": "tester", "password": "wrong"}); check("Wrong password rejected", b"Invalid" in r.data)
r = c.post("/login", data={"username": "tester", "password": "pw12345"}); check("Correct login accepted", r.status_code == 302)

print("--- upload and negative tests ---")
r = up(b"hello evidence", "a.txt"); check("Normal upload logged with investigator", b"Test Investigator" in r.data)
r = up(b"hello evidence", "a_duplicate.txt"); check("Duplicate upload handled (second record created)", len(db.get_evidence_by_hash(__import__('hashlib').sha256(b'hello evidence').hexdigest())) == 2)
r = up(b"", "empty.txt"); check("Empty file handled without error", r.status_code == 200 and b"logged successfully" in r.data)
r = up(b"\xff\xd8\xff\xe0notreallyajpeg", "fake.jpg"); check("Corrupt/non-EXIF image handled without error", r.status_code == 200 and b"logged successfully" in r.data)
r = c.post("/upload", data={"file": (io.BytesIO(b"x"), "b.txt"), "admiralty_source": "Z", "admiralty_info": "9"}, content_type="multipart/form-data", follow_redirects=True)
check("Invalid Admiralty rating rejected", b"valid Admiralty" in r.data)
r = c.post("/upload", data={"admiralty_source": "A", "admiralty_info": "1"}, content_type="multipart/form-data", follow_redirects=True)
check("Upload with no file rejected", b"No file selected" in r.data)

print("--- URL capture ---")
r = c.post("/capture", data={"url": f"http://127.0.0.1:{port}/index.html", "admiralty_source": "C", "admiralty_info": "3"}, follow_redirects=True)
check("URL capture stores page + headers", b"Captured" in r.data and len([e for e in db.get_all_evidence() if e["capture_group"]]) == 2)
r = c.post("/capture", data={"url": "ftp://example.com/x", "admiralty_source": "C", "admiralty_info": "3"}, follow_redirects=True)
check("Non-http(s) URL rejected", b"Capture failed" in r.data)
A.ALLOW_PRIVATE_URLS = False
r = c.post("/capture", data={"url": f"http://127.0.0.1:{port}/index.html", "admiralty_source": "C", "admiralty_info": "3"}, follow_redirects=True)
check("SSRF protection: loopback/private address blocked", b"not allowed" in r.data)
A.ALLOW_PRIVATE_URLS = True

print("--- verification and tamper detection ---")
page = [e for e in db.get_all_evidence() if e["evidence_type"] == "Web page (HTML)"][0]
orig = open(os.path.join(A.UPLOAD_FOLDER, page["stored_filename"]), "rb").read()
r = c.post("/verify", data={"file": (io.BytesIO(orig), "p.html"), "evidence_id": str(page["id"])}, content_type="multipart/form-data")
check("Unmodified file -> MATCH", b">MATCH<" in r.data)
t = bytearray(orig); t[5] ^= 1
r = c.post("/verify", data={"file": (io.BytesIO(bytes(t)), "p.html"), "evidence_id": str(page["id"])}, content_type="multipart/form-data")
check("One-bit change -> NO MATCH", b"NO MATCH" in r.data)

print("--- rendered (browser) capture ---")
if not A.render_available():
    print("[SKIP] Playwright not installed (pip install playwright ; playwright install chromium)")
else:
    before = len(db.get_all_evidence())
    r = c.post("/capture", data={"url": f"http://127.0.0.1:{port}/index.html", "render": "1",
               "admiralty_source": "C", "admiralty_info": "3"}, follow_redirects=True)
    new = db.get_all_evidence()[:len(db.get_all_evidence()) - before]
    kinds = sorted(e["evidence_type"] for e in new)
    if b"Rendered screenshot not captured" in r.data:
        msg = r.data.decode(errors="ignore").split("Rendered screenshot not captured:")[1][:160].split("<")[0]
        check("Rendered capture works (browser problem: %s)" % msg.strip(), False)
    else:
        check("Rendered capture stores HTML + headers + PNG screenshot + PDF", kinds == ["HTTP headers", "PDF (rendered)", "Screenshot (rendered)", "Web page (HTML)"])
        png = [e for e in new if e["evidence_type"] == "Screenshot (rendered)"]
        check("Screenshot is a real PNG file with a recorded hash",
              bool(png) and open(os.path.join(A.UPLOAD_FOLDER, png[0]["stored_filename"]), "rb").read(8) == b"\x89PNG\r\n\x1a\n"
              and len(png[0]["file_hash"]) == 64)
        hdr = [e for e in new if e["evidence_type"] == "HTTP headers"][0]
        check("Headers record includes rendered-capture details (title, browser)",
              b"rendered_capture" in open(os.path.join(A.UPLOAD_FOLDER, hdr["stored_filename"]), "rb").read()
              and b"Chromium" in open(os.path.join(A.UPLOAD_FOLDER, hdr["stored_filename"]), "rb").read())
    A.ALLOW_PRIVATE_URLS = False
    res = A.render_page(f"http://127.0.0.1:{port}/index.html", "ssrf_test")
    check("Browser cannot be pointed at a private/loopback address", res.get("ok") is False)
    A.ALLOW_PRIVATE_URLS = True
_orig_render = A.render_page
A.render_page = lambda url, prefix: {"ok": False, "error": "simulated browser failure"}
r = c.post("/capture", data={"url": f"http://127.0.0.1:{port}/index.html", "render": "1", "admiralty_source": "C", "admiralty_info": "3"}, follow_redirects=True)
check("If rendering fails, raw HTML + headers are still captured and the user is told", b"not captured" in r.data and b"Captured" in r.data)
A.render_page = _orig_render
r = c.get(f"/evidence/{db.get_all_evidence()[0]['id']}/file")
check("Stored files are served with nosniff header", r.headers.get("X-Content-Type-Options") == "nosniff")

print("--- append-only and hash chain ---")
r = c.post("/audit-log/anchor", follow_redirects=True); check("Chain head anchored while chain intact", b"anchored" in r.data and len(db.get_anchors()) == 1)
conn = db.get_db()
db.update_ots_status(1, "confirmed"); check("Timestamp status can still be upgraded (allowed field)", db.get_evidence_by_id(1)["ots_status"] == "confirmed")
for label, sql in [("UPDATE audit_log blocked", "UPDATE audit_log SET details='x' WHERE id=1"),
                   ("DELETE audit_log blocked", "DELETE FROM audit_log WHERE id=1"),
                   ("Evidence hash change blocked", "UPDATE evidence SET file_hash='0' WHERE id=1"),
                   ("Evidence delete blocked", "DELETE FROM evidence WHERE id=1"),
                   ("Admiralty rating change blocked", "UPDATE evidence SET admiralty_source='A', admiralty_info='1' WHERE id=1"),
                   ("Evidence description change blocked", "UPDATE evidence SET description='edited later' WHERE id=1"),
                   ("Anchor record change blocked", "UPDATE anchors SET head_hash='0' WHERE id=1"),
                   ("Anchor delete blocked", "DELETE FROM anchors WHERE id=1")]:
    try: conn.execute(sql); check(label, False)
    except sqlite3.DatabaseError: check(label, True)
check("Audit chain intact before attack", db.verify_chain()["ok"])
conn.execute("DROP TRIGGER audit_no_update"); conn.execute("UPDATE audit_log SET details='forged' WHERE id=3"); conn.close()
v = db.verify_chain(); check(f"Forged row detected by hash chain (broken at #{v['broken_id']})", (not v["ok"]) and v["broken_id"] == 3)
r = c.post("/audit-log/anchor", follow_redirects=True); check("Anchoring refused while chain is broken", b"refusing" in r.data)

print("--- export ---")
r = c.get(f"/evidence/{page['id']}/export")
z = zipfile.ZipFile(io.BytesIO(r.data))
check("Evidence bundle contains file, record, audit trail and verify instructions",
      {"record.json", "audit_trail.json", "README_VERIFY.txt"} <= set(z.namelist()))

print("\n==== SUMMARY: %d/%d checks passed ====" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
