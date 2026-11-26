# OSINT Evidence Tool (v1.2 - resubmission)

## Setup (Windows PowerShell, from the project folder)
    & "C:\Users\<you>\AppData\Local\Programs\Python\Python311\python.exe" -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    python -m playwright install chromium            # one-off, for rendered screenshot/PDF
    python app.py createuser inv1 "Your Full Name"   # asks for a password
    python app.py                                    # http://127.0.0.1:5000

Other commands: `python app.py listusers`, `python app.py resetpassword <username>`.
Use `python -m pip` / `python -m playwright` (Windows Application Control may block the .exe launchers).
Timestamp upgrade uses the `opentimestamps` library directly; the `ots` command-line client is not needed.
Optional: set OSINT_SECRET_KEY to a long random string.

## Dissertation tests (screenshot each one)
1. Tamper test      -> Verify page: upload an edited copy of an item -> NO MATCH.
2. Append-only test -> `python tamper_tests.py attacks` (also tries re-grading the Admiralty rating), or `sqlite3 osint_evidence.db "UPDATE audit_log SET details='x' WHERE id=1;"`
                       -> "audit_log is append-only: UPDATE blocked". Same for DELETE.
3. Chain test       -> in sqlite3: DROP TRIGGER audit_no_update; UPDATE audit_log SET details='forged' WHERE id=3;
                       open /audit-log -> "BROKEN at entry #3". (Then restore a fresh DB.)
4. Volatility test  -> Capture a page you control, edit/delete it, capture again;
                       both records + timestamps remain. Verify the first copy still MATCHES.
5. OTS upgrade      -> after a few hours press "Check / upgrade timestamp";
                       status moves stamped -> confirmed. Also try "Anchor current chain head".
6. SSRF test        -> try capturing http://127.0.0.1/ -> rejected.
7. Automated checks -> python run_checks.py (temporary DB; screenshot the summary).
8. Safe test data   -> python tamper_tests.py files (sample file, tampered copy, synthetic EXIF photo).

## Known limitations (use in your report's limitations section)
- Rendered capture (screenshot + PDF) and raw HTML capture are two separate retrievals, so a fast-changing page may differ between them; each has its own timestamp. Content behind logins, CAPTCHAs or bot-blocking is not captured.
- Evidence/audit integrity relies on the host clock until the OTS proof is Bitcoin-confirmed.
- Someone with full access to the server could replace the whole database; the hash chain
  detects edits/removals, and anchoring the chain head externally (OpenTimestamps) is what
  makes silent total replacement detectable.
- DNS rebinding between the URL check and the fetch is not fully mitigated.
- Single-server prototype; password auth only; no roles or chain-of-custody transfer.
