"""
tamper_tests.py - helper for the dissertation evidence screenshots.

  python tamper_tests.py files    -> creates test_files/ (a sample file + a 1-character-changed copy)
  python tamper_tests.py attacks  -> tries to edit/delete audit + evidence rows in the REAL database (all must be blocked)
  python tamper_tests.py forge    -> makes a COPY of the database, drops the trigger on the copy, forges one
                                     audit row, and shows the hash chain detecting it. Your real DB is not touched.
"""
import os, sys, shutil, sqlite3

DB = os.environ.get("OSINT_DB", "osint_evidence.db")
COPY = "osint_forged_copy.db"


def need_data(conn):
    a = conn.execute("SELECT MIN(id) FROM audit_log").fetchone()[0]
    e = conn.execute("SELECT MIN(id) FROM evidence").fetchone()[0]
    if a is None or e is None:
        print("Database has no audit rows / evidence yet. Upload at least one file first.")
        sys.exit(1)
    return a, e


def cmd_files():
    os.makedirs("test_files", exist_ok=True)
    text = ("OSINT TEST EVIDENCE - harmless sample file for the dissertation tests.\n"
            "Line 2: the quick brown fox jumps over the lazy dog.\n")
    with open("test_files/evidence_sample.txt", "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    with open("test_files/evidence_sample_TAMPERED.txt", "w", encoding="utf-8", newline="\n") as f:
        f.write(text.replace("quick", "quack"))   # one-letter change
    print("Created test_files/evidence_sample.txt and test_files/evidence_sample_TAMPERED.txt")
    # A SAFE test photo with synthetic EXIF (no GPS, no real person/device). Needs: pip install pillow
    try:
        from PIL import Image
        img = Image.new("RGB", (640, 400), (30, 90, 160))
        exif = Image.Exif()
        exif[0x010F] = "TestCam Ltd (synthetic)"      # Make
        exif[0x0110] = "Model T-1 (synthetic)"        # Model
        exif[0x0131] = "OSINT test generator"         # Software
        exif[0x0132] = "2026:10:28 12:00:00"          # DateTime
        img.save("test_files/sample_photo_synthetic.jpg", exif=exif)
        print("Created test_files/sample_photo_synthetic.jpg (synthetic EXIF, no GPS)")
    except ImportError:
        print("Pillow not installed, so no sample photo was made. Run: pip install pillow  and repeat.")


def cmd_attacks():
    import database as db
    conn = sqlite3.connect(DB, isolation_level=None)
    a_id, e_id = need_data(conn)
    before = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    print(f"Database: {DB}   audit rows before: {before}\n")
    tests = [
        ("Edit an audit-log row",       f"UPDATE audit_log SET details='tampered' WHERE id={a_id}"),
        ("Delete an audit-log row",     f"DELETE FROM audit_log WHERE id={a_id}"),
        ("Change an evidence file hash", f"UPDATE evidence SET file_hash='0000' WHERE id={e_id}"),
        ("Delete an evidence record",   f"DELETE FROM evidence WHERE id={e_id}"),
        ("Re-grade Admiralty rating",   f"UPDATE evidence SET admiralty_source='A', admiralty_info='1' WHERE id={e_id}"),
        ("Edit evidence description",   f"UPDATE evidence SET description='edited later' WHERE id={e_id}"),
    ]
    for name, sql in tests:
        print("SQL>", sql)
        try:
            conn.execute(sql)
            print(f"[FAIL] {name}: change was ALLOWED\n")
        except sqlite3.DatabaseError as ex:
            print(f"[PASS] {name}: BLOCKED -> {ex}\n")
    after = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    chain = db.verify_chain()
    print(f"Audit rows after: {after}")
    print("Hash chain status:", "INTACT" if chain["ok"] else f"BROKEN at #{chain['broken_id']}",
          f"({chain['checked']} entries checked)")


def cmd_forge():
    if not os.path.exists(DB):
        print("Real database not found."); sys.exit(1)
    shutil.copyfile(DB, COPY)
    os.environ["OSINT_DB"] = COPY
    import database as db
    db.DB_NAME = COPY
    conn = sqlite3.connect(COPY, isolation_level=None)
    ids = [r[0] for r in conn.execute("SELECT id FROM audit_log ORDER BY id")]
    if len(ids) < 3:
        print("Need at least 3 audit rows. Do a few actions first."); sys.exit(1)
    target = ids[len(ids) // 2]
    print(f"Working on a COPY: {COPY} (real database untouched)")
    print("Chain before forging:", db.verify_chain()["ok"] and "INTACT")
    conn.execute("DROP TRIGGER audit_no_update")           # attacker removes the protection...
    conn.execute(f"UPDATE audit_log SET details='FORGED ENTRY' WHERE id={target}")  # ...and edits history
    conn.close()
    chain = db.verify_chain()
    print(f"Forged audit row #{target} after dropping the trigger.")
    print("Chain after forging:", "INTACT" if chain["ok"] else f"BROKEN at #{chain['broken_id']} - {chain['reason']}")
    print("\nNow view it in the web page:")
    print('  Stop the app (Ctrl+C), then run:')
    print('  $env:OSINT_DB="osint_forged_copy.db"; python app.py')
    print('  Open http://127.0.0.1:5000/audit-log  (expect: BROKEN). Afterwards: Ctrl+C, then')
    print('  Remove-Item Env:OSINT_DB   and start the app normally again.')


if __name__ == "__main__":
    {"files": cmd_files, "attacks": cmd_attacks, "forge": cmd_forge}.get(
        sys.argv[1] if len(sys.argv) > 1 else "", lambda: print(__doc__))()
