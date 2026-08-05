import sqlite3
from datetime import datetime

DB_NAME = "osint_evidence.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER,
            mime_type TEXT,
            source_url TEXT,
            description TEXT,
            admiralty_source TEXT,   -- A to F
            admiralty_info TEXT,     -- 1 to 6
            ots_status TEXT DEFAULT 'pending',  -- pending / stamped / failed
            ots_proof_path TEXT,
            upload_timestamp TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id)
        )
    """)

    conn.commit()
    conn.close()


def log_action(evidence_id, action, details=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (evidence_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
        (evidence_id, action, details, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def add_evidence(original_filename, stored_filename, file_hash, file_size,
                  mime_type, source_url, description, admiralty_source, admiralty_info):
    conn = get_db()
    cur = conn.execute("""
        INSERT INTO evidence
        (original_filename, stored_filename, file_hash, file_size, mime_type,
         source_url, description, admiralty_source, admiralty_info, upload_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (original_filename, stored_filename, file_hash, file_size, mime_type,
          source_url, description, admiralty_source, admiralty_info,
          datetime.utcnow().isoformat()))
    conn.commit()
    evidence_id = cur.lastrowid
    conn.close()
    return evidence_id


def get_all_evidence():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def get_evidence_by_id(evidence_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    conn.close()
    return row


def get_audit_log(evidence_id=None):
    conn = get_db()
    if evidence_id:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE evidence_id = ? ORDER BY id DESC",
            (evidence_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def update_ots_status(evidence_id, status, proof_path=None):
    conn = get_db()
    conn.execute(
        "UPDATE evidence SET ots_status = ?, ots_proof_path = ? WHERE id = ?",
        (status, proof_path, evidence_id)
    )
    conn.commit()
    conn.close()