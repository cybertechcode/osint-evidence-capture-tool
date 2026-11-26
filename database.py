"""
database.py - SQLite layer for the OSINT acquisition tool.

Integrity features (for ACPO Principles 1 and 3, and PACE s.69 reliability):
  * audit_log is APPEND-ONLY, enforced by SQLite triggers (UPDATE/DELETE abort).
  * audit_log is HASH-CHAINED: every row stores the hash of the previous row, so
    any edit made by bypassing the triggers is detected by verify_chain().
  * evidence rows cannot be deleted and their identifying fields cannot be edited.
  * the head of the chain can be anchored with OpenTimestamps (see app.py).
"""
import os
import hashlib
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = os.environ.get("OSINT_DB", "osint_evidence.db")
GENESIS_HASH = "0" * 64


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    # isolation_level=None -> autocommit; transactions are managed explicitly.
    conn = sqlite3.connect(DB_NAME, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER,
            mime_type TEXT,
            source_url TEXT,
            description TEXT,
            admiralty_source TEXT,          -- A to F
            admiralty_info TEXT,            -- 1 to 6
            investigator TEXT NOT NULL,     -- who acquired it (proposal Obj 2)
            evidence_type TEXT,             -- screenshot / web page / headers ...
            capture_method TEXT,            -- manual upload / automated URL capture
            metadata_preserved TEXT,        -- preservation status
            metadata_json TEXT,             -- extracted EXIF / capture info
            retrieved_at TEXT,              -- when the source was retrieved (URL capture)
            capture_group TEXT,             -- links items from one capture
            ots_status TEXT DEFAULT 'pending',   -- pending / stamped / confirmed / failed
            ots_proof_path TEXT,
            upload_timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            user TEXT,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id)
        );

        CREATE TABLE IF NOT EXISTS anchors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            head_hash TEXT NOT NULL,
            entries_count INTEGER NOT NULL,
            created TEXT NOT NULL,
            created_by TEXT,
            file_path TEXT,
            proof_path TEXT,
            status TEXT
        );

        -- ---------- append-only enforcement ----------
        CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE blocked'); END;

        CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: DELETE blocked'); END;

        CREATE TRIGGER IF NOT EXISTS evidence_no_delete
        BEFORE DELETE ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence records cannot be deleted'); END;

        CREATE TRIGGER IF NOT EXISTS evidence_immutable
        BEFORE UPDATE OF original_filename, stored_filename, file_hash, file_size,
                         source_url, investigator, upload_timestamp ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence identifying fields are immutable'); END;

        CREATE TRIGGER IF NOT EXISTS anchors_no_delete
        BEFORE DELETE ON anchors
        BEGIN SELECT RAISE(ABORT, 'anchors cannot be deleted'); END;

        -- v1.2.1: the checklist fields recorded at acquisition (Admiralty rating,
        -- description, type, method, metadata, retrieval time) are also locked, so a
        -- source/credibility grading cannot be silently re-written after the event.
        -- Only ots_status and ots_proof_path may still change (timestamp upgrades).
        CREATE TRIGGER IF NOT EXISTS evidence_record_immutable
        BEFORE UPDATE OF admiralty_source, admiralty_info, description, evidence_type,
                         capture_method, metadata_preserved, metadata_json, mime_type,
                         retrieved_at, capture_group ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence checklist fields are immutable'); END;

        -- anchor records: only the status may change (pending -> confirmed)
        CREATE TRIGGER IF NOT EXISTS anchors_immutable
        BEFORE UPDATE OF head_hash, entries_count, created, created_by, file_path, proof_path ON anchors
        BEGIN SELECT RAISE(ABORT, 'anchor records are immutable'); END;
    """)
    conn.close()


# ------------------------------------------------------------------ users
class UserAlreadyExistsError(ValueError):
    """Raised when attempting to create a user with an existing username."""


def create_user(username, password, full_name):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, full_name, password_hash, created) VALUES (?,?,?,?)",
            (username, full_name, generate_password_hash(password), utcnow()),
        )
    except sqlite3.IntegrityError as exc:
        if conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone():
            raise UserAlreadyExistsError(
                f"Username '{username}' already exists."
            ) from exc
        raise
    finally:
        conn.close()


def reset_password(username, new_password):
    """Set a new password for an existing user. Returns True if the user existed."""
    conn = get_db()
    cur = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                       (generate_password_hash(new_password), username))
    conn.commit()
    found = cur.rowcount > 0
    conn.close()
    return found


def list_users():
    conn = get_db()
    rows = conn.execute("SELECT username, full_name FROM users ORDER BY id").fetchall()
    conn.close()
    return rows


def verify_user(username, password):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row and check_password_hash(row["password_hash"], password):
        return row
    return None


# ------------------------------------------------------- hash-chained audit
def compute_entry_hash(prev_hash, evidence_id, action, details, timestamp, user):
    payload = "|".join([
        prev_hash,
        "" if evidence_id is None else str(evidence_id),
        action or "",
        details or "",
        timestamp or "",
        user or "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_action(evidence_id, action, details="", user=None):
    """Append one entry to the audit log, chained to the previous entry."""
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")  # lock so two writers cannot fork the chain
        last = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["entry_hash"] if last else GENESIS_HASH
        ts = utcnow()
        entry_hash = compute_entry_hash(prev_hash, evidence_id, action, details, ts, user)
        conn.execute(
            "INSERT INTO audit_log (evidence_id, action, details, user, timestamp, prev_hash, entry_hash) "
            "VALUES (?,?,?,?,?,?,?)",
            (evidence_id, action, details, user, ts, prev_hash, entry_hash),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def verify_chain():
    """Recompute the whole chain. Returns a dict describing the result."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    conn.close()
    prev = GENESIS_HASH
    for r in rows:
        if r["prev_hash"] != prev:
            return {"ok": False, "checked": len(rows), "broken_id": r["id"],
                    "reason": "prev_hash does not match the previous entry (row removed or reordered)"}
        expected = compute_entry_hash(prev, r["evidence_id"], r["action"],
                                      r["details"], r["timestamp"], r["user"])
        if expected != r["entry_hash"]:
            return {"ok": False, "checked": len(rows), "broken_id": r["id"],
                    "reason": "entry content does not match its stored hash (row modified)"}
        prev = r["entry_hash"]
    return {"ok": True, "checked": len(rows), "broken_id": None, "head": prev,
            "reason": "chain intact"}


def get_chain_head():
    conn = get_db()
    row = conn.execute("SELECT entry_hash, id FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    count = conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"]
    conn.close()
    return (row["entry_hash"] if row else GENESIS_HASH), count


# ---------------------------------------------------------------- evidence
def add_evidence(**f):
    conn = get_db()
    cur = conn.execute("""
        INSERT INTO evidence
        (original_filename, stored_filename, file_hash, file_size, mime_type, source_url,
         description, admiralty_source, admiralty_info, investigator, evidence_type,
         capture_method, metadata_preserved, metadata_json, retrieved_at, capture_group,
         upload_timestamp)
        VALUES (:original_filename, :stored_filename, :file_hash, :file_size, :mime_type,
                :source_url, :description, :admiralty_source, :admiralty_info, :investigator,
                :evidence_type, :capture_method, :metadata_preserved, :metadata_json,
                :retrieved_at, :capture_group, :upload_timestamp)
    """, {**f, "upload_timestamp": utcnow()})
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


def get_evidence_by_hash(file_hash):
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence WHERE file_hash = ?", (file_hash,)).fetchall()
    conn.close()
    return rows


def get_audit_log(evidence_id=None):
    conn = get_db()
    if evidence_id:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE evidence_id = ? ORDER BY id DESC", (evidence_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def update_ots_status(evidence_id, status, proof_path=None):
    conn = get_db()
    conn.execute(
        "UPDATE evidence SET ots_status = ?, ots_proof_path = COALESCE(?, ots_proof_path) WHERE id = ?",
        (status, proof_path, evidence_id),
    )
    conn.close()


# ----------------------------------------------------------------- anchors
def add_anchor(head_hash, entries_count, created_by, file_path, proof_path, status):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO anchors (head_hash, entries_count, created, created_by, file_path, proof_path, status) "
        "VALUES (?,?,?,?,?,?,?)",
        (head_hash, entries_count, utcnow(), created_by, file_path, proof_path, status),
    )
    anchor_id = cur.lastrowid
    conn.close()
    return anchor_id


def get_anchors():
    conn = get_db()
    rows = conn.execute("SELECT * FROM anchors ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def get_anchor(anchor_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM anchors WHERE id = ?", (anchor_id,)).fetchone()
    conn.close()
    return row


def update_anchor_status(anchor_id, status):
    conn = get_db()
    conn.execute("UPDATE anchors SET status = ? WHERE id = ?", (status, anchor_id))
    conn.close()
