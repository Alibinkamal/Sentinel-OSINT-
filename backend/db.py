"""
SQLite persistence layer — users, cases, findings, audit log.
Uses only the stdlib sqlite3 (no ORM) to keep the footprint tiny.
"""
import sqlite3
import json
import hashlib
import os
import time
import uuid
import secrets
from contextlib import contextmanager

from config import DB_FILE

_PBKDF_ROUNDS = 200_000


# ---------------------------------------------------------------- connection
@contextmanager
def conn():
    c = sqlite3.connect(DB_FILE)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def _columns(c, table):
    return {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}


def init_db():
    with conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id       TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL,
                salt     TEXT NOT NULL,
                role     TEXT NOT NULL DEFAULT 'analyst',
                full_name TEXT DEFAULT '',
                email    TEXT DEFAULT '',
                active   INTEGER NOT NULL DEFAULT 1,
                created  REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cases(
                id       TEXT PRIMARY KEY,
                name     TEXT NOT NULL,
                target   TEXT,
                status   TEXT NOT NULL DEFAULT 'active',
                priority TEXT NOT NULL DEFAULT 'medium',
                notes    TEXT DEFAULT '',
                owner    TEXT,
                created  REAL NOT NULL,
                updated  REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings(
                id        TEXT PRIMARY KEY,
                case_id   TEXT,
                module    TEXT NOT NULL,
                selector  TEXT NOT NULL,
                summary   TEXT,
                data      TEXT,
                severity  TEXT DEFAULT 'info',
                created   REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit(
                id       TEXT PRIMARY KEY,
                ts       REAL NOT NULL,
                username TEXT,
                action   TEXT NOT NULL,
                detail   TEXT DEFAULT '',
                ip       TEXT DEFAULT '',
                status   TEXT DEFAULT 'ok'
            );
            """
        )
        # --- lightweight migration for pre-existing databases ---
        cols = _columns(c, "users")
        for name, ddl in (("full_name", "TEXT DEFAULT ''"),
                          ("email", "TEXT DEFAULT ''"),
                          ("active", "INTEGER NOT NULL DEFAULT 1")):
            if name not in cols:
                c.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")

    # First run: create a single Super Admin with a RANDOM password and print it
    # to the console once. No credential is ever hard-coded in the source.
    if not get_user("superadmin"):
        pw = secrets.token_urlsafe(12)
        create_user("superadmin", pw, role="superadmin", full_name="Super Admin")
        banner = (
            "\n" + "=" * 62 +
            "\n  SENTINEL OSINT — first-run administrator account created" +
            "\n  username : superadmin" +
            f"\n  password : {pw}" +
            "\n  ▸ Sign in, then change this password under Settings." +
            "\n  ▸ This is shown ONCE. It is not stored anywhere in clear text." +
            "\n" + "=" * 62 + "\n"
        )
        print(banner, flush=True)


# ---------------------------------------------------------------- auth helpers
def _hash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), _PBKDF_ROUNDS).hex()


def create_user(username, password, role="analyst", full_name="", email="", active=1):
    salt = os.urandom(16).hex()
    row = {
        "id": uuid.uuid4().hex,
        "username": username,
        "pw_hash": _hash(password, salt),
        "salt": salt,
        "role": role,
        "full_name": full_name or "",
        "email": email or "",
        "active": 1 if active else 0,
        "created": time.time(),
    }
    with conn() as c:
        c.execute(
            "INSERT INTO users(id,username,pw_hash,salt,role,full_name,email,active,created) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (row["id"], username, row["pw_hash"], salt, role, row["full_name"],
             row["email"], row["active"], row["created"]),
        )
    return {"id": row["id"], "username": username, "role": role,
            "full_name": row["full_name"], "email": row["email"], "active": row["active"]}


def get_user(username: str):
    with conn() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None


def verify_user(username: str, password: str):
    u = get_user(username)
    if not u:
        return None
    if _hash(password, u["salt"]) == u["pw_hash"]:
        return {"id": u["id"], "username": u["username"], "role": u["role"],
                "active": u.get("active", 1)}
    return None


def list_users():
    with conn() as c:
        rows = c.execute(
            "SELECT username, role, full_name, email, active, created "
            "FROM users ORDER BY created").fetchall()
        return [dict(r) for r in rows]


def update_user_role(username: str, role: str) -> bool:
    with conn() as c:
        return c.execute("UPDATE users SET role=? WHERE username=?",
                         (role, username)).rowcount > 0


def set_user_active(username: str, active: int) -> bool:
    with conn() as c:
        return c.execute("UPDATE users SET active=? WHERE username=?",
                         (1 if active else 0, username)).rowcount > 0


def delete_user(username: str) -> bool:
    with conn() as c:
        return c.execute("DELETE FROM users WHERE username=?", (username,)).rowcount > 0


def count_role(role: str) -> int:
    with conn() as c:
        return c.execute("SELECT COUNT(*) n FROM users WHERE role=?", (role,)).fetchone()["n"]


def change_password(username: str, new_password: str) -> bool:
    u = get_user(username)
    if not u:
        return False
    salt = os.urandom(16).hex()
    with conn() as c:
        c.execute("UPDATE users SET pw_hash=?, salt=? WHERE username=?",
                  (_hash(new_password, salt), salt, username))
    return True


# ---------------------------------------------------------------- audit log
def add_audit(username, action, detail="", ip="", status="ok"):
    with conn() as c:
        c.execute(
            "INSERT INTO audit(id,ts,username,action,detail,ip,status) VALUES(?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, time.time(), username or "-", action,
             str(detail)[:300], ip or "", status),
        )


def list_audit(limit=200, username=None):
    with conn() as c:
        if username:
            rows = c.execute("SELECT * FROM audit WHERE username=? ORDER BY ts DESC LIMIT ?",
                             (username, limit)).fetchall()
        else:
            rows = c.execute("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------- cases
def create_case(name, target="", priority="medium", owner="", notes=""):
    now = time.time()
    cid = "SNT-" + uuid.uuid4().hex[:6].upper()
    with conn() as c:
        c.execute(
            "INSERT INTO cases(id,name,target,status,priority,notes,owner,created,updated) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (cid, name, target, "active", priority, notes, owner, now, now),
        )
    return get_case(cid)


def get_case(cid):
    with conn() as c:
        r = c.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
        if not r:
            return None
        case = dict(r)
        f = c.execute("SELECT COUNT(*) n FROM findings WHERE case_id=?", (cid,)).fetchone()
        case["findings_count"] = f["n"]
        return case


def list_cases():
    with conn() as c:
        rows = c.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) findings_count "
            "FROM cases c ORDER BY updated DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def update_case(cid, **fields):
    allowed = {"name", "target", "status", "priority", "notes"}
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k}=?")
            vals.append(v)
    if not sets:
        return get_case(cid)
    sets.append("updated=?")
    vals.append(time.time())
    vals.append(cid)
    with conn() as c:
        c.execute(f"UPDATE cases SET {','.join(sets)} WHERE id=?", vals)
    return get_case(cid)


def delete_case(cid):
    with conn() as c:
        c.execute("DELETE FROM findings WHERE case_id=?", (cid,))
        c.execute("DELETE FROM cases WHERE id=?", (cid,))


# ---------------------------------------------------------------- findings
def add_finding(case_id, module, selector, summary="", data=None, severity="info"):
    now = time.time()
    fid = uuid.uuid4().hex
    with conn() as c:
        c.execute(
            "INSERT INTO findings(id,case_id,module,selector,summary,data,severity,created) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (fid, case_id, module, selector, summary,
             json.dumps(data or {}, ensure_ascii=False), severity, now),
        )
        if case_id:
            c.execute("UPDATE cases SET updated=? WHERE id=?", (now, case_id))
    return fid


def list_findings(case_id=None, limit=200):
    with conn() as c:
        if case_id:
            rows = c.execute(
                "SELECT * FROM findings WHERE case_id=? ORDER BY created DESC LIMIT ?",
                (case_id, limit)).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM findings ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["data"] = json.loads(d["data"]) if d["data"] else {}
            except json.JSONDecodeError:
                d["data"] = {}
            out.append(d)
        return out


def stats():
    with conn() as c:
        cases = c.execute("SELECT COUNT(*) n FROM cases").fetchone()["n"]
        findings = c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
        by_sev = {}
        for r in c.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity"):
            by_sev[r["severity"]] = r["n"]
        selectors = c.execute("SELECT COUNT(DISTINCT selector) n FROM findings").fetchone()["n"]
    return {"cases": cases, "findings": findings, "selectors": selectors, "by_severity": by_sev}
