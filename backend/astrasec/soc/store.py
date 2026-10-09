"""Persistent storage for the Security Center.

Separate file from the inspection log (``astrasec.db``) on purpose: this one
holds the owner's operational data — incidents, alerts, the traffic log,
configuration and the owner credential — and has a different lifecycle from
the models' per-inspection audit trail.

Nothing written here contains a raw secret. Every text field that came from a
user or a document is passed through :func:`astrasec.soc.dlp.safe_excerpt` or
:func:`astrasec.soc.dlp.redact` by the caller before it arrives.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..config import ARTIFACT_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    app_id      TEXT NOT NULL,
    session_id  TEXT,
    client      TEXT,
    source      TEXT NOT NULL,          -- prompt | file | response
    threat_class TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk        REAL NOT NULL,
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL,          -- answered | sanitized | masked | blocked | ...
    latency_ms  REAL,
    excerpt     TEXT,
    incident_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_req_ts ON requests(ts DESC);
CREATE INDEX IF NOT EXISTS idx_req_app ON requests(app_id, ts DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    updated_at  REAL NOT NULL,
    app_id      TEXT NOT NULL,
    source      TEXT NOT NULL,
    threat_class TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk        REAL NOT NULL,
    ml_confidence REAL,
    behavior    REAL,
    similarity  REAL,
    signature   REAL,
    app_risk    REAL,
    action      TEXT NOT NULL,
    defense     TEXT,                   -- JSON list of policy ids
    status      TEXT NOT NULL DEFAULT 'open',
    session_id  TEXT,
    client      TEXT,
    file_name   TEXT,
    title       TEXT,
    excerpt     TEXT,
    detail      TEXT,                   -- JSON: breakdown, findings, redacted text
    notes       TEXT                    -- JSON list of {ts, status, note}
);
CREATE INDEX IF NOT EXISTS idx_inc_ts ON incidents(ts DESC);
CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    incident_id TEXT,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    message     TEXT NOT NULL,
    app_id      TEXT,
    read        INTEGER NOT NULL DEFAULT 0,
    channels    TEXT                    -- JSON {channel: "sent"|"failed: …"|"skipped"}
);
CREATE INDEX IF NOT EXISTS idx_alert_ts ON alerts(ts DESC);

CREATE TABLE IF NOT EXISTS files (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    app_id      TEXT NOT NULL,
    session_id  TEXT,
    client      TEXT,
    name        TEXT NOT NULL,
    size        INTEGER,
    sha256      TEXT,
    kind        TEXT,
    status      TEXT NOT NULL,          -- accepted | sanitized | blocked | quarantined | rejected
    risk        REAL NOT NULL,
    summary     TEXT,                   -- JSON: counts, findings (redacted)
    incident_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_ts ON files(ts DESC);

CREATE TABLE IF NOT EXISTS kv (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
"""

INCIDENT_STATUSES = ("open", "investigating", "resolved", "false_positive")


class SOCStore:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = str(path or (ARTIFACT_DIR / "security_center.db"))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ kv
    def get(self, key: str, default: Any = None) -> Any:
        with self._cursor() as cur:
            row = cur.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    def put(self, key: str, value: Any) -> None:
        with self._cursor() as cur:
            cur.execute("INSERT OR REPLACE INTO kv VALUES (?,?,?)",
                        (key, json.dumps(value, default=str), time.time()))

    # ------------------------------------------------------------ requests
    def log_request(self, row: Dict[str, Any]) -> str:
        rid = row.get("id") or "REQ-" + uuid.uuid4().hex[:12]
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, row.get("ts", time.time()), row["app_id"], row.get("session_id"),
                 row.get("client"), row["source"], row["threat_class"], row["severity"],
                 float(row["risk"]), row["action"], row["outcome"],
                 row.get("latency_ms"), row.get("excerpt"), row.get("incident_id")))
        return rid

    def requests(self, limit: int = 100, offset: int = 0, since: Optional[float] = None,
                 source: Optional[str] = None, flagged_only: bool = False,
                 app_id: Optional[str] = None) -> List[Dict[str, Any]]:
        sql, params = "SELECT * FROM requests WHERE 1=1", []
        if since:
            sql += " AND ts >= ?"; params.append(since)
        if source:
            sql += " AND source = ?"; params.append(source)
        if app_id:
            sql += " AND app_id = ?"; params.append(app_id)
        if flagged_only:
            sql += " AND action NOT IN ('allow')"
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params += [int(limit), int(offset)]
        with self._cursor() as cur:
            return [dict(r) for r in cur.execute(sql, params).fetchall()]

    def request_rows_since(self, since: float) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            return [dict(r) for r in cur.execute(
                "SELECT ts, app_id, source, threat_class, severity, risk, action, outcome, "
                "latency_ms, client FROM requests WHERE ts >= ? ORDER BY ts", (since,)).fetchall()]

    def count_requests(self, since: Optional[float] = None) -> int:
        with self._cursor() as cur:
            if since:
                return cur.execute("SELECT COUNT(*) FROM requests WHERE ts >= ?",
                                   (since,)).fetchone()[0]
            return cur.execute("SELECT COUNT(*) FROM requests").fetchone()[0]

    # ----------------------------------------------------------- incidents
    def create_incident(self, inc: Dict[str, Any]) -> str:
        iid = inc.get("id") or "INC-" + time.strftime("%y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
        now = time.time()
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (iid, inc.get("ts", now), now, inc["app_id"], inc["source"],
                 inc["threat_class"], inc["severity"], float(inc["risk"]),
                 inc.get("ml_confidence"), inc.get("behavior"), inc.get("similarity"),
                 inc.get("signature"), inc.get("app_risk"), inc["action"],
                 json.dumps(inc.get("defense") or []), "open", inc.get("session_id"),
                 inc.get("client"), inc.get("file_name"), inc.get("title"),
                 inc.get("excerpt"), json.dumps(inc.get("detail") or {}, default=str),
                 json.dumps([])))
        return iid

    @staticmethod
    def _inc_row(r: sqlite3.Row, full: bool = False) -> Dict[str, Any]:
        d = dict(r)
        d["defense"] = json.loads(d.get("defense") or "[]")
        d["notes"] = json.loads(d.get("notes") or "[]")
        detail = json.loads(d.get("detail") or "{}")
        if full:
            d["detail"] = detail
        else:
            d.pop("detail", None)
            d["breakdown"] = detail.get("breakdown")
        return d

    def incidents(self, limit: int = 50, offset: int = 0, status: Optional[str] = None,
                  severity: Optional[str] = None, source: Optional[str] = None,
                  q: Optional[str] = None, since: Optional[float] = None
                  ) -> Tuple[List[Dict[str, Any]], int]:
        where, params = ["1=1"], []
        if status:
            if status == "active":
                where.append("status IN ('open','investigating')")
            else:
                where.append("status = ?"); params.append(status)
        if severity:
            where.append("severity = ?"); params.append(severity)
        if source:
            where.append("source = ?"); params.append(source)
        if since:
            where.append("ts >= ?"); params.append(since)
        if q:
            where.append("(id LIKE ? OR title LIKE ? OR excerpt LIKE ? OR file_name LIKE ? "
                         "OR threat_class LIKE ?)")
            params += [f"%{q}%"] * 5
        w = " AND ".join(where)
        with self._cursor() as cur:
            total = cur.execute(f"SELECT COUNT(*) FROM incidents WHERE {w}", params).fetchone()[0]
            rows = cur.execute(f"SELECT * FROM incidents WHERE {w} ORDER BY ts DESC LIMIT ? OFFSET ?",
                               params + [int(limit), int(offset)]).fetchall()
        return [self._inc_row(r) for r in rows], total

    def incident(self, iid: str) -> Optional[Dict[str, Any]]:
        with self._cursor() as cur:
            r = cur.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        return self._inc_row(r, full=True) if r else None

    def update_incident(self, iid: str, status: Optional[str] = None,
                        note: str = "") -> Optional[Dict[str, Any]]:
        inc = self.incident(iid)
        if inc is None:
            return None
        if status is not None and status not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
        notes = inc["notes"]
        notes.append({"ts": time.time(), "status": status or inc["status"],
                      "note": note[:2000]})
        with self._cursor() as cur:
            cur.execute("UPDATE incidents SET status=?, notes=?, updated_at=? WHERE id=?",
                        (status or inc["status"], json.dumps(notes), time.time(), iid))
        return self.incident(iid)

    def incident_rows_since(self, since: float) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            return [dict(r) for r in cur.execute(
                "SELECT id, ts, app_id, source, threat_class, severity, risk, action, status "
                "FROM incidents WHERE ts >= ? ORDER BY ts", (since,)).fetchall()]

    def incident_counts(self) -> Dict[str, int]:
        with self._cursor() as cur:
            rows = cur.execute("SELECT status, COUNT(*) c FROM incidents GROUP BY status").fetchall()
        return {r["status"]: r["c"] for r in rows}

    # --------------------------------------------------------------- alerts
    def create_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        aid = "ALT-" + uuid.uuid4().hex[:10]
        row = {"id": aid, "ts": time.time(), "read": 0, "channels": {}, **alert}
        with self._cursor() as cur:
            cur.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                        (aid, row["ts"], row.get("incident_id"), row["severity"],
                         row["title"], row["message"], row.get("app_id"), 0,
                         json.dumps(row["channels"])))
        return row

    def set_alert_channels(self, aid: str, channels: Dict[str, str]) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE alerts SET channels=? WHERE id=?", (json.dumps(channels), aid))

    def alerts(self, limit: int = 50, unread_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM alerts"
        if unread_only:
            sql += " WHERE read = 0"
        sql += " ORDER BY ts DESC LIMIT ?"
        with self._cursor() as cur:
            rows = cur.execute(sql, (int(limit),)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["channels"] = json.loads(d.get("channels") or "{}")
            d["read"] = bool(d["read"])
            out.append(d)
        return out

    def unread_alerts(self) -> int:
        with self._cursor() as cur:
            return cur.execute("SELECT COUNT(*) FROM alerts WHERE read = 0").fetchone()[0]

    def mark_alerts_read(self, aid: Optional[str] = None) -> int:
        with self._cursor() as cur:
            if aid:
                cur.execute("UPDATE alerts SET read=1 WHERE id=?", (aid,))
            else:
                cur.execute("UPDATE alerts SET read=1 WHERE read=0")
            return cur.rowcount

    # ---------------------------------------------------------------- files
    def log_file(self, row: Dict[str, Any]) -> str:
        fid = row.get("id") or "FILE-" + uuid.uuid4().hex[:10]
        with self._cursor() as cur:
            cur.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (fid, row.get("ts", time.time()), row["app_id"], row.get("session_id"),
                         row.get("client"), row["name"], row.get("size"), row.get("sha256"),
                         row.get("kind"), row["status"], float(row["risk"]),
                         json.dumps(row.get("summary") or {}, default=str),
                         row.get("incident_id")))
        return fid

    def files(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            rows = cur.execute("SELECT * FROM files ORDER BY ts DESC LIMIT ?", (int(limit),)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["summary"] = json.loads(d.get("summary") or "{}")
            out.append(d)
        return out

    def file_rows_since(self, since: float) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            return [dict(r) for r in cur.execute(
                "SELECT id, ts, name, kind, status, risk FROM files WHERE ts >= ? ORDER BY ts",
                (since,)).fetchall()]

    # ---------------------------------------------------------------- admin
    def purge_activity(self) -> None:
        """Delete traffic, incidents, alerts and files. Configuration is kept."""
        with self._cursor() as cur:
            for t in ("requests", "incidents", "alerts", "files"):
                cur.execute(f"DELETE FROM {t}")


__all__ = ["SOCStore", "INCIDENT_STATUSES"]
