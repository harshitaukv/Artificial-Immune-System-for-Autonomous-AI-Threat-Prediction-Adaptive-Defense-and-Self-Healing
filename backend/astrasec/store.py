"""SQLite persistence for incidents, memory cells and synthesised rules.

Kept deliberately dependency-free (stdlib ``sqlite3``, WAL mode, one file) so
the whole platform runs from a single ``python -m astrasec.api`` with no
external database. The store is an *audit log*: it is written after a verdict
has already been returned, so persistence latency never sits in the request
path.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .config import settings
from .schemas import InspectionResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    timestamp       REAL    NOT NULL,
    tenant_id       TEXT    NOT NULL,
    app_id          TEXT    NOT NULL,
    prompt_preview  TEXT,
    threat_class    TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    confidence      REAL,
    anomaly_score   REAL,
    health_score    REAL,
    action          TEXT,
    verdict         TEXT,
    recall_hit      INTEGER DEFAULT 0,
    latency_ms      REAL,
    signature_hits  TEXT,
    payload         TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts      ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant  ON incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_class   ON incidents(threat_class);
CREATE INDEX IF NOT EXISTS idx_incidents_app     ON incidents(app_id);

CREATE TABLE IF NOT EXISTS memory_cells (
    cell_id            TEXT PRIMARY KEY,
    antigen_signature  TEXT,
    threat_class       TEXT,
    exemplar_prompt    TEXT,
    defense_used       TEXT,
    encounters         INTEGER,
    successes          INTEGER,
    generation         INTEGER,
    parent_id          TEXT,
    utility            REAL,
    created_at         REAL,
    last_seen          REAL
);

CREATE TABLE IF NOT EXISTS synthesized_rules (
    rule_id       TEXT PRIMARY KEY,
    pattern       TEXT,
    threat_class  TEXT,
    action        TEXT,
    confidence    REAL,
    support       INTEGER,
    active        INTEGER,
    description   TEXT,
    created_at    REAL
);

CREATE TABLE IF NOT EXISTS reports (
    report_id   TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,          -- scan | probe | audit
    title       TEXT,
    subtitle    TEXT,
    verdict     TEXT,
    score       REAL,
    items       INTEGER,
    findings    INTEGER,
    created_at  REAL NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_kind ON reports(kind, created_at DESC);

CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id TEXT PRIMARY KEY,
    incident_id       TEXT,
    title             TEXT,
    detail            TEXT,
    priority          TEXT,
    category          TEXT,
    source            TEXT,
    created_at        REAL
);
"""


class IncidentStore:
    """Thread-safe SQLite writer/reader for the AstraSec audit trail."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = str(path or settings.database_url)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._repair_inconclusive_probes()
        self._conn.commit()

    def _repair_inconclusive_probes(self) -> None:
        """Older builds saved a probe that got no replies as score 100.

        Every attack erroring out is not a clean bill of health, it is no
        result at all. Rewrite those rows so the saved-report list shows them
        as "no response" and the roll-ups leave them out.
        """
        try:
            rows = self._conn.execute(
                "SELECT report_id, payload FROM reports WHERE kind='probe'").fetchall()
        except sqlite3.Error:
            return
        for row in rows:
            try:
                p = json.loads(row["payload"])
            except (TypeError, ValueError):
                continue
            attacks = p.get("attacks_run", 0)
            answered = p.get("attacks_answered")
            if answered is None:
                answered = max(0, attacks - sum(
                    1 for c in p.get("cases") or []
                    if c.get("category") != "control" and c.get("outcome") == "error"))
            if answered == 0 and (p.get("conclusive") is not False
                                  or p.get("grade") != "unknown"):
                p.update(conclusive=False, grade="unknown", attacks_answered=0)
                errs = [c for c in p.get("cases") or [] if c.get("outcome") == "error"]
                if not p.get("error_summary") and errs:
                    from .probe import EndpointProbe
                    p["error_summary"] = EndpointProbe._error_summary(errs)
                self._conn.execute(
                    "UPDATE reports SET score=NULL, verdict='unknown', payload=? "
                    "WHERE report_id=?", (json.dumps(p, default=str), row["report_id"]))

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ------------------------------------------------------------------
    def save_incident(self, r: InspectionResult) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO incidents VALUES
                   (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    r.incident_id, r.timestamp, r.tenant_id, r.app_id,
                    r.prompt_preview, r.prediction.threat_class.value,
                    r.prediction.severity.value, r.prediction.confidence,
                    r.behavior.anomaly_score, r.health.health_score,
                    r.defense.action.value, r.verdict,
                    1 if r.memory.recall_hit else 0, r.total_latency_ms,
                    json.dumps(r.prediction.signature_hits),
                    json.dumps(r.model_dump(mode="json"), default=str),
                ),
            )
            for rec in r.memory.recommendations:
                cur.execute(
                    """INSERT OR REPLACE INTO recommendations VALUES (?,?,?,?,?,?,?,?)""",
                    (rec.recommendation_id, r.incident_id, rec.title, rec.detail,
                     rec.priority.value, rec.category, rec.source, time.time()),
                )

    # ------------------------------------------------------------------
    # Analyst reports: scans, endpoint probes, application audits
    # ------------------------------------------------------------------
    def save_report(self, kind: str, report_id: str, payload: Dict[str, Any], *,
                    title: str = "", subtitle: str = "", verdict: str = "",
                    score: Optional[float] = 0.0, items: int = 0, findings: int = 0) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?)",
                (report_id, kind, title, subtitle, verdict,
                 None if score is None else float(score),
                 int(items), int(findings), float(payload.get("created_at", time.time())),
                 json.dumps(payload, default=str)),
            )

    def list_reports(self, kind: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        sql = "SELECT report_id, kind, title, subtitle, verdict, score, items, findings, created_at FROM reports"
        params: List[Any] = []
        if kind:
            sql += " WHERE kind = ?"
            params.append(kind)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(int(limit))
        with self._cursor() as cur:
            return [dict(r) for r in cur.execute(sql, params).fetchall()]

    def report_payloads(self, kind: str, limit: int = 200) -> List[Dict[str, Any]]:
        """Full payloads for roll-ups across many reports.

        The dashboard aggregates what the *scans* actually found, not what the
        incident table happens to hold: a scan runs with ``persist=False`` by
        default, so its items never become incidents and an incident-derived
        summary would under-report the analyst's own material by design.
        """
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT payload FROM reports WHERE kind = ? "
                "ORDER BY created_at DESC LIMIT ?", (kind, int(limit))
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            try:
                out.append(json.loads(r["payload"]))
            except json.JSONDecodeError:
                continue
        return out

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._cursor() as cur:
            row = cur.execute("SELECT payload FROM reports WHERE report_id = ?",
                              (report_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def delete_report(self, report_id: str) -> bool:
        with self._cursor() as cur:
            cur.execute("DELETE FROM reports WHERE report_id = ?", (report_id,))
            return cur.rowcount > 0

    def sync_memory(self, cells: Dict[str, Any], rules: Dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM memory_cells")
            cur.executemany(
                "INSERT INTO memory_cells VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(c.cell_id, c.antigen_signature, c.threat_class.value,
                  c.exemplar_prompt[:500], c.defense_used.value, c.encounters,
                  c.successes, c.generation, c.parent_id, c.utility,
                  c.created_at, c.last_seen) for c in cells.values()],
            )
            cur.execute("DELETE FROM synthesized_rules")
            cur.executemany(
                "INSERT INTO synthesized_rules VALUES (?,?,?,?,?,?,?,?,?)",
                [(r.rule_id, r.pattern, r.threat_class.value, r.action.value,
                  r.confidence, r.support, 1 if r.active else 0,
                  r.description, r.created_at) for r in rules.values()],
            )

    # ------------------------------------------------------------------
    def recent_incidents(self, limit: int = 100, tenant_id: Optional[str] = None,
                         threat_class: Optional[str] = None,
                         app_id: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []
        if tenant_id:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        if threat_class:
            sql += " AND threat_class = ?"
            params.append(threat_class)
        if app_id:
            sql += " AND app_id = ?"
            params.append(app_id)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        with self._cursor() as cur:
            rows = cur.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def counts_by(self, column: str) -> Dict[str, int]:
        allowed = {"threat_class", "severity", "action", "verdict", "tenant_id", "app_id"}
        if column not in allowed:
            raise ValueError(f"column must be one of {sorted(allowed)}")
        with self._cursor() as cur:
            rows = cur.execute(
                f"SELECT {column} AS k, COUNT(*) AS n FROM incidents GROUP BY {column}"
            ).fetchall()
        return {r["k"]: r["n"] for r in rows}

    def total(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute("SELECT COUNT(*) AS n FROM incidents").fetchone()["n"])

    def purge(self) -> None:
        with self._cursor() as cur:
            for table in ("incidents", "memory_cells", "synthesized_rules",
                          "recommendations", "reports"):
                cur.execute(f"DELETE FROM {table}")

    @staticmethod
    def _row(r: sqlite3.Row) -> Dict[str, Any]:
        d = dict(r)
        d.pop("payload", None)
        try:
            d["signature_hits"] = json.loads(d.get("signature_hits") or "[]")
        except json.JSONDecodeError:
            d["signature_hits"] = []
        d["recall_hit"] = bool(d.get("recall_hit"))
        return d

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["IncidentStore"]
