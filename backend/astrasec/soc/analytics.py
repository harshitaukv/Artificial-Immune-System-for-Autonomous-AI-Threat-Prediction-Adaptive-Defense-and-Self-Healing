"""Security Center analytics — the numbers behind the dashboard.

Everything is computed from stored records (the traffic log, incidents,
alerts, files, saved audits) plus the live state of the five modules, so the
dashboard shows what actually happened, not a simulation.
"""
from __future__ import annotations

import statistics
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

RANGES = {
    "24h": (24 * 3600, 3600, "%H:%M"),
    "7d": (7 * 86400, 6 * 3600, "%d %b %H:%M"),
    "30d": (30 * 86400, 86400, "%d %b"),
}
BLOCKING = {"rate_limit", "block", "quarantine"}
FLAGGING = {"monitor", "sanitize", "mask"}


def _bucket_edges(span: int, step: int, now: float) -> List[float]:
    end = (int(now) // step + 1) * step
    start = end - span
    return [start + i * step for i in range(span // step)]


def security_health(runtime_health: float, incident_rows: List[Dict[str, Any]],
                    latest_audit: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    open_ = [i for i in incident_rows if i["status"] in ("open", "investigating")]
    sev = Counter(i["severity"] for i in open_)
    exposure = max(0.0, 100.0 - (12 * sev.get("critical", 0) + 6 * sev.get("high", 0)
                                 + 2 * sev.get("medium", 0) + 0.5 * sev.get("low", 0)))
    parts = [("runtime", "AI health (Module 2)", runtime_health, 0.45,
              "Rolling health score of the protected chatbot"),
             ("exposure", "Open incident exposure", exposure, 0.35,
              "Falls with every unresolved critical or high incident")]
    if latest_audit:
        parts.append(("posture", "Latest application audit", float(latest_audit["score"]), 0.20,
                      f"{latest_audit['title']} — grade {latest_audit['grade']}"))
    wsum = sum(p[3] for p in parts)
    score = sum(p[2] * p[3] for p in parts) / wsum
    band = ("critical" if score < 40 else "high" if score < 60 else "moderate" if score < 78
            else "healthy" if score < 90 else "optimal")
    return {"score": round(score, 1), "band": band,
            "components": [{"key": k, "label": l, "value": round(v, 1),
                            "weight": round(w / wsum, 3), "detail": d}
                           for k, l, v, w, d in parts]}


def overview(store, report_store, system, gateway, bot, range_key: str = "24h") -> Dict[str, Any]:
    span, step, fmt = RANGES.get(range_key, RANGES["24h"])
    now = time.time()
    since = now - span
    reqs = store.request_rows_since(since)
    incs = store.incident_rows_since(since)
    all_incs_open, _ = store.incidents(limit=1000, status="active")
    files = store.file_rows_since(since)

    # ---- KPIs ----------------------------------------------------------
    prompts = [r for r in reqs if r["source"] == "prompt"]
    responses = [r for r in reqs if r["source"] == "response"]
    threats = [r for r in reqs if r["threat_class"] not in ("benign",) and
               r["action"] not in ("allow",)]
    # A refusal of an already-restricted client (risk 0, never analysed) is
    # enforcement of an earlier decision, not a new threat stopped.
    def pre_refusal(r):
        return r["outcome"] == "refused" and r["threat_class"] == "benign" and not r["risk"]
    blocked = [r for r in reqs if (r["action"] in BLOCKING and not pre_refusal(r))
               or (r["source"] == "response" and r["action"] == "block")]
    refused_repeat = [r for r in reqs if pre_refusal(r) and r["action"] in BLOCKING]
    sanitized = [r for r in reqs if r["action"] in ("sanitize", "mask")]
    lat = [r["latency_ms"] for r in prompts if r["latency_ms"]]
    apps = {r["app_id"] for r in reqs}
    audits = report_store.report_payloads("audit", limit=200) if report_store else []
    scans = report_store.report_payloads("scan", limit=200) if report_store else []
    probes = report_store.report_payloads("probe", limit=200) if report_store else []
    for a in audits:
        apps.add(a.get("app_id") or a.get("app_name"))
    latest_audit = None
    if audits:
        a = max(audits, key=lambda x: x.get("created_at", 0))
        latest_audit = {"title": a.get("app_name", "App"), "score": a.get("posture_score", 0),
                        "grade": a.get("grade", "?"), "audit_id": a.get("audit_id")}

    runtime_health = system.health.current(gateway.app.app_id) if system else 100.0
    health = security_health(runtime_health, all_incs_open, latest_audit)

    # ---- trend -----------------------------------------------------------
    edges = _bucket_edges(span, step, now)
    trend = [{"t": e, "label": time.strftime(fmt, time.localtime(e)), "total": 0, "allowed": 0,
              "flagged": 0, "blocked": 0, "risk_sum": 0.0, "risk_n": 0, "incidents": 0}
             for e in edges]

    def idx(ts: float) -> int:
        return max(0, min(len(edges) - 1, int((ts - edges[0]) // step)))

    for r in reqs:
        b = trend[idx(r["ts"])]
        if r["source"] == "response":
            if r["action"] == "block":
                b["blocked"] += 1
            elif r["action"] == "mask":
                b["flagged"] += 1
            continue
        b["total"] += 1
        if r["action"] in BLOCKING or r["outcome"] == "refused":
            b["blocked"] += 1
        elif r["action"] in FLAGGING or r["action"] == "sanitize":
            b["flagged"] += 1
        else:
            b["allowed"] += 1
        if r["source"] == "prompt" and r["outcome"] != "refused":
            b["risk_sum"] += r["risk"]
            b["risk_n"] += 1
    for i in incs:
        trend[idx(i["ts"])]["incidents"] += 1
    for b in trend:
        b["mean_risk"] = round(b["risk_sum"] / b["risk_n"], 1) if b["risk_n"] else None
        b.pop("risk_sum"), b.pop("risk_n")

    # ---- distributions -----------------------------------------------------
    by_class = Counter(i["threat_class"] for i in incs)
    by_severity = Counter(i["severity"] for i in incs)
    by_action = Counter(r["action"] for r in reqs if r["source"] != "response")
    by_source = defaultdict(lambda: {"total": 0, "flagged": 0, "blocked": 0})
    for r in reqs:
        s = by_source[r["source"]]
        s["total"] += 1
        if r["action"] in BLOCKING or (r["source"] == "response" and r["action"] == "block"):
            s["blocked"] += 1
        elif r["action"] not in ("allow",):
            s["flagged"] += 1
    hist = [0] * 10
    for r in prompts:
        if r["outcome"] != "refused":
            hist[min(9, int(r["risk"] // 10))] += 1

    clients = defaultdict(lambda: {"requests": 0, "flagged": 0, "max_risk": 0.0, "last": 0.0})
    for r in reqs:
        if not r.get("client"):
            continue
        c = clients[r["client"]]
        c["requests"] += 1
        if r["action"] not in ("allow",):
            c["flagged"] += 1
        c["max_risk"] = max(c["max_risk"], r["risk"])
        c["last"] = max(c["last"], r["ts"])
    restricted = {c["client"]: c for c in gateway.restricted_clients()} if gateway else {}
    top_clients = sorted(({"client": k, **v, "state": restricted.get(k, {}).get("state", "active")}
                          for k, v in clients.items()),
                         key=lambda c: (-c["flagged"], -c["max_risk"]))[:6]

    # ---- incident handling ------------------------------------------------
    counts = store.incident_counts()
    triage = []
    resolved_in_range = 0
    fp_in_range = 0
    for i in incs:
        if i["status"] == "false_positive":
            fp_in_range += 1
        if i["status"] in ("resolved", "false_positive"):
            resolved_in_range += 1
    recent, _ = store.incidents(limit=200, since=since)
    for inc in recent:
        full = None
        if inc["status"] != "open":
            full = store.incident(inc["id"])
        if full and full["notes"]:
            triage.append(full["notes"][0]["ts"] - full["ts"])

    # ---- immune memory --------------------------------------------------------
    mem = system.memory if system else None
    memory = {}
    if mem is not None:
        primary = [c for c in mem.cells.values() if c.generation == 0]
        memory = {
            "known_patterns": len(primary),
            "repeated_patterns": sum(1 for c in primary if c.encounters > 1),
            "repeat_encounters": sum(max(0, c.encounters - 1) for c in primary),
            "new_patterns": sum(1 for c in primary if c.created_at >= since),
            "clones": sum(1 for c in mem.cells.values() if c.generation > 0),
            "recall_rate": round(mem.recall_rate(), 4),
            "immunity_strength": round(mem.immunity_strength(), 4),
            "by_class": dict(Counter(c.threat_class.value for c in primary)),
            "rules_active": len(mem.promoted_rules),
            "rules_pending": len([r for r in mem.candidate_rules.values()
                                  if getattr(r, "confidence", 0) > 0]),
        }
    decided = [i for i in incs if i["action"] in ("sanitize", "mask", "rate_limit", "block",
                                                   "quarantine")]
    stopped = [i for i in decided if i["status"] != "false_positive"]
    memory["defence_success_rate"] = round(len(stopped) / len(decided), 4) if decided else None

    file_status = Counter(f["status"] for f in files)

    return {
        "range": range_key, "generated_at": now, "bucket_seconds": step,
        "kpis": {
            "requests": len([r for r in reqs if r["source"] != "response"]),
            "prompts": len(prompts),
            "files": len(files),
            "responses_checked": len([r for r in reqs if r["source"] == "prompt"
                                      and r["outcome"] in ("answered", "sanitized")]),
            "threats_detected": len(threats),
            "threats_blocked": len(blocked),
            "sanitized": len(sanitized),
            "repeat_refusals": len(refused_repeat),
            "active_incidents": counts.get("open", 0) + counts.get("investigating", 0),
            "open_critical": sum(1 for i in all_incs_open if i["severity"] == "critical"),
            "incidents_in_range": len(incs),
            "unread_alerts": store.unread_alerts(),
            "applications": len(apps) or 1,
            "ai_bots": len({r["app_id"] for r in prompts}) or 1,
            "audits": len(audits), "scans": len(scans), "probes": len(probes),
            "block_rate": round(len(blocked) / len(threats), 4) if threats else None,
            "p50_latency_ms": round(statistics.median(lat), 1) if lat else None,
            "p95_latency_ms": round(sorted(lat)[int(0.95 * (len(lat) - 1))], 1) if lat else None,
            "median_triage_minutes": round(statistics.median(triage) / 60, 1) if triage else None,
            "false_positive_rate": round(fp_in_range / len(incs), 4) if incs else None,
        },
        "health": health,
        "trend": trend,
        "threat_classes": dict(by_class),
        "severity": dict(by_severity),
        "actions": dict(by_action),
        "sources": dict(by_source),
        "risk_histogram": hist,
        "top_clients": top_clients,
        "files": dict(file_status),
        "memory": memory,
        "incident_status": counts,
        "latest_audit": latest_audit,
        "bot": bot.stats() if bot else {},
    }


__all__ = ["overview", "security_health", "RANGES"]
