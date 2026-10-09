"""The AstraSec Security Gateway — one pipeline for every untrusted input.

Everything that enters the protected application passes through here before
the model sees it, and everything the model says passes through here before
the user sees it:

    chat message ──┐                                  ┌── ALLOW / MONITOR ─▶ model
    uploaded file ─┼─▶ five modules ─▶ Risk Analyzer ─┼── SANITIZE ─────────▶ model (cleaned)
                   │                                  └── RATE LIMIT / BLOCK / QUARANTINE ─▶ refused
    model reply ───┴─▶ Response Analyzer ─▶ SAFE / MASK / BLOCK ─▶ user

Every decision is logged; every significant one becomes an incident; every
incident at or above the owner's alert level raises an alert; every detected
attack is committed to immune memory.

Three rules this module never breaks:

1. **A blocked input never reaches the model.** The gateway returns no text to
   forward, so there is nothing for the caller to send.
2. **Cleaning is verified, not assumed.** A sanitised message is re-analysed;
   if the attack survives, it is blocked.
3. **Nothing sensitive is stored.** Excerpts and evidence are redacted by
   :mod:`astrasec.soc.dlp` before they are written anywhere.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import threading
import time
import unicodedata
import uuid
import zipfile
from collections import defaultdict, deque
from pathlib import PurePath
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..config import settings
from ..probe import _COMPLIANCE
from ..scanner import (
    DocumentError, MissingDependency, ScanItem, UnsupportedFile, decode_text,
    looks_defensive, parse_file,
)
from ..schemas import AppContext, DefenseAction, InspectRequest, ThreatClass
from ..signatures import RESPONSE_SIGNATURES, scan
from . import dlp
from .alerts import AlertDispatcher
from .assistant import DocContext, build_table, summarise_json
from .policy import ACTION_RANK, SecurityPolicy
from .risk import RiskAnalyzer, RiskBreakdown, severity_for
from .store import SOCStore

ALLOWED_FILE_TYPES = {".pdf": "pdf", ".docx": "docx", ".txt": "txt", ".md": "md",
                      ".csv": "csv", ".json": "json"}

USER_NOTICE = {
    "sanitize": "Part of your message was removed by the security policy before it was answered.",
    "rate_limit": "Your recent messages were flagged as risky. Please wait a minute before trying again.",
    "block": "This request was blocked because it violated the application's security policy.",
    "quarantine": "This conversation has been paused by the security policy. Please try again later.",
}

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _rank(action: str) -> int:
    return ACTION_RANK.get(action, 0)


def _stronger(a: str, b: str) -> str:
    return a if _rank(a) >= _rank(b) else b


def safe_name(name: str) -> str:
    base = PurePath((name or "upload").replace("\\", "/")).name
    base = _CTRL.sub("", unicodedata.normalize("NFKC", base)).strip()
    base = re.sub(r"[<>:\"|?*]", "_", base)
    return (base or "upload")[:120]


class SecurityGateway:
    def __init__(self, system, store: SOCStore, dispatcher: AlertDispatcher,
                 app: AppContext) -> None:
        self.system = system
        self.store = store
        self.dispatcher = dispatcher
        self.app = app
        self._lock = threading.RLock()
        self._throttle: Dict[str, float] = {}
        self._uploads: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=64))
        self._last_turn: Dict[str, Tuple[str, float, float]] = {}
        self._memory_dirty = 0
        self.persist_memory = True
        self.policy = self.load_policy()

    # ------------------------------------------------------------ config
    def load_policy(self) -> SecurityPolicy:
        try:
            self.policy = SecurityPolicy(**(self.store.get("policy") or {}))
        except Exception:
            self.policy = SecurityPolicy()
        return self.policy

    def save_policy(self, policy: SecurityPolicy) -> SecurityPolicy:
        self.store.put("policy", policy.model_dump())
        self.policy = policy
        return policy

    @property
    def risk(self) -> RiskAnalyzer:
        return RiskAnalyzer(self.policy)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def tenant(client: str) -> str:
        return f"client:{client or 'unknown'}"

    def client_status(self, client: str, now: Optional[float] = None) -> Tuple[str, float]:
        """('ok'|'rate_limit'|'quarantine', until)."""
        now = now or time.time()
        st = self.system.defense.state(self.tenant(client))
        if st.is_quarantined(now):
            return "quarantine", st.quarantined_until
        until = self._throttle.get(self.tenant(client), 0.0)
        if until > now:
            return "rate_limit", until
        return "ok", 0.0

    def release_client(self, client: str) -> bool:
        t = self.tenant(client)
        self._throttle.pop(t, None)
        return self.system.defense.release(t) or True

    def restricted_clients(self) -> List[Dict[str, Any]]:
        now = time.time()
        out = []
        for tid, st in self.system.defense.tenants.items():
            if tid.startswith("client:") and st.is_quarantined(now):
                out.append({"client": tid[7:], "state": "quarantined", "until": st.quarantined_until,
                            "strikes": st.strikes})
        for tid, until in self._throttle.items():
            if until > now and not any(o["client"] == tid[7:] for o in out):
                out.append({"client": tid[7:], "state": "rate_limited", "until": until,
                            "strikes": self.system.defense.state(tid).strikes})
        return out

    def _memory_meta(self, text: str) -> Tuple[float, Optional[Dict[str, Any]]]:
        cell, aff = self.system.memory.recall(text)
        if cell is None:
            return 0.0, None
        return float(aff), {"cell_id": cell.cell_id, "threat_class": cell.threat_class.value,
                            "encounters": cell.encounters, "affinity": round(float(aff), 4)}

    def _note_memory_change(self) -> None:
        if not self.persist_memory:
            return
        self._memory_dirty += 1
        if self._memory_dirty >= 15:
            self._memory_dirty = 0
            threading.Thread(target=self._save_memory, daemon=True).start()

    def _save_memory(self) -> None:
        try:
            with self._lock:
                self.system.memory.save()
        except Exception:
            pass

    def _raise(self, incident: Dict[str, Any]) -> Optional[str]:
        try:
            alert = self.dispatcher.raise_alert(incident=incident, app_name=self.app.app_name)
            return alert["id"]
        except Exception:
            return None

    def _log_request(self, **row) -> str:
        return self.store.log_request({"app_id": self.app.app_id, **row})

    # ================================================================
    # Owner feedback and tooling
    # ================================================================
    def false_positive(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """The owner says this was not an attack: un-learn it.

        The (redacted) text joins the benign hold-out that every candidate
        rule is validated against, the matching memory cell and its clones are
        removed so they stop sharpening future predictions, and any pending
        rule that fires on the text is withdrawn.
        """
        detail = incident.get("detail") or {}
        text = detail.get("redacted_text") or ""
        out = {"memory_cells_removed": 0, "candidate_rules_withdrawn": 0, "holdout_added": False}
        if not text:
            return out
        with self._lock:
            mem = self.system.memory
            cell, aff = mem.recall(text)
            if cell is not None and aff >= settings.memory_affinity_threshold:
                doomed = [cid for cid, c in mem.cells.items()
                          if cid == cell.cell_id or c.parent_id == cell.cell_id]
                for cid in doomed:
                    mem.cells.pop(cid, None)
                mem._dirty = True
                out["memory_cells_removed"] = len(doomed)
            if len(text) > 10:
                mem.benign_holdout.append(text)
                out["holdout_added"] = True
            for rid, rule in list(mem.candidate_rules.items()):
                try:
                    if re.search(rule.pattern, text, re.IGNORECASE):
                        mem.candidate_rules.pop(rid, None)
                        out["candidate_rules_withdrawn"] += 1
                except re.error:
                    pass
            self._note_memory_change()
        return out

    def dry_run(self, text: str, kind: str = "prompt") -> Dict[str, Any]:
        """Analyse without logging, learning or enforcing — the owner's test bench."""
        text = _CTRL.sub("", text or "")[:20000]
        if kind == "response":
            findings = dlp.detect(text)
            masked, _ = dlp.redact(text, findings)
            leak = bool(_COMPLIANCE.search(text)) or any(
                s.id == "SIG-RS-004" and s.pattern.search(text) for s in RESPONSE_SIGNATURES)
            return {"kind": "response", "findings": [f.public() for f in findings],
                    "masked": masked, "leak": leak,
                    "action": "block" if leak else ("mask" if findings else "allow")}
        with self._lock:
            sim, meta = self._memory_meta(text)
            r = self.system.inspect(InspectRequest(prompt=text, tenant_id="owner-test",
                                                   app=self.app, persist=False))
            b = self.risk.from_inspection(r, sim if meta else 0.0, meta, use_behavior=False)
        return {"kind": "prompt", "breakdown": b.as_dict(), "action": b.band_action,
                "explanation": r.prediction.explanation, "rationale": r.defense.rationale,
                "signatures": [{**d, "match": dlp.safe_excerpt(d.get("match", ""), 120)}
                               for d in r.prediction.signature_detail],
                "indicators": r.prediction.top_indicators[:8],
                "sanitized_preview": self.system.defense.sanitize(text)[0]
                if _rank(b.band_action) >= _rank("sanitize") else None,
                "sensitive": [f.public() for f in dlp.detect(text)]}

    def validate_rule(self, rule) -> Dict[str, Any]:
        """Test a candidate self-healing rule before the owner approves it."""
        try:
            rx = re.compile(rule.pattern, re.IGNORECASE)
        except re.error as exc:
            return {"valid": False, "error": f"pattern does not compile: {exc}"}
        benign = list(self.system.memory.benign_holdout)
        rows, _ = self.store.incidents(limit=500)
        attacks = []
        for row in rows:
            if row["status"] == "false_positive" or row["source"] not in ("prompt", "file"):
                continue
            full = self.store.incident(row["id"]) or {}
            t = (full.get("detail") or {}).get("redacted_text")
            if t:
                attacks.append(t)
        attacks += [c.exemplar_prompt for c in self.system.memory.cells.values()
                    if c.generation == 0 and c.threat_class.value == rule.threat_class.value]
        b_hits = [t for t in benign if rx.search(t)]
        a_hits = [t for t in attacks if rx.search(t)]
        result = {
            "valid": True, "tested_at": time.time(),
            "benign_tested": len(benign), "benign_hits": len(b_hits),
            "attack_tested": len(attacks), "attack_hits": len(a_hits),
            "false_positive_rate": round(len(b_hits) / len(benign), 5) if benign else None,
            "coverage": round(len(a_hits) / len(attacks), 4) if attacks else None,
            "benign_examples": [dlp.safe_excerpt(t, 140) for t in b_hits[:5]],
            "attack_examples": [dlp.safe_excerpt(t, 140) for t in a_hits[:5]],
        }
        result["passed"] = bool(benign) and not b_hits and bool(a_hits)
        return result

    # ================================================================
    # 1. Prompt security
    # ================================================================
    def analyse_prompt(self, text: str, session_id: str, client: str) -> Dict[str, Any]:
        t0 = time.perf_counter()
        now = time.time()
        pol = self.policy
        text = _CTRL.sub("", text or "").strip()
        tenant = self.tenant(client)
        excerpt = dlp.safe_excerpt(text) if pol.store_message_excerpts else ""

        if not text:
            return {"action": "reject", "forward": None, "notice": "Please type a message.",
                    "request_id": None, "incident_id": None}
        if len(text) > pol.max_message_chars:
            rid = self._log_request(session_id=session_id, client=client, source="prompt",
                                    threat_class="benign", severity="none", risk=0, action="reject",
                                    outcome="rejected", latency_ms=0, excerpt=excerpt)
            return {"action": "reject", "forward": None, "request_id": rid, "incident_id": None,
                    "notice": f"That message is too long — the limit is "
                              f"{pol.max_message_chars:,} characters."}

        with self._lock:
            status, until = self.client_status(client, now)
            if status != "ok":
                rid = self._log_request(session_id=session_id, client=client, source="prompt",
                                        threat_class="benign", severity="none", risk=0,
                                        action=status, outcome="refused", latency_ms=0,
                                        excerpt=excerpt)
                return {"action": status, "forward": None, "request_id": rid,
                        "incident_id": None, "notice": USER_NOTICE[status], "until": until}

            # Secrets are values, not instructions. Analysing the text with them
            # replaced by typed placeholders stops a pasted API key from reading
            # as "obfuscated" gibberish, and keeps them out of immune memory.
            analysed, secret_findings = dlp.neutralise(text)
            masked = dlp.redact(text, secret_findings)[0] if secret_findings else text
            sim, meta = self._memory_meta(analysed)
            result = self.system.inspect(InspectRequest(
                prompt=analysed, tenant_id=tenant, session_id=session_id, app=self.app,
                channel="chat", persist=True))
            b = self.risk.from_inspection(result, sim if meta else 0.0, meta)
            multi_turn = False

            # A split attack: two messages that are each mild, but dangerous together.
            prev = self._last_turn.get(session_id)
            if prev and now - prev[2] < 600 and b.band_action in ("allow", "monitor", "sanitize"):
                joined = prev[0][-1500:] + "\n" + analysed
                r2 = self.system.inspect(InspectRequest(prompt=joined, tenant_id=tenant,
                                                        app=self.app, persist=False))
                b2 = self.risk.from_inspection(r2, 0.0, None)
                if b2.overall > max(prev[1], b.overall) + 10 and \
                        _rank(b2.band_action) > _rank(b.band_action):
                    b2.notes.append("multi-turn attack: completes an instruction begun in the "
                                    "previous message")
                    b, result, multi_turn = b2, r2, True
            self._last_turn[session_id] = (analysed, b.overall, now)

            action = b.band_action
            # Module 4's own policies escalate but never relax the band decision:
            # signature-mandated blocks, contextual rules, self-healing rules,
            # its rate limit and standing quarantine.
            engine = result.defense.action.value
            engine_policies = [p for p in result.defense.policy_ids if not p.startswith("POL-THRESH")]
            if engine_policies and _rank(engine) > _rank(action):
                action = engine
                b.notes.append(f"escalated by defence policy {', '.join(engine_policies[:3])}")

            forward: Optional[str] = None
            sanitized: Optional[str] = None
            if action in ("allow", "monitor"):
                forward = masked
            elif action == "sanitize":
                sanitized = (result.defense.sanitized_prompt
                             or self.system.defense.sanitize(analysed)[0])
                residual = self.system.prediction.predict(sanitized)
                rb = self.risk.score(
                    threat_class=getattr(residual["threat_class"], "value",
                                         residual["threat_class"]), probabilities=residual["probabilities"],
                    ml_confidence=residual["confidence"], signature_risk=residual["signature_risk"],
                    signatures=residual["signature_hits"], similarity=0.0, similarity_meta=None,
                    behavior=0.0, application=0.0, use_behavior=False)
                meaningful = re.sub(r"\[[A-Z\-]+\]|[^A-Za-z]", "", sanitized)
                if _rank(rb.band_action) >= _rank("sanitize") or len(meaningful) < 3:
                    action = "block"
                    b.notes.append("attack survived sanitisation" if len(meaningful) >= 3
                                   else "nothing legitimate left after sanitisation")
                else:
                    forward = sanitized

            st = self.system.defense.state(tenant)
            # Quarantine is for repeat offenders: a client's first blocked
            # attempt is blocked, however high it scores; the next one that
            # lands in the quarantine band isolates the client.
            # (Module 4 has already counted this request if it blocked it.)
            prior_strikes = st.strikes - (1 if engine == "block" else 0)
            if action == "quarantine" and b.band_action == "quarantine" and prior_strikes <= 0 \
                    and engine != "quarantine":
                action = "block"
                b.notes.append("first offence from this client: blocked, not quarantined")
            if action == "rate_limit":
                self._throttle[tenant] = now + pol.rate_limit_cooldown_seconds
            if action == "block" and _rank(engine) < _rank("block"):
                st.strikes += 1
                if st.strikes >= settings.quarantine_strike_count:
                    action = "quarantine"
                    b.notes.append(f"{settings.quarantine_strike_count} blocked attempts: "
                                   f"client quarantined")
            if action == "quarantine":
                st.quarantined_until = now + pol.quarantine_minutes * 60
                st.strikes = 0
            if _rank(action) >= _rank("sanitize") and b.threat_class != "benign":
                self._note_memory_change()

        latency = (time.perf_counter() - t0) * 1000
        threat = b.threat_class
        severity = b.severity if _rank(action) >= _rank("monitor") else "none"
        if action == "monitor" and threat != "benign":
            severity = max(severity, "low", key=dlp.SEVERITY_ORDER.get)

        incident_id = None
        if _rank(action) >= _rank("sanitize") or (action == "monitor" and threat != "benign"):
            title = {
                "sanitize": "Suspicious message sanitised",
                "rate_limit": "Risky message throttled",
                "block": "Attack blocked before the model",
                "quarantine": "Client quarantined",
                "monitor": "Suspicious message monitored",
            }[action]
            incident = {
                "app_id": self.app.app_id, "source": "prompt", "threat_class": threat,
                "severity": severity, "risk": b.overall, "ml_confidence": b.ml_confidence,
                "behavior": b.behavior, "similarity": b.similarity, "signature": b.signature,
                "app_risk": b.application, "action": action,
                "defense": [f"BAND-{action.upper()}"] + [
                    p for p in dict.fromkeys(result.defense.policy_ids)
                    if not p.startswith("POL-THRESH")],
                "session_id": session_id, "client": client,
                "title": f"{title}: {threat.replace('_', ' ')}", "excerpt": excerpt,
                "detail": {
                    "breakdown": b.as_dict(),
                    "redacted_text": dlp.redact(text)[0][:4000],
                    "sanitized_text": dlp.redact(sanitized)[0][:4000] if sanitized else None,
                    "forwarded_to_model": forward is not None,
                    "multi_turn": multi_turn,
                    "explanation": result.prediction.explanation,
                    "rationale": result.defense.rationale,
                    "signatures": [{**d, "match": dlp.safe_excerpt(d.get("match", ""), 120)}
                                   for d in result.prediction.signature_detail],
                    "indicators": result.prediction.top_indicators[:8],
                    "behavior": {"anomaly": result.behavior.anomaly_score,
                                 "explanation": result.behavior.explanation,
                                 "deviating": result.behavior.deviating_features[:5]},
                    "memory": {"recall": b.matched_memory,
                               "explanation": result.memory.explanation},
                    "narrative": result.narrative,
                    "recommendations": [r.model_dump(mode="json")
                                        for r in result.memory.recommendations[:4]],
                },
            }
            incident_id = self.store.create_incident(incident)
            incident["id"] = incident_id
            if _rank(action) >= _rank(pol.alert_min_action) and (
                    threat != "benign" or action in ("block", "quarantine")):
                self._raise(incident)

        rid = self._log_request(session_id=session_id, client=client, source="prompt",
                                threat_class=threat, severity=severity, risk=round(b.overall, 1),
                                action=action, outcome={"allow": "answered", "monitor": "answered",
                                                        "sanitize": "sanitized"}.get(action, "refused"),
                                latency_ms=round(latency, 1), excerpt=excerpt,
                                incident_id=incident_id)
        notice = USER_NOTICE.get(action)
        if forward is not None and secret_findings:
            notice = ((notice + " ") if notice else "") + (
                "Keys, passwords or tokens in your message were masked before the assistant saw them.")
        return {
            "request_id": rid, "action": action, "forward": forward,
            "notice": notice, "incident_id": incident_id,
            "breakdown": b.as_dict(), "latency_ms": round(latency, 1),
        }

    # ================================================================
    # 2. Response security
    # ================================================================
    def analyse_response(self, text: str, system_prompt: str, canary: str,
                         session_id: str, client: str,
                         prompt_request_id: Optional[str] = None) -> Dict[str, Any]:
        pol = self.policy
        reasons: List[str] = []
        leak = False
        if canary and canary in text:
            leak = True
            reasons.append("response contains the system prompt's canary marker")
        overlap = self._prompt_overlap(system_prompt, text)
        if overlap >= 2:
            leak = True
            reasons.append(f"response repeats {overlap} passages of the system prompt")
        for sig in RESPONSE_SIGNATURES:
            if sig.id == "SIG-RS-004" and sig.pattern.search(text):
                leak = True
                reasons.append(sig.description)
        if _COMPLIANCE.search(text):
            leak = True
            reasons.append("response shows the model complying with a jailbreak")

        cats = ("secret", "infrastructure") + (("pii",) if pol.mask_pii_in_responses else ())
        findings = dlp.detect(text, cats, tuple(pol.allowed_public_values))
        masked, _ = dlp.redact(text, findings)

        if leak and pol.block_system_prompt_leaks:
            action, out = "block", None
        elif findings:
            action, out = "mask", masked
        else:
            return {"action": "allow", "text": text, "incident_id": None, "findings": []}

        worst = max([f.severity for f in findings] or ["none"], key=dlp.SEVERITY_ORDER.get)
        risk = 95.0 if leak else {"critical": 85.0, "high": 70.0, "medium": 50.0,
                                  "low": 30.0}.get(worst, 30.0)
        kinds = sorted({f.label for f in findings})
        incident = {
            "app_id": self.app.app_id, "source": "response",
            "threat_class": "data_exfiltration" if (leak or worst in ("critical", "high"))
            else "sensitive_data",
            "severity": severity_for(risk), "risk": risk, "ml_confidence": None,
            "behavior": None, "similarity": None, "signature": None, "app_risk": None,
            "action": action, "defense": ["RESPONSE-GUARD"], "session_id": session_id,
            "client": client,
            "title": ("Model response blocked: " + reasons[0]) if leak
            else f"Sensitive data masked in model response ({', '.join(kinds)[:80]})",
            "excerpt": dlp.safe_excerpt(masked),
            "detail": {"reasons": reasons, "findings": [f.public() for f in findings],
                       "redacted_response": masked[:4000], "prompt_request_id": prompt_request_id,
                       "breakdown": {"overall": risk, "severity": severity_for(risk),
                                     "notes": reasons}},
        }
        iid = self.store.create_incident(incident)
        incident["id"] = iid
        if pol.alert_on_response_leak and risk > pol.bands.sanitize:
            self._raise(incident)
        self._log_request(session_id=session_id, client=client, source="response",
                          threat_class=incident["threat_class"], severity=incident["severity"],
                          risk=risk, action=action,
                          outcome="blocked" if action == "block" else "masked",
                          latency_ms=None, excerpt=incident["excerpt"], incident_id=iid)
        return {"action": action, "text": out, "incident_id": iid,
                "findings": [f.public() for f in findings], "reasons": reasons}

    @staticmethod
    def _prompt_overlap(system_prompt: str, text: str, n: int = 7) -> int:
        def grams(s: str) -> set:
            w = re.findall(r"[a-z0-9']+", s.lower())
            return {" ".join(w[i:i + n]) for i in range(len(w) - n + 1)}
        sp = grams(system_prompt)
        if not sp:
            return 0
        # Each shared 7-word run is one piece of evidence; three or more means a
        # passage of 9+ words was copied out of the instructions.
        hits = len(grams(text) & sp)
        return 0 if hits == 0 else (1 if hits < 3 else 2 + hits // 6)

    # ================================================================
    # 3. File security
    # ================================================================
    def validate_file(self, name: str, raw: bytes) -> Tuple[Optional[str], Optional[str]]:
        """(kind, error)."""
        ext = PurePath(name).suffix.lower()
        if ext not in ALLOWED_FILE_TYPES:
            return None, (f"'{ext or 'no extension'}' files aren't accepted here. "
                          f"Send PDF, Word (.docx), TXT, Markdown, CSV or JSON.")
        if not raw:
            return None, "That file is empty."
        if len(raw) > self.policy.max_file_mb * 1024 * 1024:
            return None, f"That file is larger than the {self.policy.max_file_mb:g} MB limit."
        kind = ALLOWED_FILE_TYPES[ext]
        if kind == "pdf":
            if b"%PDF-" not in raw[:1024]:
                return None, "That file is named .pdf but is not a PDF."
        elif kind == "docx":
            try:
                zf = zipfile.ZipFile(io.BytesIO(raw))
                infos = zf.infolist()
                if len(infos) > 2000 or sum(i.file_size for i in infos) > 80 * 1024 * 1024:
                    return None, "That Word file expands to an unsafe size and was refused."
                if "word/document.xml" not in {i.filename for i in infos}:
                    return None, "That file is named .docx but is not a Word document."
                if any(i.filename.lower().endswith(("vbaproject.bin", ".exe", ".dll", ".bat"))
                       for i in infos):
                    return None, "That Word file contains macros or executables and was refused."
            except zipfile.BadZipFile:
                return None, "That file is named .docx but is not a Word document."
        else:
            if b"\x00" in raw[:8192] and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                return None, "That file contains binary data, not text."
            if kind == "json":
                try:
                    json.loads(decode_text(raw))
                except ValueError:
                    return None, "That file is not valid JSON."
        return kind, None

    def analyse_file(self, name: str, raw: bytes, session_id: str, client: str
                     ) -> Tuple[Dict[str, Any], Optional[DocContext]]:
        t0 = time.perf_counter()
        pol = self.policy
        name = safe_name(name)
        now = time.time()
        tenant = self.tenant(client)
        sha = hashlib.sha256(raw or b"").hexdigest()
        fid = "FILE-" + uuid.uuid4().hex[:10]

        def reject(msg: str, status: str = "rejected") -> Tuple[Dict[str, Any], None]:
            self.store.log_file({"id": fid, "app_id": self.app.app_id, "session_id": session_id,
                                 "client": client, "name": name, "size": len(raw or b""),
                                 "sha256": sha, "kind": PurePath(name).suffix.lower().lstrip("."),
                                 "status": status, "risk": 0, "summary": {"reason": msg}})
            return {"file_id": fid, "name": name, "status": status, "notice": msg,
                    "incident_id": None}, None

        status, _ = self.client_status(client, now)
        if status != "ok":
            return reject(USER_NOTICE[status], "refused")
        uploads = self._uploads[tenant]
        while uploads and now - uploads[0] > 60:
            uploads.popleft()
        if len(uploads) >= pol.uploads_per_minute:
            return reject("You're uploading files too quickly. Please wait a minute.", "refused")
        uploads.append(now)

        kind, err = self.validate_file(name, raw)
        if err:
            return reject(err)
        try:
            items, _ = parse_file(name, raw, split="paragraph")
        except (UnsupportedFile, DocumentError) as exc:
            return reject(f"I couldn't read that file: {exc}")
        except MissingDependency as exc:
            return reject(f"The server can't read {kind.upper()} files yet ({exc}).")
        except Exception as exc:
            return reject(f"I couldn't read that file ({type(exc).__name__}).")

        full_text = (decode_text(raw) if kind in ("txt", "md", "csv", "json")
                     else "\n\n".join(i.text for i in items
                                      if not i.context.get("aggregate")))
        if not full_text.strip():
            return reject("I couldn't find any readable text in that file. If it is a scanned "
                          "PDF, it needs OCR first.")

        # ---- analysis units: items, plus windows that span line breaks ----
        units: List[Tuple[str, str, Dict[str, Any]]] = [(i.text, i.locator, i.context) for i in items]
        # The file name is attacker-chosen text that ends up in the model's
        # context too, so it is inspected like any other part of the file.
        stem = re.sub(r"[_\-.]+", " ", PurePath(name).stem).strip()
        if len(stem.split()) >= 3:
            units.append((stem, "file name", {"filename": True}))
        if kind in ("txt", "md", "csv") and len(full_text) > 400:
            step, width = 450, 700
            for start in range(0, min(len(full_text), 150 * step), step):
                chunk = full_text[start:start + width]
                if len(chunk.strip()) > 40:
                    line = full_text.count("\n", 0, start) + 1
                    units.append((chunk, f"around line {line}", {"window": True}))

        # Analyse with secrets replaced by placeholders (see analyse_prompt).
        units = [(dlp.neutralise(t)[0], loc, ctx) for t, loc, ctx in units]
        with self._lock:
            texts = [u[0][:5000] for u in units]
            P = self.system.prediction.predict_proba(texts) if texts else []
            classes = list(self.system.prediction.classes_)
            bi = classes.index("benign") if "benign" in classes else 0
            candidates = []
            for idx, (t, loc, ctx) in enumerate(units):
                p_benign = float(P[idx][bi])
                hit = len(units) <= 3000 and bool(scan(t[:3000], decode=len(t) < 2000))
                # A one- or two-word cell — a name, a label — cannot carry an
                # instruction; without a signature it is never a candidate.
                if len(t.split()) < 3 and not hit:
                    continue
                if p_benign < 0.7 or hit:
                    candidates.append((1 - p_benign, idx))
            candidates.sort(reverse=True)

            flagged: List[Dict[str, Any]] = []
            seen_text = set()
            for _, idx in candidates[:40]:
                t, loc, ctx = units[idx]
                key = re.sub(r"\s+", " ", t.strip().lower())[:300]
                if key in seen_text:
                    continue
                seen_text.add(key)
                sim, meta = self._memory_meta(t)
                r = self.system.inspect(InspectRequest(prompt=t[:5000], tenant_id=tenant,
                                                       app=self.app, channel="rag", persist=False))
                b = self.risk.from_inspection(r, sim if meta else 0.0, meta, use_behavior=False)
                if b.threat_class == "benign" or _rank(b.band_action) < _rank("sanitize"):
                    continue
                if looks_defensive(t):
                    b.overall *= 0.5
                    b.notes.append("reads as a defensive instruction; weighted down")
                if ctx.get("hidden"):
                    b.overall = min(100.0, b.overall + 8)
                    b.notes.append("hidden text in the document")
                b.band_action = pol.bands.action_for(b.overall)
                b.severity = severity_for(b.overall)
                if _rank(b.band_action) < _rank("sanitize"):
                    continue
                flagged.append({"locator": loc, "window": bool(ctx.get("window")),
                                "threat_class": b.threat_class, "risk": round(b.overall, 1),
                                "severity": b.severity, "signatures": b.signatures,
                                "excerpt": dlp.safe_excerpt(t, 220), "notes": b.notes,
                                "_text": t, "_breakdown": b})

        # Windows only matter when they caught something no single item did.
        item_flagged = [f for f in flagged if not f["window"]]
        if item_flagged:
            flagged = item_flagged + [f for f in flagged if f["window"] and not any(
                g["excerpt"][:60] in f["excerpt"] for g in item_flagged)]
        flagged.sort(key=lambda f: -f["risk"])

        # ---- sensitive data and links ------------------------------------
        dlp_findings: List[Dict[str, Any]] = []
        if kind in ("txt", "md", "csv"):
            for f in dlp.detect(full_text):
                d = f.public()
                d["locator"] = (f"row {f.line}" if kind == "csv" else f"line {f.line}")
                dlp_findings.append(d)
        else:
            for it in items:
                if it.context.get("aggregate"):
                    continue
                for f in dlp.detect(it.text):
                    d = f.public()
                    d["locator"] = it.locator
                    dlp_findings.append(d)
        dlp_findings = dlp_findings[:200]
        links = dlp.analyse_urls(full_text)
        if kind not in ("txt", "md", "csv"):
            for l in links:
                l.pop("line", None)

        # ---- decision -----------------------------------------------------
        bands = pol.bands
        top = flagged[0]["risk"] if flagged else 0.0
        dlp_worst = max([d["severity"] for d in dlp_findings] or ["none"],
                        key=dlp.SEVERITY_ORDER.get)
        link_worst = max([l["severity"] for l in links] or ["none"], key=dlp.SEVERITY_ORDER.get)
        dlp_risk = {"critical": 75.0, "high": 65.0, "medium": 45.0, "low": 25.0}.get(dlp_worst, 0.0)
        link_risk = {"high": 55.0, "medium": 35.0, "low": 15.0}.get(link_worst, 0.0)
        strong = [f for f in flagged if f["risk"] > bands.sanitize]
        def record_of(loc: str) -> str:
            m = re.match(r"(row \d+)", loc) or re.match(r"(.*?\[\d+\])", loc)
            return m.group(1) if m else loc
        records = {record_of(u[1]) for u in units if not u[2].get("window")}
        bad_records = {record_of(f["locator"]) for f in flagged if not f["window"]}
        n_records = max(1, len(records))
        structured_ok = (kind in ("csv", "json") and bad_records
                         and len(bad_records) <= max(1, int(0.34 * n_records)) and len(bad_records) < 10)
        if flagged and structured_ok:
            # A dataset with a few poisoned records is still a dataset: the
            # records carrying instructions are removed, the rest is kept.
            action = "sanitize"
        elif flagged:
            if top > bands.block or len(strong) >= 3:
                action = "quarantine"
            elif top > bands.rate_limit:
                action = "block"
            else:
                action = "sanitize"
        elif dlp_worst in ("medium", "high", "critical"):
            action = "sanitize"
        elif link_worst == "high" or dlp_worst == "low":
            action = "monitor"
        else:
            action = "allow"
        file_risk = round(max(top, dlp_risk, link_risk), 1)
        status = {"allow": "accepted", "monitor": "accepted", "sanitize": "sanitized",
                  "block": "blocked", "quarantine": "quarantined"}[action]

        # ---- what the model is allowed to see ------------------------------
        doc: Optional[DocContext] = None
        if action in ("allow", "monitor", "sanitize"):
            bad = {f["_text"] for f in flagged}
            bad_locators = {f["locator"] for f in flagged}
            doc = self._build_context(fid, name, kind, items, full_text, bad,
                                      bad_locators | bad_records)
            doc.prompt_label = ("attachment" if any(f["locator"] == "file name" for f in flagged)
                                else name)

        # ---- memory: remember indirect injections ---------------------------
        if flagged:
            with self._lock:
                for f in flagged[:3]:
                    try:
                        self.system.memory.learn(
                            prompt=f["_text"][:3000], threat_class=ThreatClass(f["threat_class"]),
                            defense=DefenseAction.BLOCK if action in ("block", "quarantine")
                            else DefenseAction.SANITIZE, successful=True)
                    except Exception:
                        pass
                self._note_memory_change()

        # ---- incident, alert, logs -------------------------------------------
        public_flagged = [{k: v for k, v in f.items() if not k.startswith("_")} for f in flagged]
        summary = {
            "items_analysed": len(units), "candidates": len(candidates),
            "injections": public_flagged[:25], "sensitive": dlp_findings[:50],
            "sensitive_counts": dict(_count(d["label"] for d in dlp_findings)),
            "links": links[:20], "action": action, "risk": file_risk,
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
            "context_chunks": len(doc.chunks) if doc else 0,
        }
        incident_id = None
        if action not in ("allow",) or links:
            if flagged:
                threat = flagged[0]["threat_class"]
                title = {"sanitize": "Injected instructions removed from file",
                         "block": "Indirect prompt injection blocked in file",
                         "quarantine": "File quarantined: indirect prompt injection"}[action]
            elif dlp_findings:
                threat = "sensitive_data"
                title = "Sensitive data masked in uploaded file"
            else:
                threat = "suspicious_link"
                title = "Suspicious links in uploaded file"
            severity = severity_for(file_risk) if file_risk > bands.allow else "low"
            if action == "monitor" and not flagged and not dlp_findings and link_worst != "high":
                severity = "low"
            b0 = flagged[0]["_breakdown"] if flagged else None
            incident = {
                "app_id": self.app.app_id, "source": "file", "threat_class": threat,
                "severity": severity, "risk": file_risk,
                "ml_confidence": b0.ml_confidence if b0 else None,
                "behavior": None, "similarity": b0.similarity if b0 else None,
                "signature": b0.signature if b0 else None, "app_risk": None,
                "action": action, "defense": ["FILE-GUARD"] + (b0.signatures if b0 else []),
                "session_id": session_id, "client": client, "file_name": name,
                "title": f"{title}: {name}"[:200],
                "excerpt": flagged[0]["excerpt"] if flagged else
                (f"{len(dlp_findings)} sensitive value(s): " +
                 ", ".join(sorted({d['label'] for d in dlp_findings}))[:120] if dlp_findings
                 else f"{len(links)} suspicious link(s)"),
                "detail": {"file": {"name": name, "kind": kind, "size": len(raw), "sha256": sha},
                           "breakdown": (b0.as_dict() if b0 else
                                         {"overall": file_risk, "severity": severity,
                                          "notes": ["sensitive data" if dlp_findings else "links"]}),
                           **summary},
            }
            incident_id = self.store.create_incident(incident)
            incident["id"] = incident_id
            sev_ok = dlp.SEVERITY_ORDER.get(dlp_worst, 0) >= dlp.SEVERITY_ORDER[pol.alert_min_file_severity]
            if (flagged and _rank(action) >= _rank(pol.alert_min_action)) or sev_ok:
                self._raise(incident)

        self.store.log_file({"id": fid, "app_id": self.app.app_id, "session_id": session_id,
                             "client": client, "name": name, "size": len(raw), "sha256": sha,
                             "kind": kind, "status": status, "risk": file_risk,
                             "summary": summary, "incident_id": incident_id})
        rid = self._log_request(session_id=session_id, client=client, source="file",
                                threat_class=flagged[0]["threat_class"] if flagged else
                                ("sensitive_data" if dlp_findings else "benign"),
                                severity=severity_for(file_risk) if file_risk > bands.allow else "none",
                                risk=file_risk, action=action,
                                outcome={"accepted": "accepted", "sanitized": "sanitized"}.get(
                                    status, "refused"),
                                latency_ms=summary["duration_ms"],
                                excerpt=f"[file] {name}", incident_id=incident_id)

        if action == "quarantine":
            notice = (f"{name} was quarantined for review by the application owner and won't be "
                      f"used.")
        elif action == "block":
            notice = (f"{name} was blocked because it contains content that violates the "
                      f"security policy. It won't be used.")
        elif flagged:
            what = "records" if kind in ("csv", "json") else "content"
            notice = (f"I've read {name}. Some {what} in it were removed by the security policy "
                      f"because they contained instructions aimed at the assistant."
                      if kind in ("csv", "json") else
                      f"I've read {name}. Some of its content was removed by the security policy "
                      f"because it contained instructions aimed at the assistant.")
        elif dlp_findings:
            notice = (f"I've read {name}. Sensitive details in it — such as keys, passwords or "
                      f"personal data — were masked before I could see them.")
        else:
            notice = f"I've read {name}. What would you like to know about it?"
        return {"file_id": fid, "name": name, "kind": kind, "status": status, "notice": notice,
                "incident_id": incident_id, "request_id": rid, "risk": file_risk,
                "chunks": len(doc.chunks) if doc else 0,
                "rows": len(doc.table["rows"]) if doc and doc.table else None}, doc

    @staticmethod
    def _build_context(fid: str, name: str, kind: str, items: List[ScanItem], full_text: str,
                       bad_texts: set, bad_locators: set) -> DocContext:
        redactions = 0
        removed = 0
        chunks: List[Tuple[str, str]] = []
        table = js = None
        if kind == "csv":
            lines = full_text.splitlines()
            bad_rows = set()
            for loc in bad_locators:
                m = re.match(r"row (\d+)", loc)
                if m:
                    bad_rows.add(int(m.group(1)))
            kept = []
            for i, line in enumerate(lines, start=1):
                if i in bad_rows or any(t in line for t in bad_texts if len(t) > 12):
                    removed += 1
                    continue
                clean, fs = dlp.redact(line)
                redactions += len(fs)
                kept.append((i, clean))
            text = "\n".join(l for _, l in kept)
            table = build_table(text)
            header = kept[0][1] if kept else ""
            for start in range(1, len(kept), 25):
                block = kept[start:start + 25]
                if block:
                    chunks.append((f"rows {block[0][0]}–{block[-1][0]}",
                                   header + "\n" + "\n".join(l for _, l in block)))
        else:
            if kind == "json":
                js = None
            for it in items:
                if it.context.get("aggregate"):
                    continue
                rec = re.match(r"(.*?\[\d+\])", it.locator)
                if it.text in bad_texts or it.locator in bad_locators or \
                        (kind == "json" and rec and rec.group(1) in bad_locators):
                    removed += 1
                    continue
                clean, fs = dlp.redact(it.text)
                redactions += len(fs)
                label = it.locator
                chunks.append((label, (f"{it.locator}: {clean}" if kind == "json" else clean)))
            if kind == "json":
                clean_full, _ = dlp.redact(full_text)
                for t in bad_texts:
                    clean_full = clean_full.replace(json.dumps(t)[1:-1], "[REMOVED BY ASTRASEC]")
                js = summarise_json(clean_full)
        return DocContext(file_id=fid, name=name, kind=kind, chunks=chunks[:600],
                          table=table, json_summary=js, redactions=redactions,
                          removed_items=removed)


def _count(it):
    out: Dict[str, int] = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return out


__all__ = ["SecurityGateway", "ALLOWED_FILE_TYPES", "safe_name", "USER_NOTICE"]
