"""HTTP routes for AstraBot (public), owner auth, and the Security Center (owner)."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field, ValidationError

from ..config import settings
from . import analytics
from .auth import COOKIE, TOKEN_TTL, is_loopback
from .policy import AlertChannels, BotConfig, SecurityPolicy, merge_secret
from .runtime import runtime
from .store import INCIDENT_STATUSES


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _need_bot():
    if runtime.bot is None:
        raise HTTPException(503, "AstraBot is starting up or the models are not loaded yet.")
    return runtime.bot


def _need_gateway():
    if runtime.gateway is None:
        raise HTTPException(503, "The security models are not loaded. Train them with "
                                 "`python -m astrasec.train`, then restart.")
    return runtime.gateway


# ==========================================================================
# AstraBot — public
# ==========================================================================
bot_router = APIRouter(prefix="/api/bot", tags=["astrabot"])


class ChatIn(BaseModel):
    session_id: str = Field(..., min_length=32, max_length=32)
    message: str = Field(..., max_length=50_000)


class SessionIn(BaseModel):
    session_id: str = Field(..., min_length=32, max_length=32)


@bot_router.get("/info")
def bot_info() -> Dict[str, Any]:
    return _need_bot().info()


@bot_router.post("/session")
def bot_session() -> Dict[str, str]:
    return {"session_id": _need_bot().new_session()}


@bot_router.post("/chat")
def bot_chat(body: ChatIn, request: Request) -> Dict[str, Any]:
    bot = _need_bot()
    try:
        return bot.chat(body.session_id, body.message, client_ip(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@bot_router.post("/upload")
async def bot_upload(request: Request, session_id: str = Form(...),
                     file: UploadFile = File(...)) -> Dict[str, Any]:
    bot = _need_bot()
    limit = int(runtime.gateway.policy.max_file_mb * 1024 * 1024)
    raw = await file.read(limit + 1)
    if len(raw) > limit:
        return {"status": "rejected", "name": file.filename, "attached": False,
                "notice": f"That file is larger than the "
                          f"{runtime.gateway.policy.max_file_mb:g} MB limit."}
    try:
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(bot.upload, session_id, file.filename or "upload", raw,
                                       client_ip(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@bot_router.delete("/files/{file_id}")
def bot_remove_file(file_id: str, session_id: str = Query(..., min_length=32, max_length=32)
                    ) -> Dict[str, Any]:
    try:
        return {"removed": _need_bot().remove_file(session_id, file_id)}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@bot_router.post("/reset")
def bot_reset(body: SessionIn) -> Dict[str, bool]:
    _need_bot().reset(body.session_id)
    return {"ok": True}


# ==========================================================================
# Owner authentication
# ==========================================================================
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


class PasswordIn(BaseModel):
    password: str = Field(..., max_length=256)


class ChangeIn(BaseModel):
    current: str = Field(..., max_length=256)
    new: str = Field(..., max_length=256)


def token_from(request: Request) -> Optional[str]:
    tok = request.cookies.get(COOKIE)
    if not tok:
        h = request.headers.get("authorization", "")
        if h.lower().startswith("bearer "):
            tok = h[7:].strip()
    return tok


def is_owner(request: Request) -> bool:
    if not runtime.enforce_auth:
        return True
    auth = runtime.auth
    if auth is None:
        return False
    if not auth.configured():
        return is_loopback(client_ip(request))
    return auth.verify(token_from(request))


def _set_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(COOKIE, token, max_age=TOKEN_TTL, httponly=True, samesite="strict",
                    path="/", secure=False)


@auth_router.get("/status")
def auth_status(request: Request) -> Dict[str, Any]:
    auth = runtime.auth
    configured = bool(auth and auth.configured())
    return {"configured": configured, "authenticated": is_owner(request),
            "loopback": is_loopback(client_ip(request)),
            "setup_allowed": (not configured) and is_loopback(client_ip(request))}


@auth_router.post("/setup")
def auth_setup(body: PasswordIn, request: Request, response: Response) -> Dict[str, Any]:
    auth = runtime.auth
    if auth.configured():
        raise HTTPException(409, "An owner password is already set. Sign in instead.")
    if not is_loopback(client_ip(request)):
        raise HTTPException(403, "The owner password can only be created from this computer.")
    try:
        auth.set_password(body.password)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    _set_cookie(response, auth.issue())
    return {"ok": True}


@auth_router.post("/login")
def auth_login(body: PasswordIn, request: Request, response: Response) -> Dict[str, Any]:
    auth = runtime.auth
    ip = client_ip(request)
    if not auth.configured():
        raise HTTPException(409, "No owner password yet — create one first.")
    if auth.locked_out(ip):
        raise HTTPException(429, "Too many failed attempts. Try again in five minutes.")
    if not auth.check_password(body.password):
        auth.record_failure(ip)
        time.sleep(0.4)
        raise HTTPException(401, "Incorrect password.")
    auth.clear_failures(ip)
    _set_cookie(response, auth.issue())
    return {"ok": True}


@auth_router.post("/logout")
def auth_logout(response: Response) -> Dict[str, Any]:
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@auth_router.post("/change")
def auth_change(body: ChangeIn, request: Request, response: Response) -> Dict[str, Any]:
    auth = runtime.auth
    if not is_owner(request):
        raise HTTPException(401, "Sign in first.")
    if auth.configured() and not auth.check_password(body.current):
        raise HTTPException(401, "The current password is incorrect.")
    try:
        auth.set_password(body.new)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    _set_cookie(response, auth.issue())
    return {"ok": True}


# ==========================================================================
# Security Center — owner only (enforced by middleware in api.py)
# ==========================================================================
soc_router = APIRouter(prefix="/api/soc", tags=["security-center"])


@soc_router.get("/overview")
def soc_overview(range: str = Query("24h", pattern="^(24h|7d|30d)$")) -> Dict[str, Any]:
    from ..api import state
    gw = runtime.gateway
    return analytics.overview(runtime.store, state.store, gw.system if gw else state.system,
                              gw, runtime.bot, range)


# ---- incidents -----------------------------------------------------------
class IncidentPatch(BaseModel):
    status: Optional[str] = None
    note: str = Field("", max_length=2000)


@soc_router.get("/incidents")
def soc_incidents(status: Optional[str] = None, severity: Optional[str] = None,
                  source: Optional[str] = None, q: Optional[str] = Query(None, max_length=100),
                  limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)
                  ) -> Dict[str, Any]:
    rows, total = runtime.store.incidents(limit=limit, offset=offset, status=status,
                                          severity=severity, source=source, q=q)
    return {"items": rows, "total": total}


@soc_router.get("/incidents/{iid}")
def soc_incident(iid: str) -> Dict[str, Any]:
    inc = runtime.store.incident(iid)
    if inc is None:
        raise HTTPException(404, f"Incident {iid} not found.")
    return inc


@soc_router.patch("/incidents/{iid}")
def soc_incident_update(iid: str, body: IncidentPatch) -> Dict[str, Any]:
    if body.status and body.status not in INCIDENT_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(INCIDENT_STATUSES)}")
    before = runtime.store.incident(iid)
    if before is None:
        raise HTTPException(404, f"Incident {iid} not found.")
    inc = runtime.store.update_incident(iid, body.status, body.note)
    feedback = None
    if body.status == "false_positive" and before["status"] != "false_positive" \
            and runtime.gateway is not None:
        feedback = runtime.gateway.false_positive(inc)
    return {**inc, "feedback": feedback}


# ---- alerts ----------------------------------------------------------------
class AlertRead(BaseModel):
    id: Optional[str] = None


@soc_router.get("/alerts")
def soc_alerts(unread: bool = False, limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    return {"items": runtime.store.alerts(limit=limit, unread_only=unread),
            "unread": runtime.store.unread_alerts()}


@soc_router.post("/alerts/read")
def soc_alerts_read(body: AlertRead) -> Dict[str, Any]:
    return {"updated": runtime.store.mark_alerts_read(body.id),
            "unread": runtime.store.unread_alerts()}


# ---- traffic & files ---------------------------------------------------------
@soc_router.get("/requests")
def soc_requests(source: Optional[str] = Query(None, pattern="^(prompt|file|response)$"),
                 flagged: bool = False, limit: int = Query(100, ge=1, le=1000),
                 offset: int = Query(0, ge=0)) -> List[Dict[str, Any]]:
    return runtime.store.requests(limit=limit, offset=offset, source=source,
                                  flagged_only=flagged)


@soc_router.get("/files")
def soc_files(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    return runtime.store.files(limit)


# ---- clients -----------------------------------------------------------------
@soc_router.get("/clients")
def soc_clients() -> List[Dict[str, Any]]:
    return _need_gateway().restricted_clients()


@soc_router.post("/clients/{client}/release")
def soc_release(client: str) -> Dict[str, Any]:
    if not re.fullmatch(r"[0-9A-Za-z.:\-_%]{1,80}", client):
        raise HTTPException(422, "invalid client id")
    return {"released": _need_gateway().release_client(client)}


# ---- configuration -----------------------------------------------------------
@soc_router.get("/policy")
def soc_policy() -> Dict[str, Any]:
    return _need_gateway().policy.model_dump()


@soc_router.put("/policy")
def soc_policy_put(body: Dict[str, Any]) -> Dict[str, Any]:
    gw = _need_gateway()
    try:
        pol = SecurityPolicy(**{**gw.policy.model_dump(), **body})
    except ValidationError as exc:
        raise HTTPException(422, "; ".join(e["msg"] for e in exc.errors()))
    return gw.save_policy(pol).model_dump()


@soc_router.get("/bot-config")
def soc_bot_config() -> Dict[str, Any]:
    bot = _need_bot()
    cfg = bot.config()
    provider, label = bot.model.resolve(cfg)
    return {**cfg.public(), "resolved_provider": provider, "resolved_label": label,
            "last_error": bot.model.last_error or None}


@soc_router.put("/bot-config")
def soc_bot_config_put(body: Dict[str, Any]) -> Dict[str, Any]:
    bot = _need_bot()
    old = bot.config().model_dump()
    new = merge_secret({**old, **body}, old, "api_key")
    if body.get("clear_api_key"):
        new["api_key"] = ""
    new.pop("clear_api_key", None)
    for k in ("api_key_set", "resolved_provider", "resolved_label", "last_error"):
        new.pop(k, None)
    try:
        cfg = bot.save_config(BotConfig(**new))
    except ValidationError as exc:
        raise HTTPException(422, "; ".join(e["msg"] for e in exc.errors()))
    provider, label = bot.model.resolve(cfg, force=True)
    return {**cfg.public(), "resolved_provider": provider, "resolved_label": label,
            "last_error": bot.model.last_error or None}


@soc_router.get("/alert-channels")
def soc_channels() -> Dict[str, Any]:
    return runtime.dispatcher.channels().public()


@soc_router.put("/alert-channels")
def soc_channels_put(body: Dict[str, Any]) -> Dict[str, Any]:
    old = runtime.dispatcher.channels().model_dump()
    email = merge_secret({**old["email"], **(body.get("email") or {})}, old["email"], "password")
    email.pop("password_set", None)
    webhook = {**old["webhook"], **(body.get("webhook") or {})}
    try:
        ch = AlertChannels(email=email, webhook=webhook)
    except ValidationError as exc:
        raise HTTPException(422, "; ".join(e["msg"] for e in exc.errors()))
    runtime.store.put("alert_channels", ch.model_dump())
    return ch.public()


@soc_router.post("/alert-channels/test")
def soc_channels_test() -> Dict[str, str]:
    return runtime.dispatcher.test()


# ---- analyzer console -----------------------------------------------------------
class AnalyzeIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=20_000)
    kind: str = Field("prompt", pattern="^(prompt|response)$")


@soc_router.post("/analyze")
def soc_analyze(body: AnalyzeIn) -> Dict[str, Any]:
    return _need_gateway().dry_run(body.text, body.kind)


# ---- immune memory & controlled self-healing ---------------------------------------
@soc_router.get("/memory")
def soc_memory(limit: int = Query(30, ge=1, le=200)) -> Dict[str, Any]:
    from .dlp import safe_excerpt
    mem = _need_gateway().system.memory
    cells = sorted((c for c in mem.cells.values() if c.generation == 0),
                   key=lambda c: (-c.encounters, -c.last_seen))[:limit]
    return {"stats": mem.stats(), "patterns": [
        {"cell_id": c.cell_id, "threat_class": c.threat_class.value,
         "exemplar": safe_excerpt(c.exemplar_prompt, 140), "encounters": c.encounters,
         "success_rate": round(c.success_rate, 3), "defense": c.defense_used.value,
         "first_seen": c.created_at, "last_seen": c.last_seen,
         "clones": sum(1 for x in mem.cells.values() if x.parent_id == c.cell_id)}
        for c in cells]}


def _rule_row(r, state: str) -> Dict[str, Any]:
    d = r.model_dump(mode="json")
    d["state"] = state
    return d


@soc_router.get("/rules")
def soc_rules() -> Dict[str, Any]:
    mem = _need_gateway().system.memory
    pending = sorted(mem.candidate_rules.values(), key=lambda r: (-r.confidence, -r.support))
    return {"pending": [_rule_row(r, "pending") for r in pending[:60]],
            "active": [_rule_row(r, "active") for r in mem.promoted_rules.values()],
            "auto_promote": settings.rule_auto_promote}


def _find_rule(rule_id: str):
    mem = _need_gateway().system.memory
    rule = mem.candidate_rules.get(rule_id) or mem.promoted_rules.get(rule_id)
    if rule is None:
        raise HTTPException(404, f"Rule {rule_id} not found.")
    return mem, rule


@soc_router.post("/rules/{rule_id}/validate")
def soc_rule_validate(rule_id: str) -> Dict[str, Any]:
    gw = _need_gateway()
    mem, rule = _find_rule(rule_id)
    with gw._lock:
        rule.validation = gw.validate_rule(rule)
    return _rule_row(rule, "active" if rule_id in mem.promoted_rules else "pending")


@soc_router.post("/rules/{rule_id}/approve")
def soc_rule_approve(rule_id: str) -> Dict[str, Any]:
    gw = _need_gateway()
    mem, rule = _find_rule(rule_id)
    v = rule.validation or {}
    if not v.get("passed"):
        raise HTTPException(409, "Run the security test first — a rule can only go live once it "
                                 "has matched real attacks and zero benign messages.")
    if time.time() - v.get("tested_at", 0) > 3600:
        raise HTTPException(409, "The last test is more than an hour old. Test it again.")
    with gw._lock:
        rule.active = True
        rule.approved_at = time.time()
        mem.promoted_rules[rule.rule_id] = rule
        mem.candidate_rules.pop(rule.rule_id, None)
        gw.system.defense.install_rule(rule)
    return _rule_row(rule, "active")


@soc_router.post("/rules/{rule_id}/reject")
def soc_rule_reject(rule_id: str) -> Dict[str, Any]:
    gw = _need_gateway()
    mem, rule = _find_rule(rule_id)
    with gw._lock:
        mem.candidate_rules.pop(rule_id, None)
        if mem.promoted_rules.pop(rule_id, None) is not None:
            gw.system.defense.remove_rule(rule_id)
    return {"removed": rule_id}


@soc_router.post("/rules/{rule_id}/disable")
def soc_rule_disable(rule_id: str) -> Dict[str, Any]:
    gw = _need_gateway()
    mem, rule = _find_rule(rule_id)
    with gw._lock:
        if mem.promoted_rules.pop(rule_id, None) is not None:
            gw.system.defense.remove_rule(rule_id)
            rule.active = False
            mem.candidate_rules[rule_id] = rule
    return _rule_row(rule, "pending")


# ---- housekeeping ---------------------------------------------------------------------
@soc_router.post("/purge")
def soc_purge() -> Dict[str, bool]:
    runtime.store.purge_activity()
    return {"ok": True}


__all__ = ["bot_router", "auth_router", "soc_router", "is_owner", "client_ip"]
