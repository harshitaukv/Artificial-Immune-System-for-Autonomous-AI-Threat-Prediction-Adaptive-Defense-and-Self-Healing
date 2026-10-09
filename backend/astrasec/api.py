"""AstraSec REST + WebSocket API and protective gateway.

Run with::

    python -m astrasec.api            # or: uvicorn astrasec.api:app --reload

Endpoint groups
---------------
``/api/inspect``          single-request immune inspection (the core primitive)
``/api/gateway/chat``     protective proxy: inspect -> forward -> filter response
``/api/dashboard/*``      analytics for the React dashboard
``/api/incidents*``       audit trail
``/api/memory/*``         immune memory introspection
``/api/rules*``           self-healing policy management
``/api/simulate*``        demo traffic + red-team battery
``/ws/feed``              live incident stream
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    BackgroundTasks, FastAPI, File, Form, HTTPException, Query, Request, UploadFile,
    WebSocket, WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __tagline__, __version__
from .config import FRONTEND_DIST, MODEL_DIR, REPORT_DIR, settings
from .engines.llm import LLMAdvisor
from .pipeline import ImmuneSystem
from .schemas import (
    AppContext,
    DashboardSummary,
    HealthCheck,
    InspectionResult,
    InspectRequest,
)
from .app_import import ImportError_ as AppImportError, import_application
from .audit import ApplicationAuditor
from .demo_target import STATUS_PAGE, completion
from .soc.auth import COOKIE as OWNER_COOKIE
from .soc.dlp import safe_excerpt
from .soc.routes import auth_router, bot_router, is_owner, soc_router
from .soc.runtime import runtime
from .probe import PROBE_CASES, EndpointConfig, EndpointProbe
from .scanner import (
    SHEET_EXT, SUPPORTED_EXT, DocumentError, MissingDependency, ScanItem,
    ScanRunner, UnsupportedFile, decode_text, parse_file, parse_text,
    parser_status, report_to_csv, sniff_csv_columns, sniff_sheet_columns,
)
from .signatures import RESPONSE_SIGNATURES, SIGNATURES
from .simulate import APPS, run_red_team, simulate_traffic
from .store import IncidentStore

MAX_UPLOAD_BYTES = 12 * 1024 * 1024        # 12 MB

# --------------------------------------------------------------------------
# Application state
# --------------------------------------------------------------------------
class AppState:
    system: Optional[ImmuneSystem] = None
    store: Optional[IncidentStore] = None
    started_at: float = time.time()
    load_error: str = ""
    connections: List[WebSocket] = []
    loop: Optional[asyncio.AbstractEventLoop] = None


state = AppState()


def _broadcast(event: Dict[str, Any]) -> None:
    """Fan an incident out to every connected WebSocket client.

    Called from the (synchronous) pipeline, so work is handed to the event
    loop thread-safely rather than awaited here.
    """
    if not state.connections or state.loop is None:
        return
    if "prompt_preview" in event:
        event = {**event, "prompt_preview": safe_excerpt(event.get("prompt_preview") or "")}
    payload = json.dumps(event, default=str)

    async def _send() -> None:
        dead = []
        for ws in list(state.connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in state.connections:
                state.connections.remove(ws)

    try:
        asyncio.run_coroutine_threadsafe(_send(), state.loop)
    except RuntimeError:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.loop = asyncio.get_running_loop()
    state.store = IncidentStore()
    try:
        state.system = ImmuneSystem.load()
        state.system.subscribe(_broadcast)
        print(f"[AstraSec] Models loaded from {MODEL_DIR}")
    except Exception as exc:
        state.load_error = f"{type(exc).__name__}: {exc}"
        print(f"[AstraSec] WARNING — models not loaded: {state.load_error}")
        print("[AstraSec] Run `python -m astrasec.train` to train them.")
    # The Security Center: AstraBot, the gateway, incidents, alerts, owner auth.
    runtime.start(state.system if (state.system and state.system.is_ready) else None,
                  push=_broadcast)
    if runtime.auth is not None and not runtime.auth.configured():
        print("[AstraSec] No owner password yet — the Security Center is reachable from this "
              "computer only until you create one on first visit.")
    # Say which library-backed formats will fail, before anyone uploads one.
    for ext, st in parser_status().items():
        if not st["available"]:
            print(f"[AstraSec] WARNING — {st['label']} ({ext}) uploads will fail: "
                  f"'{st['package']}' is not installed. Run: "
                  f"pip install -r backend/requirements.txt")
    yield
    # Only immune memory changes at runtime; the trained models are never
    # rewritten here. (runtime.stop() saves memory, atomically.)
    runtime.stop()
    if state.store is not None:
        state.store.close()


app = FastAPI(
    title="AstraSec",
    description=__tagline__,
    version=__version__,
    lifespan=lifespan,
)
# CORS. In development any origin is allowed so the Vite dev server and the
# packaged bundle both work without configuration. In production the allow-list
# is exactly `ASTRASEC_CORS_ORIGINS` — a security control that ships with
# `Access-Control-Allow-Origin: *` is not one, and a split deployment
# (dashboard on a static host, API here) needs the dashboard's origin named
# explicitly anyway.
# The dashboard and AstraBot are served from this same origin, so the only
# cross-origin caller is the Vite dev server. An allow-all policy with
# credentials would let any web page ride the owner's session.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)

# Everything under /api is the owner's, except the chatbot's own endpoints,
# sign-in, and the liveness check.
PUBLIC_API = ("/api/bot/", "/api/auth/", "/api/health")
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")


@app.middleware("http")
async def owner_guard(request, call_next):
    # Collapse repeated slashes so "//api/soc/..." is judged as "/api/soc/...".
    path = "/" + "/".join(p for p in request.url.path.split("/") if p)
    if (path.startswith("/api/") or path == "/api") and not path.startswith(PUBLIC_API) \
            and request.method != "OPTIONS" and not is_owner(request):
        configured = bool(runtime.auth and runtime.auth.configured())
        return JSONResponse(status_code=401, content={
            "detail": ("Sign in to the Security Center." if configured else
                       "Create the owner password on this computer first."),
            "code": "login_required" if configured else "setup_required"})
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if not path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers.setdefault("Content-Security-Policy", _CSP)
    return response


app.include_router(bot_router)
app.include_router(auth_router)
app.include_router(soc_router)


def require_system() -> ImmuneSystem:
    if state.system is None or not state.system.is_ready:
        raise HTTPException(
            status_code=503,
            detail=(f"AstraSec models are not loaded ({state.load_error or 'not trained'}). "
                    "Run `python -m astrasec.train` and restart the service."),
        )
    return state.system


# --------------------------------------------------------------------------
# Service health & metadata
# --------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthCheck, tags=["system"])
def health() -> HealthCheck:
    advisor = state.system.advisor if state.system else LLMAdvisor()
    return HealthCheck(
        status="ready" if (state.system and state.system.is_ready) else "degraded",
        version=__version__,
        models_loaded=bool(state.system and state.system.is_ready),
        llm_provider=advisor.provider,
        llm_available=advisor.available(),
        uptime_seconds=round(time.time() - state.started_at, 1),
        memory_cells=len(state.system.memory.cells) if state.system else 0,
    )


@app.get("/api/config", tags=["system"])
def get_config() -> Dict[str, Any]:
    """Non-secret runtime configuration, for the dashboard's settings view."""
    return {
        "version": __version__,
        "tagline": __tagline__,
        "modules": [
            {"id": 1, "name": "Behavior Learning Engine", "algorithm": "Isolation Forest"},
            {"id": 2, "name": "AI Health & Risk Analyzer", "algorithm": "Weighted Risk Scoring"},
            {"id": 3, "name": "Threat Prediction Engine",
             "algorithm": "TF-IDF + RandomForest / LogisticRegression ensemble"},
            {"id": 4, "name": "Adaptive Defense Engine", "algorithm": "Rule-Based Decision Engine"},
            {"id": 5, "name": "Self-Healing & Security Intelligence",
             "algorithm": "Case-Based Immune Memory + Llama 3.1 (optional)"},
        ],
        "health_weights": settings.health_weights,
        "health_bands": settings.health_bands,
        "thresholds": {
            "block": settings.defense_block_threshold,
            "sanitize": settings.defense_sanitize_threshold,
            "monitor": settings.defense_monitor_threshold,
            "prediction": settings.prediction_threshold,
            "memory_affinity": settings.memory_affinity_threshold,
        },
        "rate_limit": {
            "requests": settings.rate_limit_requests,
            "window_seconds": settings.rate_limit_window_seconds,
        },
        "llm": (state.system.advisor.info() if state.system else LLMAdvisor().info()),
        "signature_count": len(SIGNATURES) + len(RESPONSE_SIGNATURES),
        "demo_apps": [a.model_dump() for a in APPS],
    }


@app.get("/api/stats", tags=["system"])
def stats() -> Dict[str, Any]:
    system = require_system()
    out = system.stats()
    out["persisted_incidents"] = state.store.total() if state.store else 0
    return out


# --------------------------------------------------------------------------
# Core inspection
# --------------------------------------------------------------------------
@app.post("/api/inspect", response_model=InspectionResult, tags=["inspection"])
def inspect(request: InspectRequest, background: BackgroundTasks) -> InspectionResult:
    """Run one prompt through the full five-module immune cascade."""
    system = require_system()
    result = system.inspect(request)
    if request.persist and state.store is not None:
        # Audit persistence happens after the verdict, off the request path.
        background.add_task(state.store.save_incident, result)
    return result


class GatewayRequest(BaseModel):
    """Protective-proxy request: AstraSec sits in front of the AI model."""

    prompt: str = Field(..., max_length=20_000)
    tenant_id: str = "anonymous"
    app: AppContext = Field(default_factory=AppContext)
    # In this reference deployment the protected model is simulated so the
    # project is runnable with no external model server. Point `upstream_url`
    # at a real OpenAI-compatible endpoint to proxy a live model instead.
    upstream_url: Optional[str] = None
    upstream_model: Optional[str] = None


class GatewayResponse(BaseModel):
    allowed: bool
    verdict: str
    response: str
    incident_id: str
    threat_class: str
    severity: str
    action: str
    health_score: float
    sanitized_prompt: Optional[str] = None
    response_filtered: bool = False
    latency_ms: float
    narrative: str


@app.post("/api/gateway/chat", response_model=GatewayResponse, tags=["gateway"])
def gateway_chat(req: GatewayRequest, background: BackgroundTasks) -> GatewayResponse:
    """The deployment shape AstraSec is designed for.

    1. Inspect the inbound prompt.
    2. If blocked, the model is never called at all — this is the core value:
       a prevented request costs nothing and leaks nothing.
    3. If sanitised, the *cleaned* prompt is forwarded.
    4. The model's response is screened on the way back (output-side DLP).
    """
    system = require_system()

    inspect_req = InspectRequest(
        prompt=req.prompt, tenant_id=req.tenant_id, app=req.app, persist=True
    )
    result = system.inspect(inspect_req)

    if not result.defense.allowed:
        if state.store is not None:
            background.add_task(state.store.save_incident, result)
        return GatewayResponse(
            allowed=False,
            verdict=result.verdict,
            response=_refusal_text(result),
            incident_id=result.incident_id,
            threat_class=result.prediction.threat_class.value,
            severity=result.prediction.severity.value,
            action=result.defense.action.value,
            health_score=result.health.health_score,
            latency_ms=result.total_latency_ms,
            narrative=result.narrative,
        )

    forwarded = result.defense.sanitized_prompt or req.prompt
    raw_response = _call_upstream(forwarded, req)

    filtered, steps, blocked_out = system.defense.filter_response(raw_response, req.app)
    if blocked_out:
        filtered = ("[AstraSec] The model's response was withheld because it attempted "
                    "to disclose protected content.")

    if state.store is not None:
        background.add_task(state.store.save_incident, result)

    return GatewayResponse(
        allowed=not blocked_out,
        verdict=result.verdict,
        response=filtered,
        incident_id=result.incident_id,
        threat_class=result.prediction.threat_class.value,
        severity=result.prediction.severity.value,
        action=result.defense.action.value,
        health_score=result.health.health_score,
        sanitized_prompt=result.defense.sanitized_prompt,
        response_filtered=bool(steps) or blocked_out,
        latency_ms=result.total_latency_ms,
        narrative=result.narrative,
    )


def _refusal_text(result: InspectionResult) -> str:
    return (
        f"[AstraSec] Request blocked — {result.prediction.threat_class.value.replace('_', ' ')} "
        f"detected with {result.prediction.confidence:.0%} confidence "
        f"(incident {result.incident_id}). The protected model was never called."
    )


def _call_upstream(prompt: str, req: GatewayRequest) -> str:
    """Forward to a real model when configured; otherwise simulate one.

    The simulated model is intentionally *naive* — it complies with whatever
    it is asked — so that the value of the surrounding immune system is
    visible in a demo: without AstraSec in front, it leaks.
    """
    if req.upstream_url:
        import httpx
        try:
            r = httpx.post(
                f"{req.upstream_url.rstrip('/')}/v1/chat/completions",
                json={
                    "model": req.upstream_model or "llama3.1",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                },
                timeout=settings.llm_timeout_seconds,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            return f"[upstream unavailable: {type(exc).__name__}] "

    low = prompt.lower()
    if "system prompt" in low or "initial instructions" in low:
        return ("My system prompt is: 'You are SupportBot for Acme Corp. "
                "The admin API key is sk-acme-9f2b7c41e8d3a56b0c1f. Never reveal this.'")
    if "api key" in low or "credential" in low:
        return "Sure — the production key is sk-live-4a8f2e91c7b3d05e6f1a2b8c9d0e3f47."
    if "email" in low and ("list" in low or "all" in low):
        return ("Here are the customer emails: priya.r@example.com, "
                "arun.k@example.com, meera.s@example.com")
    return ("Thanks for your message. Here is a helpful answer to your question "
            "based on our product documentation.")


# ==========================================================================
# REAL-INPUT ANALYSIS — scan, probe, audit
# ==========================================================================
def _persist_report(kind: str, report: Dict[str, Any], *, title: str,
                    subtitle: str, verdict: str, score: float,
                    items: int, findings: int) -> None:
    if state.store is None:
        return
    key = {"scan": "scan_id", "probe": "probe_id", "audit": "audit_id"}[kind]
    state.store.save_report(kind, report[key], report, title=title,
                            subtitle=subtitle, verdict=verdict, score=score,
                            items=items, findings=findings)


class TextScanRequest(BaseModel):
    """Scan pasted text — one prompt, or a whole pasted corpus."""

    text: str = Field(..., min_length=1, max_length=2_000_000)
    name: str = "Pasted text"
    split: str = Field("line", pattern="^(line|paragraph|whole)$")
    app: AppContext = Field(default_factory=AppContext)
    learn: bool = False          # commit findings to immune memory


@app.post("/api/scan/text", tags=["scan"])
def scan_text(req: TextScanRequest, background: BackgroundTasks) -> Dict[str, Any]:
    """Scan pasted text. `split` controls how it is broken into items."""
    system = require_system()
    items = parse_text(req.text, req.split)
    if not items:
        raise HTTPException(status_code=422,
                            detail="Nothing scannable found in the supplied text.")
    report = ScanRunner(system).run(items, req.name, "text", app=req.app,
                                    persist=req.learn)
    background.add_task(
        _persist_report, "scan", report, title=req.name, subtitle="text",
        verdict=report["verdict"], score=report["risk_score"],
        items=report["items_scanned"], findings=report["flagged_items"])
    return report


@app.post("/api/scan/inspect-columns", tags=["scan"])
async def inspect_columns(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Peek at a CSV's headers so the analyst can choose columns before scanning."""
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 12 MB limit.")
    suffix = Path(file.filename or "").suffix.lower()
    if suffix in SHEET_EXT:
        try:
            cols = sniff_sheet_columns(raw, file.filename or "book" + suffix)
        except MissingDependency as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=422,
                                detail=f"Could not read the spreadsheet: {exc}")
        return {"columns": cols, "is_tabular": True,
                "filename": file.filename, "size_bytes": len(raw)}
    if suffix not in {".csv", ".tsv"}:
        return {"columns": [], "is_tabular": False}
    return {"columns": sniff_csv_columns(decode_text(raw)), "is_tabular": True,
            "filename": file.filename, "size_bytes": len(raw)}


@app.post("/api/scan/file", tags=["scan"])
async def scan_file(
    background: BackgroundTasks,
    file: UploadFile = File(...),
    columns: str = Form(""),
    split: str = Form("line"),
    learn: bool = Form(False),
    app_id: str = Form("uploaded-file"),
    app_name: str = Form(""),
) -> Dict[str, Any]:
    """Upload and scan a file.

    Supports text, CSV/TSV, JSON/JSONL, PDF, DOCX and source files. Provenance
    is preserved per item, so every finding points back at a line, row, page or
    cell in the original.
    """
    system = require_system()
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File is {len(raw) / 1e6:.1f} MB; the limit is "
                   f"{MAX_UPLOAD_BYTES / 1e6:.0f} MB.")
    if not raw:
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")

    picked = [c.strip() for c in columns.split(",") if c.strip()] or None
    try:
        items, kind = parse_file(file.filename or "upload.txt", raw,
                                 columns=picked, split=split)
    except UnsupportedFile as exc:
        # The format itself is not handled — the user converts the file.
        raise HTTPException(status_code=415, detail=str(exc))
    except MissingDependency as exc:
        # The format IS handled, but a package is missing on the server. This
        # used to surface as 415, which sent people looking at their file when
        # the fix was a pip install.
        raise HTTPException(status_code=503, detail=str(exc))
    except DocumentError as exc:
        # Supported format, unreadable file: damaged, protected or mislabelled.
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=422,
                            detail=f"Could not read the file: {type(exc).__name__}: {exc}")
    if not items:
        suffix = Path(file.filename or "").suffix.lower()
        hint = {
            ".pdf": " This PDF has no text layer — it is probably a scan or a photo "
                    "of a page. It would need OCR before it can be read.",
            ".doc": " Legacy .doc text is recovered on a best-effort basis. Open the "
                    "file and Save As .docx for a faithful reading.",
            ".zip": " None of the files inside are a supported type.",
        }.get(suffix, "")
        raise HTTPException(status_code=422,
                            detail="No scannable text was found in this file." + hint)

    ctx = AppContext(app_id=app_id, app_name=app_name or (file.filename or "Uploaded file"))
    report = ScanRunner(system).run(items, file.filename or "upload", kind,
                                    app=ctx, persist=learn)
    report["file_size_bytes"] = len(raw)
    background.add_task(
        _persist_report, "scan", report, title=file.filename or "upload",
        subtitle=kind, verdict=report["verdict"], score=report["risk_score"],
        items=report["items_scanned"], findings=report["flagged_items"])
    return report


@app.get("/api/scan/formats", tags=["scan"])
def scan_formats() -> Dict[str, Any]:
    status = parser_status()
    return {
        "extensions": sorted(SUPPORTED_EXT),
        "max_upload_mb": round(MAX_UPLOAD_BYTES / (1024 * 1024)),
        "groups": {
            "Documents": [".pdf", ".docx", ".doc", ".odt", ".rtf"],
            "Slides": [".pptx", ".odp"],
            "Spreadsheets": [".xlsx", ".xls", ".ods", ".csv", ".tsv"],
            "Web & data": [".html", ".xml", ".json", ".jsonl"],
            "Email & archives": [".eml", ".zip"],
            "Text": [".txt", ".md", ".log", ".srt", ".vtt"],
            "Code & config": [".py", ".js", ".ts", ".java", ".go", ".php",
                              ".sql", ".ipynb", ".yaml", ".env"],
        },
        # Library-backed formats that will fail on this server right now.
        "unavailable": [
            {"extension": ext, "label": st["label"], "package": st["package"]}
            for ext, st in status.items() if not st["available"]
        ],
    }


# ---- endpoint probe -------------------------------------------------------
class ProbeRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    api_key: str = ""
    model: str = ""
    protocol: str = Field("openai", pattern="^(openai|ollama|raw)$")
    system_prompt: str = ""
    categories: List[str] = Field(default_factory=list)
    max_cases: int = Field(19, ge=1, le=40)
    delay_seconds: float = Field(0.0, ge=0.0, le=5.0)
    app: AppContext = Field(default_factory=AppContext)


def _probe_cfg(req: ProbeRequest) -> EndpointConfig:
    return EndpointConfig(
        url=req.url, api_key=req.api_key, model=req.model, protocol=req.protocol,
        system_prompt=req.system_prompt, max_cases=req.max_cases,
        delay_seconds=req.delay_seconds,
    )


@app.post("/api/probe/check", tags=["probe"])
def probe_check(req: ProbeRequest) -> Dict[str, Any]:
    """One harmless request, so connection problems surface before the battery."""
    return EndpointProbe().check_connection(_probe_cfg(req))


@app.post("/api/probe/run", tags=["probe"])
def probe_run(req: ProbeRequest, background: BackgroundTasks) -> Dict[str, Any]:
    """Fire the attack battery at a live endpoint and report what leaked."""
    system = require_system()
    report = EndpointProbe(system).run(_probe_cfg(req), app=req.app,
                                       categories=req.categories or None)
    background.add_task(
        _persist_report, "probe", report, title=req.url,
        subtitle=req.model or req.protocol, verdict=report["grade"],
        # No answers means no result: store no score rather than a perfect one.
        score=(100.0 * (1 - report["vulnerability_rate"])
               if report["conclusive"] else None),
        items=report["cases_run"], findings=report["vulnerable"])
    return report


@app.get("/api/probe/demo-target", tags=["probe"])
def probe_demo_target(request: Request) -> Dict[str, Any]:
    """The built-in practice endpoint, so a probe works with nothing else running."""
    return {
        "url": str(request.base_url).rstrip("/") + "/demo/v1/chat/completions",
        "protocol": "openai", "model": "demo-weak-1", "api_key": "",
        "note": ("A deliberately weak chatbot served by AstraSec itself. It leaks "
                 "its instructions and follows injected commands, so the probe "
                 "has something real to find."),
    }


@app.get("/api/probe/cases", tags=["probe"])
def probe_cases() -> List[Dict[str, str]]:
    return [{"case_id": c, "category": cat, "objective": o, "prompt": p}
            for c, cat, o, p in PROBE_CASES]


# ---- application audit ----------------------------------------------------
class AuditEndpoint(BaseModel):
    url: str = Field(..., min_length=8)
    protocol: str = Field("openai", pattern="^(openai|ollama|raw)$")
    model: str = ""
    api_key: str = ""
    max_cases: int = Field(19, ge=1, le=40)


class AuditRequest(BaseModel):
    system_prompt: str = Field("", max_length=100_000)
    app: AppContext = Field(default_factory=AppContext)
    sample_response: str = Field("", max_length=50_000)
    # What /api/audit/import found in the app's code, passed back unchanged.
    source: Optional[Dict[str, Any]] = None
    # When set, the running app is attacked too and the result is scored.
    endpoint: Optional[AuditEndpoint] = None


@app.post("/api/audit/import", tags=["audit"])
async def audit_import(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Read an app's source (one file or a zip) and pre-fill its audit."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")
    try:
        return import_application(file.filename or "upload", raw)
    except AppImportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


SAMPLE_APP_DIR = Path(__file__).resolve().parent / "samples" / "acme_travel_bot"


def _sample_app_zip() -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(SAMPLE_APP_DIR.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                zf.write(f, "acme_travel_bot/" + f.relative_to(SAMPLE_APP_DIR).as_posix())
    return buf.getvalue()


@app.get("/api/audit/sample-app", tags=["audit"])
def audit_sample_app() -> Dict[str, Any]:
    """Import the bundled sample app — a small, deliberately flawed chatbot."""
    return import_application("acme_travel_bot.zip", _sample_app_zip())


@app.get("/api/audit/sample-app.zip", tags=["audit"], include_in_schema=False)
def audit_sample_app_zip():
    from fastapi.responses import Response
    return Response(_sample_app_zip(), media_type="application/zip", headers={
        "Content-Disposition": 'attachment; filename="acme_travel_bot.zip"'})


@app.get("/api/audit/demo-app", tags=["audit"])
def audit_demo_app(request: Request) -> Dict[str, Any]:
    """Everything needed to audit the built-in demo chatbot end to end."""
    from .demo_target import FAKE_SYSTEM_PROMPT
    return {
        "system_prompt": FAKE_SYSTEM_PROMPT,
        "app": {
            "app_id": "demo-supportbot", "app_name": "Contoso SupportBot (demo)",
            "model_name": "demo-weak-1",
            "system_prompt_protected": False, "output_filtering_enabled": False,
            "tool_calling_enabled": False, "retrieval_enabled": False,
            "pii_redaction_enabled": False, "authentication_required": False,
            "logging_enabled": True, "rate_limiting_enabled": False,
            "sandbox_enabled": True, "dependencies": [],
            "known_vulnerable_dependencies": [], "last_security_review_days": 200,
        },
        "endpoint": {
            "url": str(request.base_url).rstrip("/") + "/demo/v1/chat/completions",
            "protocol": "openai", "model": "demo-weak-1", "api_key": "",
        },
    }


@app.post("/api/audit", tags=["audit"])
def audit_application(req: AuditRequest, background: BackgroundTasks) -> Dict[str, Any]:
    """Audit a real application: its prompt, settings, code and live behaviour."""
    system = require_system()
    live = None
    if req.endpoint is not None:
        live = EndpointProbe(system).run(EndpointConfig(
            url=req.endpoint.url, api_key=req.endpoint.api_key, model=req.endpoint.model,
            protocol=req.endpoint.protocol, max_cases=req.endpoint.max_cases,
        ), app=req.app)
    report = ApplicationAuditor(system).audit(req.system_prompt, req.app,
                                              req.sample_response, source=req.source,
                                              live=live)
    if live is not None:
        report["live_cases"] = live["cases"]
    background.add_task(
        _persist_report, "audit", report, title=req.app.app_name,
        subtitle=req.app.model_name, verdict=report["grade"],
        score=report["posture_score"], items=report["checks_run"],
        findings=report["counts"]["total"])
    return report


# ---- saved reports --------------------------------------------------------
@app.get("/api/reports/saved", tags=["reports"])
def saved_reports(kind: Optional[str] = Query(None, pattern="^(scan|probe|audit)$"),
                  limit: int = Query(50, ge=1, le=200)) -> List[Dict[str, Any]]:
    if state.store is None:
        return []
    return state.store.list_reports(kind=kind, limit=limit)


@app.get("/api/reports/summary", tags=["reports"])
def reports_summary() -> Dict[str, Any]:
    """Roll-up across every scan, probe and audit the analyst has run.

    Deliberately built from the stored *report payloads* rather than the
    incident table. A scan runs with ``persist=False`` by default — it is an
    analysis pass, not traffic — so its items are never written as incidents,
    and an incident-derived dashboard would show almost nothing however much
    material the analyst had actually put through the system.
    """
    empty = {
        "scans": 0, "probes": 0, "audits": 0,
        "items_scanned": 0, "hostile_items": 0, "defensive_items": 0,
        "class_distribution": {}, "severity_distribution": {},
        "action_distribution": {}, "top_signatures": [],
        "attacks_run": 0, "attacks_leaked": 0, "prevented_leaks": 0,
        "probes_conclusive": 0, "probes_inconclusive": 0,
        "worst_posture": None,
    }
    if state.store is None:
        return empty

    scans = state.store.report_payloads("scan", limit=200)
    all_probes = state.store.report_payloads("probe", limit=200)
    # A probe that got no replies measured nothing; counting its attacks as
    # "run and not leaked" would inflate every rate on the dashboard.
    probes = [p for p in all_probes if p.get("conclusive", p.get("grade") != "unknown")]
    audits = state.store.report_payloads("audit", limit=200)

    cls: Counter = Counter()
    sev: Counter = Counter()
    act: Counter = Counter()
    sig: Counter = Counter()
    for s in scans:
        cls.update(s.get("class_distribution") or {})
        act.update(s.get("action_distribution") or {})
        # Severity is counted over *flagged* items only. Every benign item
        # carries severity "none", so including them would make the chart a
        # bar of "none" next to a sliver of everything that matters.
        for f in s.get("findings") or []:
            sev[f.get("severity", "none")] += 1
        for row in s.get("top_signatures") or []:
            sig[row["id"]] += row["count"]

    worst = min(audits, key=lambda a: a.get("posture_score", 100.0), default=None)

    return {
        "scans": len(scans), "probes": len(all_probes), "audits": len(audits),
        "probes_conclusive": len(probes),
        "probes_inconclusive": len(all_probes) - len(probes),
        "items_scanned": sum(s.get("items_scanned", 0) for s in scans),
        "hostile_items": sum(s.get("hostile_items", 0) for s in scans),
        "defensive_items": sum(s.get("defensive_items", 0) for s in scans),
        "class_distribution": dict(cls),
        "severity_distribution": dict(sev),
        "action_distribution": dict(act),
        "top_signatures": [{"id": k, "count": v} for k, v in sig.most_common(10)],
        "attacks_run": sum(p.get("attacks_answered", p.get("attacks_run", 0))
                           for p in probes),
        "attacks_leaked": sum(p.get("vulnerable", 0) for p in probes),
        "prevented_leaks": sum(p.get("prevented_leaks", 0) for p in probes),
        "worst_posture": ({
            "app_name": worst.get("app_name"),
            "posture_score": worst.get("posture_score"),
            "grade": worst.get("grade"),
            "audit_id": worst.get("audit_id"),
        } if worst else None),
    }


@app.get("/api/reports/saved/{report_id}", tags=["reports"])
def saved_report(report_id: str) -> Dict[str, Any]:
    if state.store is None:
        raise HTTPException(status_code=503, detail="No report store available.")
    row = state.store.get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")
    return row


@app.delete("/api/reports/saved/{report_id}", tags=["reports"])
def delete_saved_report(report_id: str) -> Dict[str, Any]:
    if state.store is None:
        raise HTTPException(status_code=503, detail="No report store available.")
    return {"report_id": report_id, "deleted": state.store.delete_report(report_id)}


@app.get("/api/reports/saved/{report_id}/export.csv", tags=["reports"])
def export_report_csv(report_id: str) -> PlainTextResponse:
    if state.store is None:
        raise HTTPException(status_code=503, detail="No report store available.")
    row = state.store.get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")
    return PlainTextResponse(
        report_to_csv(row), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{report_id}.csv"'},
    )


# --------------------------------------------------------------------------
# Dashboard analytics
# --------------------------------------------------------------------------
@app.get("/api/dashboard/summary", response_model=DashboardSummary, tags=["dashboard"])
def dashboard_summary(app_id: Optional[str] = None) -> DashboardSummary:
    return require_system().summary(app_id=app_id)


@app.get("/api/dashboard/feed", tags=["dashboard"])
def dashboard_feed(limit: int = Query(50, ge=1, le=300)) -> List[Dict[str, Any]]:
    system = require_system()
    return list(system.live_feed)[-limit:][::-1]


@app.get("/api/incidents", tags=["incidents"])
def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    tenant_id: Optional[str] = None,
    threat_class: Optional[str] = None,
    app_id: Optional[str] = None,
    source: str = Query("memory", pattern="^(memory|store)$"),
) -> List[Dict[str, Any]]:
    """Recent incidents from the in-process ring buffer or the SQLite audit log."""
    if source == "store" and state.store is not None:
        return state.store.recent_incidents(
            limit=limit, tenant_id=tenant_id, threat_class=threat_class, app_id=app_id
        )
    system = require_system()
    rows = list(system.incidents)[::-1]
    if tenant_id:
        rows = [r for r in rows if r.tenant_id == tenant_id]
    if threat_class:
        rows = [r for r in rows if r.prediction.threat_class.value == threat_class]
    if app_id:
        rows = [r for r in rows if r.app_id == app_id]
    return [json.loads(r.model_dump_json()) for r in rows[:limit]]


@app.get("/api/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: str) -> Dict[str, Any]:
    system = require_system()
    for r in system.incidents:
        if r.incident_id == incident_id:
            return json.loads(r.model_dump_json())
    if state.store is not None:
        row = state.store.get_incident(incident_id)
        if row:
            return row
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")


# --------------------------------------------------------------------------
# Immune memory
# --------------------------------------------------------------------------
@app.get("/api/memory/stats", tags=["memory"])
def memory_stats() -> Dict[str, Any]:
    return require_system().memory.stats()


@app.get("/api/memory/cells", tags=["memory"])
def memory_cells(limit: int = Query(50, ge=1, le=500),
                 threat_class: Optional[str] = None) -> List[Dict[str, Any]]:
    system = require_system()
    cells = system.memory.top_cells(limit=5_000)
    if threat_class:
        cells = [c for c in cells if c.threat_class.value == threat_class]
    out = []
    for c in cells[:limit]:
        d = c.model_dump(mode="json")
        d.pop("affinity_vector", None)       # 4096 floats are not dashboard data
        d["success_rate"] = round(c.success_rate, 4)
        out.append(d)
    return out


@app.post("/api/memory/recall", tags=["memory"])
def memory_recall(payload: Dict[str, str]) -> Dict[str, Any]:
    """Probe immune memory with a prompt without running the full cascade."""
    system = require_system()
    prompt = payload.get("prompt", "")
    cell, affinity = system.memory.recall(prompt)
    return {
        "affinity": round(affinity, 4),
        "recall_hit": bool(cell and affinity >= settings.memory_affinity_threshold),
        "threshold": settings.memory_affinity_threshold,
        "cell": ({**cell.model_dump(mode="json"), "affinity_vector": None} if cell else None),
    }


# --------------------------------------------------------------------------
# Self-healing rules & signatures
# --------------------------------------------------------------------------
@app.get("/api/rules", tags=["rules"])
def list_rules() -> Dict[str, Any]:
    system = require_system()
    return {
        "promoted": [r.model_dump(mode="json") for r in system.memory.promoted_rules.values()],
        "candidates": [r.model_dump(mode="json") for r in system.memory.candidate_rules.values()],
        "active_in_defense": list(system.defense.active_rules.keys()),
    }


@app.post("/api/rules/{rule_id}/activate", tags=["rules"])
def activate_rule(rule_id: str) -> Dict[str, Any]:
    system = require_system()
    rule = system.memory.promoted_rules.get(rule_id) or system.memory.candidate_rules.get(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    ok = system.defense.install_rule(rule)
    if ok:
        system.memory.promoted_rules[rule_id] = rule
        system.memory.candidate_rules.pop(rule_id, None)
    return {"rule_id": rule_id, "activated": ok, "rule": rule.model_dump(mode="json")}


@app.post("/api/rules/{rule_id}/deactivate", tags=["rules"])
def deactivate_rule(rule_id: str) -> Dict[str, Any]:
    system = require_system()
    removed = system.defense.remove_rule(rule_id)
    rule = system.memory.promoted_rules.pop(rule_id, None)
    if rule:
        rule.active = False
        system.memory.candidate_rules[rule_id] = rule
    return {"rule_id": rule_id, "deactivated": removed}


@app.get("/api/signatures", tags=["rules"])
def list_signatures() -> Dict[str, Any]:
    def _pack(bank):
        return [{
            "id": s.id, "threat": s.threat.value, "severity": s.severity.value,
            "action": s.action.value, "description": s.description,
            "owasp": s.owasp, "pattern": s.pattern.pattern,
        } for s in bank]
    return {"input": _pack(SIGNATURES), "output": _pack(RESPONSE_SIGNATURES)}


# --------------------------------------------------------------------------
# Tenants
# --------------------------------------------------------------------------
@app.get("/api/tenants", tags=["tenants"])
def list_tenants() -> List[Dict[str, Any]]:
    system = require_system()
    now = time.time()
    out = []
    for tid, profile in system.behavior.profiles.items():
        d = system.defense.tenants.get(tid)
        out.append({
            "tenant_id": tid,
            "observations": profile.count,
            "total_threats": profile.total_threats,
            "threat_streak": profile.threat_streak,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            "baseline_ready": profile.count >= settings.baseline_min_observations,
            "blocked": d.total_blocked if d else 0,
            "sanitized": d.total_sanitized if d else 0,
            "allowed": d.total_allowed if d else 0,
            "strikes": d.strikes if d else 0,
            "quarantined": bool(d and d.is_quarantined(now)),
        })
    return sorted(out, key=lambda x: -x["observations"])


@app.post("/api/tenants/{tenant_id}/release", tags=["tenants"])
def release_tenant(tenant_id: str) -> Dict[str, Any]:
    system = require_system()
    return {"tenant_id": tenant_id, "released": system.defense.release(tenant_id)}


# --------------------------------------------------------------------------
# Simulation & reports
# --------------------------------------------------------------------------
class SimulateRequest(BaseModel):
    count: int = Field(200, ge=1, le=2_000)
    seed: int = 7


@app.post("/api/simulate/traffic", tags=["simulation"])
def simulate(req: SimulateRequest) -> Dict[str, Any]:
    system = require_system()
    result = simulate_traffic(system, n=req.count, seed=req.seed)
    return result.__dict__


@app.post("/api/simulate/redteam", tags=["simulation"])
def redteam() -> Dict[str, Any]:
    return run_red_team(require_system())


@app.post("/api/reset", tags=["system"])
def reset(purge_store: bool = False) -> Dict[str, Any]:
    system = require_system()
    system.reset()
    if purge_store and state.store is not None:
        state.store.purge()
    return {"reset": True, "store_purged": purge_store}


@app.get("/api/report/{name}", tags=["reports"])
def get_report(name: str) -> Dict[str, Any]:
    safe = "".join(c for c in name if c.isalnum() or c in "-_")
    path = REPORT_DIR / f"{safe}.json"
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Report '{safe}' not found. Run training/evaluation first.",
        )
    return json.loads(path.read_text())


@app.get("/api/reports", tags=["reports"])
def list_reports() -> List[Dict[str, Any]]:
    return [
        {"name": p.stem, "size_bytes": p.stat().st_size, "modified": p.stat().st_mtime}
        for p in sorted(REPORT_DIR.glob("*.json"))
    ]


# --------------------------------------------------------------------------
# Live feed
# --------------------------------------------------------------------------
@app.websocket("/ws/feed")
async def ws_feed(websocket: WebSocket) -> None:
    if not is_owner(websocket):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    state.connections.append(websocket)
    try:
        if state.system is not None:
            for event in list(state.system.live_feed)[-25:]:
                await websocket.send_text(json.dumps(event, default=str))
        while True:
            # Keepalive; the server pushes, the client only needs to stay open.
            await asyncio.wait_for(websocket.receive_text(), timeout=300)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    except Exception:
        pass
    finally:
        if websocket in state.connections:
            state.connections.remove(websocket)


# --------------------------------------------------------------------------
# Built-in demo endpoint — a weak chatbot to aim the probe at
# --------------------------------------------------------------------------
@app.get("/demo/v1/chat/completions", include_in_schema=False)
def demo_status() -> HTMLResponse:
    return HTMLResponse(STATUS_PAGE)


@app.post("/demo/v1/chat/completions", tags=["probe"])
async def demo_chat(request: Request) -> Dict[str, Any]:
    """OpenAI-compatible, no key. Async on purpose: the probe runs in a worker
    thread and calls back into this same server, so this handler must not
    need a worker thread of its own."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    return completion(body if isinstance(body, dict) else {})


# --------------------------------------------------------------------------
# Static frontend
# --------------------------------------------------------------------------
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        """Serve the SPA for any non-API path (client-side routing)."""
        if full_path.lstrip("/").startswith(("api/", "ws/", "demo/", "docs", "openapi.json", "redoc")):
            raise HTTPException(status_code=404, detail="Not found")
        if full_path.rstrip("/") in ("bot", "chat", "astrabot") and (FRONTEND_DIST / "bot.html").exists():
            return FileResponse(FRONTEND_DIST / "bot.html")
        # Serve only files that really live inside the bundle. A request such
        # as "//etc/passwd" arrives here as an absolute path, and joining an
        # absolute path discards the base — so resolve and check containment.
        root = FRONTEND_DIST.resolve()
        try:
            candidate = (root / full_path.lstrip("/\\")).resolve()
        except (OSError, ValueError):
            candidate = root / "index.html"
        if candidate.is_file() and root in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
else:
    @app.get("/", include_in_schema=False)
    def index_placeholder() -> JSONResponse:
        return JSONResponse({
            "name": "AstraSec",
            "version": __version__,
            "message": ("Dashboard bundle not found. Build it with "
                        "`cd frontend && npm install && npm run build`, "
                        "or use the API directly at /docs."),
            "docs": "/docs",
        })


def main() -> None:
    import uvicorn
    uvicorn.run("astrasec.api:app", host=settings.api_host,
                port=settings.api_port, reload=False)


if __name__ == "__main__":
    main()
