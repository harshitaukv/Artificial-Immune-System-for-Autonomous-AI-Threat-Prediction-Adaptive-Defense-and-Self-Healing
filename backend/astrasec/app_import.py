"""Read an application's own files and pre-fill its audit.

An audit is only as honest as its inputs, and typing a system prompt and a
dozen deployment switches from memory is where honesty goes to die: people
paste the prompt they *meant* to ship and tick the switches they *meant* to
turn on. This module reads what was actually shipped instead.

Give it the app's source — a single file, or a zip of the project — and it
returns:

* **system prompts** found in the code, ranked, each with the file and line
  it came from;
* **hard-coded secrets**, redacted, with their location;
* **dependencies** from requirements / pyproject / package.json, with the
  pinned version and any match against the local advisory list;
* **posture evidence** — for each deployment switch, whether the code shows
  it, and the line that shows it. A switch with no evidence is reported as
  "not found", never silently assumed on;
* **code risks** that belong in the report on their own: user input
  interpolated into the system prompt, and dynamic code execution.

Nothing here executes the uploaded code. Everything is regular expressions
over text.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .engines.health import DEPENDENCY_ADVISORIES

# ---- what counts as source ----------------------------------------------
CODE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go",
    ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".ipynb",
}
TEXT_EXT = {".txt", ".md", ".prompt", ".j2", ".jinja", ".tmpl", ".mustache", ".hbs"}
CONFIG_EXT = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".properties"}
ALL_EXT = CODE_EXT | TEXT_EXT | CONFIG_EXT
SPECIAL_NAMES = {".env", "requirements.txt", "pipfile", "dockerfile", "procfile"}

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "__pycache__", "dist",
             "build", ".next", ".mypy_cache", ".pytest_cache", "site-packages", ".idea",
             ".vscode", "coverage"}
MAX_MEMBERS = 3000
MAX_TOTAL = 60 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024


class ImportError_(ValueError):
    """The upload could not be read as application source."""


@dataclass
class SourceFile:
    path: str
    text: str

    @property
    def ext(self) -> str:
        return PurePosixPath(self.path).suffix.lower()

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name.lower()

    def line_of(self, pos: int) -> int:
        return self.text.count("\n", 0, pos) + 1


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------
def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = raw.decode(enc)
            if enc == "utf-16" and not raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                continue
            return text
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _wanted(path: str) -> bool:
    p = PurePosixPath(path)
    if any(part.lower() in SKIP_DIRS for part in p.parts[:-1]):
        return False
    name = p.name.lower()
    return (p.suffix.lower() in ALL_EXT or name in SPECIAL_NAMES
            or name.startswith(".env") or name.startswith("requirements"))


def _notebook_text(raw: str) -> str:
    try:
        nb = json.loads(raw)
    except ValueError:
        return raw
    cells = []
    for c in nb.get("cells", []):
        src = c.get("source", "")
        cells.append("".join(src) if isinstance(src, list) else str(src))
    return "\n\n".join(cells)


def load_sources(filename: str, raw: bytes) -> List[SourceFile]:
    """Turn an upload into a list of text files. Zips are unpacked in memory."""
    name = filename or "upload"
    if name.lower().endswith(".zip") or raw[:4] == b"PK\x03\x04":
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile as exc:
            raise ImportError_(f"{name} is not a valid zip archive.") from exc
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            raise ImportError_(f"The archive has {len(infos)} files; the limit is "
                               f"{MAX_MEMBERS}. Zip the source folder without "
                               f"node_modules or virtual environments.")
        total = 0
        out: List[SourceFile] = []
        for info in infos:
            if not _wanted(info.filename) or info.file_size > MAX_FILE:
                continue
            total += info.file_size
            if total > MAX_TOTAL:
                raise ImportError_("The archive expands past 60 MB of source. "
                                   "Leave out data files and dependencies.")
            text = _decode(zf.read(info))
            if info.filename.lower().endswith(".ipynb"):
                text = _notebook_text(text)
            out.append(SourceFile(info.filename, text))
        if not out:
            raise ImportError_("The archive contains no source, config or prompt files "
                               "AstraSec can read.")
        return out

    if len(raw) > MAX_FILE * 4:
        raise ImportError_("That file is too large to be application source.")
    text = _decode(raw)
    if name.lower().endswith(".ipynb"):
        text = _notebook_text(text)
    return [SourceFile(name, text)]


# --------------------------------------------------------------------------
# System prompts
# --------------------------------------------------------------------------
_STR = r"""(?P<q>\"\"\"|'''|`|\"|')(?P<body>.*?)(?<!\\)(?P=q)"""
_PROMPT_VAR = re.compile(
    r"(?P<name>\b[A-Za-z_][\w]*(?:system|prompt|instruction|persona|preamble)[\w]*)"
    r"\s*(?::\s*[\w\[\], ]+)?\s*[:=]\s*(?:[frbuFRBU]{1,2})?" + _STR,
    re.IGNORECASE | re.DOTALL)
_ROLE_SYSTEM = re.compile(
    r"""[\"']?role[\"']?\s*[:=]\s*[\"']system[\"']\s*,\s*[\"']?content[\"']?\s*[:=]\s*"""
    r"(?:[frbuFRBU]{1,2})?" + _STR,
    re.IGNORECASE | re.DOTALL)
_SYSTEM_MESSAGE = re.compile(
    r"\b(?:SystemMessage|SystemMessagePromptTemplate\.from_template|system_instruction|"
    r"systemInstruction|instructions)\s*[(=:]\s*(?:content\s*=\s*)?(?:[frbuFRBU]{1,2})?" + _STR,
    re.DOTALL)
_PROMPT_WORDS = re.compile(
    r"\b(you are|your role|assistant|do not|don't|never|always|only|must|refuse|"
    r"respond|answer|rules?|instructions?)\b", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r"\{\{?\s*(?:user[_ ]?(?:input|message|query|question|text)?|input|query|question|"
    r"message|prompt|request\.[\w.]+|req\.body[\w.]*)\s*\}?\}|\$\{\s*(?:user\w*|input|"
    r"query|question|message|req\.body[\w.]*)\s*\}", re.IGNORECASE)


def _prompt_score(text: str, via: str) -> float:
    words = len(text.split())
    if words < 8:
        return 0.0
    cues = len(_PROMPT_WORDS.findall(text))
    base = {"role": 3.0, "sdk": 2.5, "variable": 2.0, "file": 1.5, "config": 2.0}[via]
    return round(base + min(cues, 12) * 0.35 + min(words, 400) / 200, 3)


def _unescape(body: str, quote: str) -> str:
    if quote in ('"', "'"):
        body = body.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"') \
                   .replace("\\'", "'")
    return body.strip()


def find_prompts(files: Iterable[SourceFile]) -> List[Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}

    def add(text: str, f: SourceFile, pos: int, via: str, name: str = "") -> None:
        text = text.strip()
        score = _prompt_score(text, via)
        if score <= 0:
            return
        key = re.sub(r"\s+", " ", text)[:400]
        if key in found and found[key]["score"] >= score:
            return
        found[key] = {
            "text": text[:20_000],
            "location": f"{f.path}:{f.line_of(pos)}" if via != "file" else f.path,
            "source": {"role": "a system-role message", "sdk": "an SDK system-message call",
                       "variable": f"the variable {name}" if name else "a prompt variable",
                       "file": "a prompt file", "config": f"the config key {name}"}[via],
            "words": len(text.split()),
            "interpolates_user_input": bool(_PLACEHOLDER.search(text)),
            "score": score,
        }

    for f in files:
        if f.ext in TEXT_EXT and re.search(r"prompt|system|instruction|persona", f.name):
            add(f.text, f, 0, "file")
            continue
        if f.ext in CODE_EXT:
            for rx, via in ((_ROLE_SYSTEM, "role"), (_SYSTEM_MESSAGE, "sdk"),
                            (_PROMPT_VAR, "variable")):
                for m in rx.finditer(f.text):
                    add(_unescape(m.group("body"), m.group("q")), f, m.start(), via,
                        m.groupdict().get("name") or "")
        elif f.ext in (".json", ".yaml", ".yml", ".toml"):
            for m in re.finditer(
                    r"""(?P<name>[\w-]*(?:system|prompt|instruction)[\w-]*)[\"']?\s*[:=]\s*"""
                    r"""(?:\|[-+]?\s*\n(?P<block>(?:[ \t]+.*\n?)+)|""" + _STR + ")",
                    f.text, re.IGNORECASE):
                body = m.group("block") or _unescape(m.group("body") or "", m.group("q") or '"')
                if m.group("block"):
                    body = re.sub(r"^[ \t]+", "", body, flags=re.MULTILINE)
                add(body, f, m.start(), "config", m.group("name"))

    ranked = sorted(found.values(), key=lambda d: -d["score"])
    return ranked[:12]


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------
_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("OpenAI / Anthropic-style API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Database URL with password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s@/]{3,}@[^\s\"']+")),
]
_ASSIGNED_SECRET = re.compile(
    r"""(?P<name>\b[A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*)\s*[:=]\s*"""
    r"""[\"']?(?P<val>[^\s\"'#]{8,})""", re.IGNORECASE)
_PLACEHOLDER_VALUE = re.compile(
    r"^(?:your|xxx|changeme|example|placeholder|dummy|test|<|\$\{|\{\{|os\.environ|"
    r"process\.env|getenv|env\(|settings\.|config\.|none|null|true|false)", re.IGNORECASE)


def _redact(value: str) -> str:
    return value[:4] + "…" + f"[{len(value)} chars redacted]"


def find_secrets(files: Iterable[SourceFile]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for f in files:
        for label, rx in _SECRET_PATTERNS:
            for m in rx.finditer(f.text):
                key = (f.path, m.group(0))
                if key in seen:
                    continue
                seen.add(key)
                out.append({"kind": label, "location": f"{f.path}:{f.line_of(m.start())}",
                            "preview": _redact(m.group(0)),
                            "committed_env_file": f.name.startswith(".env")})
        for m in _ASSIGNED_SECRET.finditer(f.text):
            val = m.group("val")
            if _PLACEHOLDER_VALUE.match(val) or (f.path, val) in seen:
                continue
            # A real secret has mixed character classes; an identifier does not.
            classes = sum(bool(re.search(p, val)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"))
            if classes < 2 or val.isidentifier() and "_" in val:
                continue
            seen.add((f.path, val))
            out.append({"kind": f"Value assigned to {m.group('name')}",
                        "location": f"{f.path}:{f.line_of(m.start())}",
                        "preview": _redact(val),
                        "committed_env_file": f.name.startswith(".env")})
    return out[:50]


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-\[\]]*)\s*(?:(==|>=|<=|~=|>|<|!=)\s*([\w.\-*]+))?")


def _version_tuple(v: str) -> Tuple[int, ...]:
    parts = []
    for p in re.split(r"[.\-+]", v):
        m = re.match(r"\d+", p)
        if not m:
            break
        parts.append(int(m.group(0)))
    return tuple(parts) or (0,)


def _norm(name: str) -> str:
    return re.sub(r"\[.*\]", "", name).lower().replace("_", "-").strip()


def find_dependencies(files: Iterable[SourceFile]) -> List[Dict[str, Any]]:
    deps: Dict[str, Dict[str, Any]] = {}

    def add(name: str, op: Optional[str], ver: Optional[str], where: str, eco: str) -> None:
        n = _norm(name)
        if not n or n in ("python", "node", "-e", "-r", "pip"):
            return
        raw_ver = (ver or "").strip()
        pinned = op == "==" or (eco == "npm" and op is None
                                and re.fullmatch(r"v?[\d.]+", raw_ver) is not None)
        ver = raw_ver.lstrip("^~=v ") or None
        deps[n] = {"name": n, "version": ver, "pinned": bool(pinned), "file": where,
                   "ecosystem": eco}

    for f in files:
        if f.name.startswith("requirements") and f.name.endswith(".txt"):
            for line in f.text.splitlines():
                line = line.split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = _REQ_LINE.match(line)
                if m:
                    add(m.group(1), m.group(2), m.group(3), f.path, "pypi")
        elif f.name == "pyproject.toml":
            block = re.search(r"dependencies\s*=\s*\[(.*?)\]", f.text, re.DOTALL)
            if block:
                for item in re.findall(r"[\"']([^\"']+)[\"']", block.group(1)):
                    m = _REQ_LINE.match(item)
                    if m:
                        add(m.group(1), m.group(2), m.group(3), f.path, "pypi")
            poetry = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\Z)", f.text, re.DOTALL)
            if poetry:
                for n, v in re.findall(r"^([\w.\-]+)\s*=\s*[\"']([^\"']+)[\"']",
                                       poetry.group(1), re.MULTILINE):
                    add(n, "==" if re.fullmatch(r"[\d.]+", v) else None, v, f.path, "pypi")
        elif f.name == "package.json":
            try:
                pkg = json.loads(f.text)
            except ValueError:
                continue
            for section in ("dependencies", "devDependencies"):
                for n, v in (pkg.get(section) or {}).items():
                    add(n, None, str(v), f.path, "npm")

    # Match against the advisory list the health engine already uses.
    for d in deps.values():
        d["advisories"] = []
        for advisory, (sev, code, detail) in DEPENDENCY_ADVISORIES.items():
            m = re.match(r"([\w.\-]+)(?:<([\w.]+))?", advisory)
            name, below = _norm(m.group(1)), m.group(2)
            if name != d["name"]:
                continue
            if below is None:
                d["advisories"].append({"advisory": advisory, "code": code,
                                        "severity": sev.value, "detail": detail,
                                        "certain": True})
            elif d["version"] and d["pinned"]:
                if _version_tuple(d["version"]) < _version_tuple(below):
                    d["advisories"].append({"advisory": advisory, "code": code,
                                            "severity": sev.value, "detail": detail,
                                            "certain": True})
            elif not d["pinned"]:
                d["advisories"].append({"advisory": advisory, "code": code,
                                        "severity": sev.value, "detail": detail,
                                        "certain": False})
    return sorted(deps.values(), key=lambda d: d["name"])


# --------------------------------------------------------------------------
# Posture evidence
# --------------------------------------------------------------------------
POSTURE_EVIDENCE: Dict[str, List[str]] = {
    "authentication_required": [
        r"OAuth2PasswordBearer", r"HTTPBearer", r"APIKeyHeader", r"Depends\(\s*get_current_user",
        r"@login_required", r"passport\.authenticate", r"jwt\.(?:decode|verify)",
        r"next-auth|NextAuth\(", r"@clerk/", r"verify_id_token", r"requireAuth",
        r"auth\.requires_auth", r"Authorization.*Bearer",
    ],
    "rate_limiting_enabled": [
        r"\bslowapi\b", r"flask_limiter|Limiter\(", r"express-rate-limit|rateLimit\(",
        r"@ratelimit|django_ratelimit", r"RateLimiter", r"throttle_classes",
        r"@upstash/ratelimit",
    ],
    "logging_enabled": [
        r"^\s*import logging", r"logging\.getLogger", r"\blogger\.(?:info|warning|error)",
        r"\bwinston\b", r"\bpino\b", r"\bstructlog\b", r"langsmith|langfuse|helicone",
    ],
    "output_filtering_enabled": [
        r"moderations?\.create", r"\bguardrails\b", r"nemoguardrails", r"llm_guard|llm-guard",
        r"OutputGuard|output_filter|filter_output|sanitize_output|check_output",
        r"lakera", r"rebuff",
    ],
    "pii_redaction_enabled": [
        r"presidio", r"scrubadub", r"redact(?:_pii|PII|Pii)?\(", r"anonymi[sz]e\(",
    ],
    "sandbox_enabled": [
        r"\be2b\b", r"docker\.from_env|containers\.run", r"RestrictedPython", r"pyodide",
        r"gvisor|firecracker", r"vm2|isolated-vm",
    ],
    "tool_calling_enabled": [
        r"\btools\s*=\s*\[", r"tool_choice", r"\bfunctions\s*=\s*\[", r"@tool\b",
        r"bind_tools", r"function_call", r"AgentExecutor|create_\w*agent", r"tool_use",
    ],
    "retrieval_enabled": [
        r"\bchroma(?:db)?\b", r"\bfaiss\b", r"pinecone", r"weaviate", r"qdrant", r"pgvector",
        r"similarity_search", r"as_retriever|Retriever\b", r"VectorStoreIndex|vectorstore",
        r"embeddings?\.create|Embeddings\(",
    ],
}
_POSTURE_RX = {k: re.compile("|".join(v), re.IGNORECASE | re.MULTILINE)
               for k, v in POSTURE_EVIDENCE.items()}

_CODE_EXEC = re.compile(
    r"(?<![\w.])(?:exec|eval)\s*\(|subprocess\.(?:run|Popen|call|check_output)|os\.system\(|"
    r"child_process|new Function\(|PythonREPL|PythonAstREPLTool|ShellTool|"
    r"allow_dangerous_code\s*=\s*True|trust_remote_code\s*=\s*True")
_MODEL_NAME = re.compile(
    r"""[\"']((?:gpt-[\w.\-]+|o[134](?:-[\w.]+)?|claude-[\w.\-]+|gemini-[\w.\-]+|"""
    r"""llama[\w.:\-]*|mistral[\w.:\-]*|mixtral[\w.:\-]*|phi-?[\w.:\-]+|qwen[\w.:\-]*|"""
    r"""deepseek[\w.:\-]*|command-r[\w.\-]*))[\"']""", re.IGNORECASE)


def find_posture(files: List[SourceFile]) -> Dict[str, Dict[str, Any]]:
    code = [f for f in files if f.ext in CODE_EXT or f.ext in CONFIG_EXT
            or f.name in SPECIAL_NAMES or f.name.startswith("requirements")]
    out: Dict[str, Dict[str, Any]] = {}
    for key, rx in _POSTURE_RX.items():
        evidence = None
        for f in code:
            m = rx.search(f.text)
            if m:
                line = f.text.splitlines()[f.line_of(m.start()) - 1].strip()
                evidence = {"location": f"{f.path}:{f.line_of(m.start())}", "line": line[:160]}
                break
        out[key] = {"detected": evidence is not None, "evidence": evidence}
    return out


def find_code_risks(files: List[SourceFile]) -> List[Dict[str, Any]]:
    out = []
    for f in files:
        if f.ext not in CODE_EXT:
            continue
        for m in _CODE_EXEC.finditer(f.text):
            line = f.text.splitlines()[f.line_of(m.start()) - 1].strip()
            if line.startswith(("#", "//")):
                continue
            out.append({"kind": "dynamic_code_execution",
                        "location": f"{f.path}:{f.line_of(m.start())}", "line": line[:160]})
            if len(out) >= 20:
                return out
    return out


def _guess_name(files: List[SourceFile], fallback: str) -> str:
    for f in files:
        if f.name == "package.json":
            try:
                n = json.loads(f.text).get("name")
                if n:
                    return str(n)
            except ValueError:
                pass
        if f.name == "pyproject.toml":
            m = re.search(r"^name\s*=\s*[\"']([^\"']+)", f.text, re.MULTILINE)
            if m:
                return m.group(1)
    stem = PurePosixPath(fallback).stem
    return stem.replace("_", " ").replace("-", " ").strip().title() or "Imported application"


def _guess_model(files: List[SourceFile]) -> Optional[str]:
    for f in files:
        if f.ext in CODE_EXT or f.ext in CONFIG_EXT or f.name.startswith(".env"):
            m = _MODEL_NAME.search(f.text)
            if m:
                return m.group(1)
    return None


# --------------------------------------------------------------------------
# Code, configuration, API and AI-integration checks
# --------------------------------------------------------------------------
# (code, category, severity, title, pattern, remediation). Patterns run over
# source lines; comments are skipped. Each is a *supported pattern*, not a
# proof — the report says where to look and why.
CODE_CHECKS = [
    ("CODE-SQLI", "code", "high", "SQL built from strings",
     re.compile(r"""(?i)\bf["'][^"'\n]*\b(?:select|insert|update|delete)\b[^"'\n]*\{"""
                r"""|"[^"\n]*\b(?:select|insert|update|delete)\b[^"\n]*"\s*(?:\+|%|\.format)"""
                r"""|'[^'\n]*\b(?:select|insert|update|delete)\b[^'\n]*'\s*(?:\+|%|\.format)"""
                r"""|`[^`\n]*\b(?:select|insert|update|delete)\b[^`\n]*\$\{"""),
     "Use parameterised queries (placeholders + a parameter tuple) or the ORM, never string formatting."),
    ("CODE-PATH", "code", "high", "File path taken from the request",
     re.compile(r"(?:open|send_file|send_from_directory|FileResponse|readFile(?:Sync)?|createReadStream)\s*\([^)\n]*"
                r"(?:request\.|req\.(?:query|params|body)|args\.get|form\.get|params\[)"),
     "Resolve the path, then check it stays inside an allowed directory (reject '..' and absolute paths)."),
    ("CODE-DESER", "code", "high", "Unsafe deserialisation",
     re.compile(r"\bpickle\.loads?\(|\bmarshal\.loads?\(|\bjsonpickle\.decode\(|\byaml\.load\((?![^)\n]*SafeLoader)"
                r"|\bunserialize\(|ObjectInputStream"),
     "Never deserialise untrusted data with pickle/marshal/yaml.load; use JSON or yaml.safe_load."),
    ("CODE-CRYPTO", "code", "medium", "Weak hash used for secrets",
     re.compile(r"(?i)hashlib\.(?:md5|sha1)\(|createHash\(\s*['\"](?:md5|sha1)"),
     "Hash passwords with bcrypt, scrypt, argon2 or PBKDF2 — never MD5 or SHA-1."),
    ("CODE-TLS", "code", "medium", "TLS certificate checking disabled",
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureRequestWarning|CERT_NONE"),
     "Keep certificate verification on; fix the certificate chain instead."),
    ("CFG-DEBUG", "configuration", "medium", "Debug mode enabled",
     re.compile(r"(?:\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*(?:True|1|['\"]true['\"])|app\.run\([^)]*debug\s*=\s*True)"),
     "Turn debug off in production — it exposes stack traces, settings and sometimes a code console."),
    ("CFG-CORS", "configuration", "medium", "CORS allows any origin",
     re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']|CORS\(\s*app\s*\)|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origin\s*:\s*["']\*["']"""),
     "List the exact origins that may call the API; never combine '*' with credentials."),
    ("CFG-BIND", "configuration", "low", "Server listens on every interface",
     re.compile(r"""host\s*=\s*["']0\.0\.0\.0["']|--host\s+0\.0\.0\.0"""),
     "Bind to 127.0.0.1 unless the service must be reachable from other machines, and then put it behind a proxy."),
]

_ROUTE = re.compile(r"@(?:app|router|bp|blueprint|api)\.(?:get|post|put|patch|delete|route)\(|"
                    r"\b(?:app|router)\.(?:get|post|put|patch|delete)\(\s*['\"]/")
_RAW_INPUT = re.compile(r"request\.(?:json|args|form|get_json\(\))\s*\[|req\.body\.\w+")
_LLM_CALL = re.compile(r"chat\.completions\.create|messages\.create\(|ChatOpenAI|ChatAnthropic|ollama\.(?:chat|generate)"
                       r"|\.invoke\(|generate_content\(|pipeline\(\s*['\"]text-generation")
_MODEL_OUTPUT_EXEC = re.compile(
    r"(?:exec|eval|subprocess\.\w+|os\.system|child_process\.\w+)\s*\([^)\n]*\b(?:reply|response|answer|output|completion|"
    r"result|text|content|message)\b")


def find_code_findings(files: List[SourceFile], posture: Dict[str, Dict[str, Any]],
                       prompts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    code = [f for f in files if f.ext in CODE_EXT or f.ext in CONFIG_EXT or f.name.startswith(".env")]
    routes = 0
    llm_files = []
    for f in code:
        lines = f.text.splitlines()
        for i, line in enumerate(lines, start=1):
            st = line.strip()
            if not st or st.startswith(("#", "//", "*", "/*")):
                continue
            for cid, cat, sev, title, rx, fix in CODE_CHECKS:
                if rx.search(line) and (cid, f.path) not in seen:
                    seen.add((cid, f.path))
                    out.append({"code": cid, "category": cat, "severity": sev, "title": title,
                                "location": f"{f.path}:{i}", "line": st[:160], "remediation": fix})
            if _MODEL_OUTPUT_EXEC.search(line) and ("AI-EXEC", f.path) not in seen:
                seen.add(("AI-EXEC", f.path))
                out.append({"code": "AI-EXEC", "category": "ai", "severity": "critical",
                            "title": "Model output is executed as code or a command",
                            "location": f"{f.path}:{i}", "line": st[:160],
                            "remediation": "Never execute model output. If the model must trigger an "
                                           "action, map it to an allow-list of fixed operations "
                                           "and require confirmation for anything destructive."})
            if _RAW_INPUT.search(line) and ("API-INPUT", f.path) not in seen:
                seen.add(("API-INPUT", f.path))
                out.append({"code": "API-INPUT", "category": "api", "severity": "medium",
                            "title": "Request data used without validation",
                            "location": f"{f.path}:{i}", "line": st[:160],
                            "remediation": "Validate request bodies against a schema (e.g. Pydantic, "
                                           "zod) before use: types, lengths and allowed values."})
        routes += len(_ROUTE.findall(f.text))
        if f.ext in CODE_EXT and _LLM_CALL.search(f.text):
            llm_files.append(f.path)

    if routes and not posture.get("authentication_required", {}).get("detected"):
        out.append({"code": "API-AUTH", "category": "api", "severity": "high",
                    "title": f"{routes} API route(s) and no authentication found",
                    "location": "", "line": "",
                    "remediation": "Require authentication on every route that reaches the model or "
                                   "user data (API key, OAuth2 bearer token or session)."})
    if routes and not posture.get("rate_limiting_enabled", {}).get("detected"):
        out.append({"code": "API-RATE", "category": "api", "severity": "medium",
                    "title": "API routes without rate limiting",
                    "location": "", "line": "",
                    "remediation": "Add per-client rate limits (slowapi, express-rate-limit, a gateway) "
                                   "— model extraction and credential stuffing both need volume."})
    if llm_files and not posture.get("output_filtering_enabled", {}).get("detected"):
        out.append({"code": "AI-OUTPUT", "category": "ai", "severity": "high",
                    "title": "Model output returned without validation",
                    "location": llm_files[0], "line": "",
                    "remediation": "Filter replies before they reach users: secrets, personal data and "
                                   "system-prompt disclosure (AstraSec's response analyzer does this)."})
    if posture.get("retrieval_enabled", {}).get("detected") and not any(
            re.search(r"\bas data\b|untrusted|do not follow", p.get("text", ""), re.IGNORECASE)
            for p in prompts):
        out.append({"code": "AI-RAG", "category": "ai", "severity": "high",
                    "title": "Retrieved documents are trusted like instructions",
                    "location": posture["retrieval_enabled"]["evidence"]["location"] if
                    posture["retrieval_enabled"].get("evidence") else "", "line": "",
                    "remediation": "Wrap retrieved text as data, tell the model never to follow "
                                   "instructions inside it, and scan documents before indexing."})
    if posture.get("tool_calling_enabled", {}).get("detected") and \
            any(r["code"] in ("AI-EXEC",) for r in out):
        out.append({"code": "AI-TOOLS", "category": "ai", "severity": "high",
                    "title": "Tools can run commands with the app's own permissions",
                    "location": posture["tool_calling_enabled"]["evidence"]["location"], "line": "",
                    "remediation": "Give each tool the least privilege it needs and run code tools "
                                   "in a sandbox."})
    return out


# --------------------------------------------------------------------------
def import_application(filename: str, raw: bytes) -> Dict[str, Any]:
    files = load_sources(filename, raw)
    prompts = find_prompts(files)
    secrets = find_secrets(files)
    deps = find_dependencies(files)
    posture = find_posture(files)
    code_risks = find_code_risks(files)

    code_findings = find_code_findings(files, posture, prompts)
    interpolated = [p for p in prompts if p["interpolates_user_input"]]
    for p in interpolated:
        code_risks.insert(0, {"kind": "user_input_in_system_prompt",
                              "location": p["location"],
                              "line": "System prompt template contains a user-input placeholder."})

    # What the form should be pre-filled with. Only switches with evidence are
    # turned on: an undetected control is exactly the thing an audit should
    # make the operator confirm, not assume.
    suggested = {k: v["detected"] for k, v in posture.items()}
    suggested["system_prompt_protected"] = bool(prompts) and not interpolated
    known_vuln = sorted({a["advisory"] for d in deps for a in d["advisories"] if a["certain"]})

    return {
        "filename": filename,
        "files_scanned": len(files),
        "files": [f.path for f in files][:200],
        "app_name": _guess_name(files, filename),
        "model_name": _guess_model(files),
        "prompts": prompts,
        "secrets": secrets,
        "dependencies": deps,
        "posture": posture,
        "code_risks": code_risks,
        "code_findings": code_findings,
        "suggested_app": {
            **suggested,
            "dependencies": [d["name"] + (f"=={d['version']}" if d["pinned"] and d["version"] else "")
                             for d in deps],
            "known_vulnerable_dependencies": known_vuln,
        },
    }


__all__ = ["import_application", "load_sources", "find_prompts", "find_secrets",
           "find_dependencies", "find_posture", "find_code_risks", "ImportError_"]
