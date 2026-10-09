"""Sensitive-data detection and redaction, shared by every AstraSec guard.

One detector, used in four places, so they can never disagree about what
counts as a secret:

* the **file guard** — secrets and personal data inside an uploaded document;
* the **response guard** — secrets, personal data and internal details in what
  the model is about to say;
* the **incident logger** — nothing is written to the database, an alert or
  the dashboard until it has been through :func:`redact`;
* the **application auditor** — hard-coded credentials in source.

Design rules:

1. **Never keep the value.** A finding records the kind, the location and a
   redacted preview (first four characters and a length). The raw match is
   used only for in-place replacement and then dropped.
2. **Validate before claiming.** A 16-digit number is only a payment card if
   it passes the Luhn checksum; a 12-digit number is only an Aadhaar number if
   it passes Verhoeff. Without that, order IDs and phone numbers are reported
   as cards, and an owner who sees that twice stops reading the alerts.
3. **Placeholders are not secrets.** ``API_KEY=your-key-here`` is
   documentation.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional, Pattern, Tuple
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Checksums
# --------------------------------------------------------------------------
def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) != 12 or d[0] in (0, 1):
        return False
    c = 0
    for i, n in enumerate(reversed(d)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][n]]
    return c == 0


def _iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in rearranged)
    try:
        return int(num) % 97 == 1
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Detector table
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Detector:
    kind: str                    # stable id, e.g. "api_key"
    label: str                   # human label, e.g. "API key"
    category: str                # secret | pii | infrastructure
    severity: str                # low | medium | high | critical
    pattern: Pattern
    validate: Optional[Callable[[str], bool]] = None
    group: int = 0               # which regex group is the sensitive value


_PLACEHOLDER = re.compile(
    r"^(?:your[_\-\s]|<|\$\{|\{\{|x{4,}|\*{4,}|changeme|example|placeholder|dummy|"
    r"sample|redacted|none$|null$|true$|false$|os\.environ|process\.env|getenv|env\()"
    r"|^\[[A-Z\-]*REDACTED\]$|REDACTED\]?$",
    re.IGNORECASE)


def _real_secret_value(v: str) -> bool:
    if _PLACEHOLDER.match(v):
        return False
    if len(v) < 8:
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"))
    if classes < 2:
        return False
    # snake_case identifiers such as `settings_api_key` are references, not values
    if re.fullmatch(r"[a-z_][a-z0-9_.]*", v):
        return False
    return True


DETECTORS: List[Detector] = [
    # ---- credentials ------------------------------------------------------
    Detector("private_key", "Private key", "secret", "critical",
             re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----"
                        r"[\s\S]{0,4000}?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    Detector("api_key", "OpenAI / Anthropic API key", "secret", "critical",
             re.compile(r"\bsk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_\-]{20,}")),
    Detector("api_key", "GitHub token", "secret", "critical",
             re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    Detector("api_key", "AWS access key ID", "secret", "critical",
             re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("api_key", "AWS secret access key", "secret", "critical",
             re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=:\s]+([A-Za-z0-9/+=]{40})\b"),
             group=1),
    Detector("api_key", "Google API key", "secret", "critical",
             re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Detector("api_key", "Slack token", "secret", "critical",
             re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    Detector("api_key", "Stripe key", "secret", "critical",
             re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    Detector("api_key", "Hugging Face token", "secret", "critical",
             re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    Detector("api_key", "GitLab token", "secret", "critical",
             re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    Detector("api_key", "Groq key", "secret", "critical",
             re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    Detector("token", "JSON Web Token", "secret", "high",
             re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    Detector("token", "Bearer token", "secret", "high",
             re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-_.=]{20,})"), group=1),
    Detector("db_credential", "Database URL with password", "secret", "critical",
             re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)"
                        r"://[^\s:/@]+:[^\s@/]{3,}@[^\s\"'<>]+")),
    Detector("password", "Password", "secret", "high",
             re.compile(r"(?i)\b(?:password|passwd|pwd|passphrase|passcode|pin\s*code)\b"
                        r"\s*(?:is|=|:|->)\s*[\"']?([^\s\"',;]{6,})"),
             validate=lambda v: _real_secret_value(v) or bool(re.search(r"\d", v) and len(v) >= 6
                                                                and not _PLACEHOLDER.match(v)),
             group=1),
    Detector("api_key", "Assigned secret", "secret", "high",
             re.compile(r"(?i)\b[A-Z0-9_]*(?:API[_-]?KEY|SECRET(?:[_-]?KEY)?|ACCESS[_-]?TOKEN|"
                        r"AUTH[_-]?TOKEN|CLIENT[_-]?SECRET)[A-Z0-9_]*\b\s*[:=]\s*[\"']?([^\s\"'#,;]{8,})"),
             validate=_real_secret_value, group=1),
    # ---- personal data ------------------------------------------------------
    Detector("payment_card", "Payment card number", "pii", "critical",
             re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"), validate=luhn_ok),
    Detector("national_id", "Aadhaar number", "pii", "high",
             re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), validate=verhoeff_ok),
    Detector("national_id", "US Social Security number", "pii", "high",
             re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")),
    Detector("national_id", "PAN (India)", "pii", "high",
             re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")),
    Detector("bank_account", "IBAN", "pii", "high",
             re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b"),
             validate=_iban_ok),
    Detector("email", "Email address", "pii", "medium",
             re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("phone", "Phone number", "pii", "medium",
             re.compile(r"(?<![\w+])(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?)?"
                        r"(?:[6-9]\d{9}|\d{3}[\s-]\d{3}[\s-]\d{4}|\d{5}[\s-]\d{5})(?!\d)")),
    # ---- infrastructure -------------------------------------------------------
    Detector("internal_host", "Internal host or URL", "infrastructure", "medium",
             re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                        r"|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                        r"|(?:[a-z0-9-]+\.)+(?:internal|local|corp|intranet|lan))(?![a-z0-9-])[^\s\"'<>)]*",
                        re.IGNORECASE)),
]

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LABEL_TOKEN = {
    "private_key": "PRIVATE-KEY", "api_key": "API-KEY", "token": "TOKEN",
    "db_credential": "DB-CREDENTIAL", "password": "PASSWORD", "payment_card": "CARD",
    "national_id": "NATIONAL-ID", "bank_account": "BANK-ACCOUNT", "email": "EMAIL",
    "phone": "PHONE", "internal_host": "INTERNAL-URL",
}


@dataclass
class Finding:
    kind: str
    label: str
    category: str
    severity: str
    start: int
    end: int
    preview: str                 # never the value — see _preview
    line: Optional[int] = None

    def public(self) -> Dict:
        d = asdict(self)
        d.pop("start"), d.pop("end")
        return d


def _preview(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return "[REDACTED]"
    return f"{value[:4]}…[{len(value)} chars redacted]"


def detect(text: str, categories: Optional[Tuple[str, ...]] = None,
           allow_values: Tuple[str, ...] = ()) -> List[Finding]:
    """Every sensitive value in ``text``, non-overlapping, strongest first."""
    if not text:
        return []
    allow = {a.strip().lower() for a in allow_values if a.strip()}
    raw: List[Finding] = []
    for det in DETECTORS:
        if categories and det.category not in categories:
            continue
        for m in det.pattern.finditer(text):
            try:
                value = m.group(det.group) or m.group(0)
                s, e = (m.start(det.group), m.end(det.group)) if det.group else (m.start(), m.end())
            except IndexError:
                value, s, e = m.group(0), m.start(), m.end()
            if value.strip().lower() in allow:
                continue
            if det.validate and not det.validate(value):
                continue
            if det.kind == "phone" and len(re.sub(r"\D", "", value)) < 10:
                continue
            raw.append(Finding(det.kind, det.label, det.category, det.severity, s, e,
                               _preview(value), text.count("\n", 0, s) + 1))
    # Resolve overlaps: keep the most severe, then the longest.
    raw.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], -(f.end - f.start), f.start))
    kept: List[Finding] = []
    for f in raw:
        if any(not (f.end <= k.start or f.start >= k.end) for k in kept):
            continue
        kept.append(f)
    kept.sort(key=lambda f: f.start)
    return kept


def redact(text: str, findings: Optional[List[Finding]] = None,
           categories: Optional[Tuple[str, ...]] = None,
           allow_values: Tuple[str, ...] = ()) -> Tuple[str, List[Finding]]:
    """Replace every finding with a typed placeholder such as ``[API-KEY-REDACTED]``."""
    findings = findings if findings is not None else detect(text, categories, allow_values)
    out, last = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        out.append(text[last:f.start])
        out.append(f"[{LABEL_TOKEN.get(f.kind, 'SENSITIVE')}-REDACTED]")
        last = f.end
    out.append(text[last:])
    return "".join(out), findings


def neutralise(text: str, categories: Tuple[str, ...] = ("secret",)) -> Tuple[str, List[Finding]]:
    """Replace sensitive values with the plain word ``REDACTED`` for *analysis*.

    Typed, bracketed placeholders are right for people and for the model, but
    to a text classifier ``[API-KEY-REDACTED]`` is a run of brackets and
    capitals — exactly what obfuscated payloads look like. A plain word reads as
    what it is: a value that has been removed.
    """
    findings = detect(text, categories)
    if not findings:
        return text, findings
    out, last = [], 0
    for f in findings:
        out.append(text[last:f.start])
        out.append("REDACTED")
        last = f.end
    out.append(text[last:])
    return "".join(out), findings


def safe_excerpt(text: str, limit: int = 160) -> str:
    """What may be stored or shown about a piece of untrusted text."""
    clean, _ = redact(text or "")
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


# --------------------------------------------------------------------------
# URLs
# --------------------------------------------------------------------------
_URL = re.compile(r"\b(?:https?|ftp|javascript|data|file|vbscript)://[^\s\"'<>)\]]+|"
                  r"\b(?:javascript|data|vbscript):[^\s\"'<>)\]]{4,}", re.IGNORECASE)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
               "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
_RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
               "country", "kim", "loan", "men", "icu", "cam", "rest"}
_EXEC_EXT = re.compile(r"\.(?:exe|scr|bat|cmd|ps1|vbs|js|jar|msi|apk|dll|hta|lnk|iso|sh)(?:$|[?#])",
                       re.IGNORECASE)


def analyse_urls(text: str) -> List[Dict]:
    """Suspicious links, each with the reasons it is suspicious."""
    out: List[Dict] = []
    seen = set()
    for m in _URL.finditer(text or ""):
        url = m.group(0).rstrip(".,;:")
        if url in seen:
            continue
        seen.add(url)
        reasons: List[str] = []
        severity = "low"
        scheme = url.split(":", 1)[0].lower()
        if scheme in ("javascript", "vbscript", "data", "file"):
            reasons.append(f"'{scheme}:' link can run code or read local files")
            severity = "high"
        else:
            try:
                parts = urlsplit(url)
                host = (parts.hostname or "").lower()
            except ValueError:
                host, parts = "", None
            if parts is not None and parts.username:
                reasons.append("credentials embedded in the link")
                severity = "high"
            try:
                ipaddress.ip_address(host)
                reasons.append("raw IP address instead of a domain")
                severity = max(severity, "medium", key=SEVERITY_ORDER.get)
            except ValueError:
                pass
            if "xn--" in host:
                reasons.append("punycode domain (possible look-alike)")
                severity = max(severity, "medium", key=SEVERITY_ORDER.get)
            if host in _SHORTENERS:
                reasons.append("link shortener hides the destination")
            if host.rsplit(".", 1)[-1] in _RISKY_TLDS:
                reasons.append(f"high-abuse top-level domain .{host.rsplit('.', 1)[-1]}")
            if host.count(".") >= 4:
                reasons.append("unusually deep subdomain chain")
            if _EXEC_EXT.search(parts.path if parts else url):
                reasons.append("points straight at an executable or script")
                severity = "high"
            if re.search(r"(?:localhost|\.internal|\.local|\.corp)$", host):
                reasons.append("internal host")
                severity = max(severity, "medium", key=SEVERITY_ORDER.get)
        if reasons:
            out.append({"url_preview": url[:80] + ("…" if len(url) > 80 else ""),
                        "reasons": reasons, "severity": severity,
                        "line": (text or "").count("\n", 0, m.start()) + 1})
    return out[:50]


__all__ = ["detect", "redact", "neutralise", "safe_excerpt", "analyse_urls", "Finding", "DETECTORS",
           "luhn_ok", "verhoeff_ok", "SEVERITY_ORDER"]
