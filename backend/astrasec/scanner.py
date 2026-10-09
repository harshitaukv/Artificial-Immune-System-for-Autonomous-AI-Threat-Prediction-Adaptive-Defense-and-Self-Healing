"""Real-input scanning — the analyst-facing entry point to the immune system.

Everything here works on material the user actually supplies: a pasted prompt,
an exported chat log, a PDF a customer sent, the prompt templates inside a
codebase. Nothing is generated.

Each source is reduced to a list of :class:`ScanItem` — a unit of text plus
enough provenance to point the analyst back at *where it came from* (line 412,
row 88 column ``message``, page 3, ``prompts.py`` line 57). Provenance is the
difference between "your file contains an injection" and "your file contains an
injection, here, in this cell".

Supported sources
-----------------
``text``      pasted directly, scanned whole or split per line
``txt/md/log`` one item per non-empty line
``csv/tsv``   one item per cell of the chosen text column(s)
``json/jsonl`` every string leaf, with its JSON path
``pdf``       one item per page block, plus a whole-document pass
``docx/odt``  paragraphs, tables, headers, footers, footnotes and comments
``pptx/odp``  slide text and speaker notes
``xlsx/xls/ods`` one item per text cell, with sheet, row and column
``html/xml``  visible text, HTML comments, alt text, XML elements
``eml``       subject, body and any attachments, recursively
``rtf/doc``   rich text, and best-effort recovery from legacy .doc
``zip``       every supported file inside, each with its own path
``code``      string literals and comments, where prompt templates actually live

Office and OpenDocument formats are read straight from their XML with the
standard library (see :mod:`astrasec.documents`); only PDF and legacy .xls
need a package.

Indirect prompt injection is the reason document formats matter: an attacker
does not need access to your app if they can put an instruction inside a CV
your app reads.
"""
from __future__ import annotations

import ast
import codecs
import csv
import io
import json
import re
from html.parser import HTMLParser
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .documents import (
    pdf_paragraphs, Block, DocumentError, MissingDependency, Sheet, extract_doc, extract_docx,
    extract_eml, extract_odp, extract_ods, extract_odt, extract_pdf,
    extract_pptx, extract_xls, extract_xlsx, extract_xml, parser_status,
    rtf_to_text,
)
from .schemas import AppContext, InspectRequest, ThreatClass

# --------------------------------------------------------------------------
# Source classification
# --------------------------------------------------------------------------
TEXT_EXT = {".txt", ".md", ".markdown", ".log", ".text", ".rst"}
SUBTITLE_EXT = {".srt", ".vtt"}
CSV_EXT = {".csv", ".tsv"}
JSON_EXT = {".json", ".jsonl", ".ndjson"}
PDF_EXT = {".pdf"}
DOCX_EXT = {".docx", ".docm", ".dotx", ".dotm"}
PPTX_EXT = {".pptx", ".pptm", ".potx"}
XLSX_EXT = {".xlsx", ".xlsm", ".xltx"}
XLS_EXT = {".xls"}
ODT_EXT = {".odt", ".ott"}
ODP_EXT = {".odp"}
ODS_EXT = {".ods"}
RTF_EXT = {".rtf"}
DOC_EXT = {".doc"}
EML_EXT = {".eml"}
HTML_EXT = {".html", ".htm", ".xhtml"}
XML_EXT = {".xml"}
ZIP_EXT = {".zip"}
CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".rs", ".kt", ".swift", ".sh", ".yaml", ".yml",
    ".toml", ".ini", ".env", ".cfg", ".sql", ".ipynb",
}
SHEET_EXT = XLSX_EXT | XLS_EXT | ODS_EXT
SUPPORTED_EXT = (TEXT_EXT | SUBTITLE_EXT | CSV_EXT | JSON_EXT | PDF_EXT
                 | DOCX_EXT | PPTX_EXT | SHEET_EXT | ODT_EXT | ODP_EXT
                 | RTF_EXT | DOC_EXT | EML_EXT | HTML_EXT | XML_EXT | ZIP_EXT
                 | CODE_EXT)

# Formats people reasonably try that genuinely cannot be read as text. Each
# gets a specific explanation instead of a generic "unsupported".
_KNOWN_UNSUPPORTED = {
    frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif",
               ".tiff", ".heic", ".svg"}):
        "Images can't be scanned: AstraSec reads text, and getting text out of "
        "a picture needs OCR. Copy the text into the Paste text tab instead.",
    frozenset({".mp3", ".wav", ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".webm"}):
        "Audio and video can't be scanned. If you have a transcript or "
        "subtitles (.srt, .vtt), upload those instead.",
    frozenset({".msg"}):
        "Outlook .msg files use a proprietary format. In Outlook, use "
        "File → Save As → .eml (or drag the email to your desktop "
        "from a web client) and upload that.",
    frozenset({".ppt"}):
        "Legacy PowerPoint (.ppt) isn't supported. Open it and Save As .pptx.",
    frozenset({".exe", ".dll", ".bin", ".iso", ".dmg", ".apk"}):
        "Binary programs don't contain text to scan.",
    frozenset({".rar", ".7z", ".tar", ".gz", ".tgz"}):
        "Only .zip archives are supported. Re-compress the folder as a .zip.",
}

MAX_ITEMS = 5_000
MAX_ITEM_CHARS = 20_000
MIN_ITEM_CHARS = 3


class UnsupportedFile(ValueError):
    """Raised when a file extension has no parser."""


@dataclass
class ScanItem:
    """One unit of text to inspect, with where it came from."""

    text: str
    locator: str                       # human-readable: "line 42", "row 8 · message"
    index: int = 0
    context: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------
def decode_text(raw: bytes) -> str:
    """Decode an uploaded text file the way Windows actually writes them.

    Excel's "CSV UTF-8" export starts with a byte-order mark — left in place
    it becomes part of the first column name, so "id" silently stops matching
    "id". Notepad's "Unicode" is UTF-16. Anything else is tried as UTF-8 and
    then as Windows-1252, the encoding of most older exports.
    """
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16", errors="replace")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _blocks_to_items(blocks: Iterable[Block], prefix: str = "") -> List[ScanItem]:
    items: List[ScanItem] = []
    for b in blocks:
        text = b.text.strip()
        if len(text) < MIN_ITEM_CHARS:
            continue
        items.append(ScanItem(text=text[:MAX_ITEM_CHARS], locator=prefix + b.locator,
                              index=len(items), context=dict(b.context)))
        if len(items) >= MAX_ITEMS:
            break
    return items


def _clean(s: Any) -> str:
    if s is None:
        return ""
    return str(s).strip()


def parse_text(content: str, split: str = "line") -> List[ScanItem]:
    """Plain text. ``split`` is ``line``, ``paragraph`` or ``whole``."""
    if split == "whole":
        return [ScanItem(text=content[:MAX_ITEM_CHARS], locator="whole document", index=0)]
    if split == "paragraph":
        chunks = re.split(r"\n\s*\n", content)
        return [
            ScanItem(text=c.strip()[:MAX_ITEM_CHARS], locator=f"paragraph {i + 1}", index=i)
            for i, c in enumerate(chunks)
            if len(c.strip()) >= MIN_ITEM_CHARS
        ][:MAX_ITEMS]
    items = []
    for i, line in enumerate(content.splitlines()):
        line = line.strip()
        if len(line) >= MIN_ITEM_CHARS:
            items.append(ScanItem(text=line[:MAX_ITEM_CHARS], locator=f"line {i + 1}", index=i))
        if len(items) >= MAX_ITEMS:
            break
    return items


def sniff_csv_columns(content: str) -> List[str]:
    """Header names, so the UI can let the analyst pick the message column."""
    try:
        dialect = csv.Sniffer().sniff(content[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(content), dialect)
    try:
        return [h.strip() for h in next(reader)]
    except StopIteration:
        return []


_IDENTIFIER = re.compile(r"^[A-Za-z]{0,6}[-_/#]?\d[\w\-/#.]*$")


def _is_identifier(val: str) -> bool:
    """A single short token with a digit in it — a ticket, invoice or SKU.

    "T-9" and "INV-2231" are references, not text anyone wrote, and scanning
    one is a wasted inspection that can only ever produce noise.
    """
    return " " not in val and len(val) <= 16 and bool(_IDENTIFIER.match(val))


# Columns that almost never contain a prompt; skipped when auto-selecting.
_NON_TEXT_COLUMNS = re.compile(
    r"^(id|uuid|guid|index|idx|timestamp|time|date|created|updated|ts|"
    r"score|count|n|num|rating|price|amount|lat|lon|url|link|status|code)$",
    re.IGNORECASE,
)


def parse_csv(content: str, columns: Optional[Sequence[str]] = None) -> List[ScanItem]:
    """One item per cell of the selected text columns.

    With no explicit column list, every column that does not look like an
    identifier or a number is scanned — a chat export rarely labels its message
    column predictably, and missing it silently would be worse than scanning a
    little too much.
    """
    try:
        dialect = csv.Sniffer().sniff(content[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(content), dialect=dialect)
    fields = reader.fieldnames or []
    if not fields:
        return parse_text(content)

    chosen = [c for c in (columns or []) if c in fields]
    if not chosen:
        chosen = [c for c in fields if c and not _NON_TEXT_COLUMNS.match(c.strip())]
    if not chosen:
        chosen = list(fields)

    items: List[ScanItem] = []
    for r, row in enumerate(reader, start=2):        # row 1 is the header
        for col in chosen:
            val = _clean(row.get(col))
            if len(val) < MIN_ITEM_CHARS or val.replace(".", "", 1).isdigit() or _is_identifier(val):
                continue
            items.append(ScanItem(
                text=val[:MAX_ITEM_CHARS],
                locator=f"row {r} · {col}",
                index=len(items),
                context={"row": r, "column": col},
            ))
            if len(items) >= MAX_ITEMS:
                return items
    return items


def _load_sheets(raw: bytes, suffix: str) -> List[Sheet]:
    if suffix in XLSX_EXT:
        return extract_xlsx(raw)
    if suffix in XLS_EXT:
        return extract_xls(raw)
    if suffix in ODS_EXT:
        return extract_ods(raw)
    raise UnsupportedFile(f"'{suffix}' is not a spreadsheet format.")


def sniff_sheet_columns(raw: bytes, filename: str) -> List[str]:
    """Header names across every sheet, first occurrence wins, order kept."""
    seen: List[str] = []
    for _, rows in _load_sheets(raw, Path(filename).suffix.lower()):
        for h in rows[0][1]:
            h = h.strip()
            if h and h not in seen:
                seen.append(h)
    return seen


def sniff_xlsx_columns(raw: bytes) -> List[str]:
    """Kept for callers that predate the other sheet formats."""
    return sniff_sheet_columns(raw, "book.xlsx")


def _sheets_to_items(sheets: List[Sheet],
                     columns: Optional[Sequence[str]] = None) -> List[ScanItem]:
    """One item per text cell, with the same column rules as a CSV.

    The first row with content is each sheet's header. With several sheets
    the sheet name joins the locator, because "row 8 · message" is ambiguous
    the moment two sheets both have a row 8.
    """
    items: List[ScanItem] = []
    multi = len(sheets) > 1
    for title, rows in sheets:
        header = [h.strip() for h in rows[0][1]]
        chosen = [i for i, h in enumerate(header) if h and h in (columns or [])]
        if not chosen:
            chosen = [i for i, h in enumerate(header)
                      if h and not _NON_TEXT_COLUMNS.match(h)]
        if not chosen:
            chosen = list(range(len(header)))
        prefix = f"{title} · " if multi else ""
        for rownum, row in rows[1:]:
            for i in chosen:
                if i >= len(row):
                    continue
                val = _clean(row[i])
                if len(val) < MIN_ITEM_CHARS or val.replace(".", "", 1).isdigit() or _is_identifier(val):
                    continue
                col = header[i] if i < len(header) and header[i] else f"column {i + 1}"
                items.append(ScanItem(
                    text=val[:MAX_ITEM_CHARS],
                    locator=f"{prefix}row {rownum} · {col}",
                    index=len(items),
                    context={"sheet": title, "row": rownum, "column": col},
                ))
                if len(items) >= MAX_ITEMS:
                    return items
    return items


def parse_sheet(raw: bytes, filename: str,
                columns: Optional[Sequence[str]] = None) -> List[ScanItem]:
    return _sheets_to_items(_load_sheets(raw, Path(filename).suffix.lower()), columns)


def parse_xlsx(raw: bytes, columns: Optional[Sequence[str]] = None) -> List[ScanItem]:
    return _sheets_to_items(extract_xlsx(raw), columns)


class _HTMLText(HTMLParser):
    """Collects visible text as blocks, one per block-level element.

    Script, style and template contents are dropped: they are code the
    browser runs, not text a person reads. Hidden text is a different matter
    — an injection hidden with CSS is exactly what an indirect prompt
    injection looks like — so it is deliberately *kept*.
    """

    _SKIP = {"script", "style", "noscript", "template", "svg", "head"}
    _BLOCK = {"p", "div", "li", "td", "th", "tr", "h1", "h2", "h3", "h4", "h5",
              "h6", "blockquote", "pre", "section", "article", "br", "hr",
              "dt", "dd", "figcaption", "caption", "label", "option", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: List[str] = []
        self._buf: List[str] = []
        self._skip = 0
        self.comments: List[str] = []

    def _flush(self) -> None:
        text = re.sub(r"\s+", " ", "".join(self._buf)).strip()
        if text:
            self.blocks.append(text)
        self._buf = []

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag in self._BLOCK:
            self._flush()
        # Alt text and titles are read aloud by assistive tech and indexed by
        # crawlers — and by any model that ingests the page.
        for name, value in attrs:
            if name in ("alt", "title", "aria-label") and value and value.strip():
                self.blocks.append(value.strip())

    def handle_endtag(self, tag):
        if tag in self._SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag in self._BLOCK:
            self._flush()

    def handle_data(self, data):
        if not self._skip:
            self._buf.append(data)

    def handle_comment(self, data):
        # An HTML comment is invisible on the page but fully visible to any
        # model reading the source — a classic indirect-injection carrier.
        if data.strip():
            self.comments.append(data.strip())

    def close(self):
        super().close()
        self._flush()


def parse_html(content: str) -> List[ScanItem]:
    """Visible text blocks, then HTML comments, each keeping its position."""
    parser = _HTMLText()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        # Real-world HTML is often malformed; fall back to tag stripping
        # rather than refusing the file.
        stripped = re.sub(r"<[^>]+>", " ", content)
        return parse_text(stripped, "paragraph")

    items: List[ScanItem] = []
    for n, block in enumerate(parser.blocks, start=1):
        if len(block) < MIN_ITEM_CHARS:
            continue
        items.append(ScanItem(text=block[:MAX_ITEM_CHARS], locator=f"block {n}",
                              index=len(items), context={"block": n}))
        if len(items) >= MAX_ITEMS:
            return items
    for n, comment in enumerate(parser.comments, start=1):
        if len(comment) < MIN_ITEM_CHARS:
            continue
        items.append(ScanItem(text=comment[:MAX_ITEM_CHARS],
                              locator=f"HTML comment {n}", index=len(items),
                              context={"comment": n}))
        if len(items) >= MAX_ITEMS:
            break
    return items


# Keys whose value is metadata about a message rather than the message. A
# chat export has one of these per record, so scanning them would roughly
# double the item count of every JSON file while classifying the word "user"
# over and over. They are skipped only when the value is a single token: a
# field genuinely called "name" or "status" that contains a sentence is
# content, and is scanned.
_STRUCTURAL_KEYS = frozenset({
    "role", "id", "uuid", "type", "kind", "status", "state", "model", "name",
    "author", "sender", "from", "to", "channel", "source", "level", "severity",
    "timestamp", "time", "date", "created_at", "updated_at", "version", "lang",
    "language", "locale", "format", "mime", "encoding", "finish_reason",
})


def _walk_json(node: Any, path: str, out: List[ScanItem], key: str = "") -> None:
    if len(out) >= MAX_ITEMS:
        return
    if isinstance(node, str):
        v = node.strip()
        if len(v) < MIN_ITEM_CHARS:
            return
        if key.lower() in _STRUCTURAL_KEYS and len(v.split()) == 1:
            return
        out.append(ScanItem(text=v[:MAX_ITEM_CHARS], locator=path or "$",
                            index=len(out), context={"path": path}))
    elif isinstance(node, dict):
        for k, v in node.items():
            _walk_json(v, f"{path}.{k}" if path else str(k), out, key=str(k))
    elif isinstance(node, list):
        # The key carries through a list: ``{"tags": ["billing", "urgent"]}``
        # is still the structural field ``tags``, one level down.
        for i, v in enumerate(node):
            _walk_json(v, f"{path}[{i}]", out, key=key)


def parse_json(content: str, jsonl: bool = False) -> List[ScanItem]:
    """Every string leaf, keyed by its JSON path."""
    out: List[ScanItem] = []
    if jsonl:
        for i, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                _walk_json(json.loads(line), f"L{i}", out)
            except json.JSONDecodeError:
                if len(line) >= MIN_ITEM_CHARS:
                    out.append(ScanItem(text=line[:MAX_ITEM_CHARS],
                                        locator=f"line {i} (unparsed)", index=len(out)))
            if len(out) >= MAX_ITEMS:
                break
        return out
    try:
        _walk_json(json.loads(content), "", out)
    except json.JSONDecodeError:
        # A .json file that is really JSONL is common in chat exports.
        return parse_json(content, jsonl=True)
    return out


def parse_pdf(raw: bytes) -> List[ScanItem]:
    """One item per page block, plus a whole-document item.

    The whole-document pass matters: an instruction can be split across a page
    boundary, and a model reading the file end to end would still obey it.
    """
    pages = extract_pdf(raw)
    items: List[ScanItem] = []
    for p, text in pages:
        for i, para in enumerate(pdf_paragraphs(text), start=1):
            para = para.strip()
            if len(para) >= MIN_ITEM_CHARS:
                items.append(ScanItem(text=para[:MAX_ITEM_CHARS],
                                      locator=f"page {p} · block {i}",
                                      index=len(items), context={"page": p}))
        if len(items) >= MAX_ITEMS:
            break
    if len(pages) > 1:
        items.append(ScanItem(text="\n".join(t for _, t in pages)[:MAX_ITEM_CHARS],
                              locator="whole document", index=len(items),
                              context={"aggregate": True}))
    return items


def parse_docx(raw: bytes) -> List[ScanItem]:
    """Paragraphs, tables, headers, footers, footnotes and comments.

    Read straight from the document XML — no third-party package, so a
    missing library can never break Word uploads. Text formatted to be
    invisible is kept and labelled, because that is where a planted
    instruction hides.
    """
    return _blocks_to_items(extract_docx(raw))


def parse_pptx(raw: bytes) -> List[ScanItem]:
    return _blocks_to_items(extract_pptx(raw))


def parse_odt(raw: bytes) -> List[ScanItem]:
    return _blocks_to_items(extract_odt(raw))


def parse_odp(raw: bytes) -> List[ScanItem]:
    return _blocks_to_items(extract_odp(raw))


def parse_doc(raw: bytes) -> List[ScanItem]:
    return _blocks_to_items(extract_doc(raw))


def parse_rtf(content: str) -> List[ScanItem]:
    """Each ``\\par`` ends a paragraph, so each output line is one."""
    items = parse_text(rtf_to_text(content), "line")
    return [ScanItem(text=i.text, locator=i.locator.replace("line", "paragraph"),
                     index=i.index, context=i.context) for i in items]


def parse_xml(content: str) -> List[ScanItem]:
    try:
        return _blocks_to_items(extract_xml(content))
    except DocumentError:
        return parse_text(content, "line")


_TIMING = re.compile(r"^\s*(?:\d+|WEBVTT.*|NOTE.*|[\d:.,]+\s*-->\s*[\d:.,]+.*)\s*$")


def parse_subtitles(content: str) -> List[ScanItem]:
    """Caption text only — cue numbers and timestamps are not speech."""
    kept = "\n".join("" if _TIMING.match(line) else line for line in content.splitlines())
    return parse_text(kept, "line")


_JS_STRING = re.compile(
    r"""(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).){12,})(?P=q)""", re.DOTALL
)
_COMMENT = re.compile(r"(?m)^\s*(?:#|//)\s?(.{12,})$")

# Placeholders in a prompt template: "{system}", "%(user)s", "${input}", "{0}".
_PLACEHOLDER = re.compile(r"\{[^{}]{0,40}\}|%\([^)]{0,40}\)[sdr]|%[sdr]\b|\$\{[^}]{0,40}\}")


def _is_placeholder_only(value: str) -> bool:
    """True for a literal that is scaffolding rather than prompt text.

    ``"{system}\n{user_input}"`` is a format string, not something a model
    reads as instructions. Classifying it is meaningless — it is short,
    punctuation-heavy and unlike anything in the training distribution, so it
    reliably produces a confident nonsense label. Skipping it removes a whole
    category of false positive from every code scan.
    """
    stripped = _PLACEHOLDER.sub(" ", value)
    stripped = re.sub(r"\\[nrt]|[^A-Za-z ]+", " ", stripped)
    return len(re.sub(r"\s+", "", stripped)) < 12


def parse_code(content: str, filename: str = "") -> List[ScanItem]:
    """String literals and comments — where prompt templates actually live.

    Scanning raw source line by line drowns the report in imports and
    boilerplate. What matters for prompt security is the *text the model will
    see*, which in a codebase means string literals, plus comments (a
    surprisingly common place for a stray instruction to end up in a template).
    """
    items: List[ScanItem] = []
    suffix = Path(filename).suffix.lower()

    if suffix == ".py":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    v = node.value.strip()
                    if len(v) >= 12 and not _is_placeholder_only(v):
                        items.append(ScanItem(
                            text=v[:MAX_ITEM_CHARS],
                            locator=f"line {getattr(node, 'lineno', 0)} · string literal",
                            index=len(items),
                            context={"line": getattr(node, "lineno", 0), "kind": "literal"},
                        ))
        except SyntaxError:
            pass                        # fall through to the regex pass

    if not items:
        for m in _JS_STRING.finditer(content):
            v = m.group("body").strip()
            if len(v) < 12 or _is_placeholder_only(v):
                continue
            line = content.count("\n", 0, m.start()) + 1
            items.append(ScanItem(
                text=v[:MAX_ITEM_CHARS],
                locator=f"line {line} · string literal",
                index=len(items),
                context={"line": line, "kind": "literal"},
            ))
            if len(items) >= MAX_ITEMS:
                break

    for m in _COMMENT.finditer(content):
        v = m.group(1).strip()
        line = content.count("\n", 0, m.start()) + 1
        items.append(ScanItem(
            text=v[:MAX_ITEM_CHARS], locator=f"line {line} · comment",
            index=len(items), context={"line": line, "kind": "comment"},
        ))
        if len(items) >= MAX_ITEMS:
            break

    # A config or template file with no literals is still worth line-scanning.
    if not items and suffix in {".yaml", ".yml", ".toml", ".ini", ".env", ".cfg", ".sh"}:
        return parse_text(content)
    return items[:MAX_ITEMS]


_ZIP_MAX_MEMBERS = 3_000
_ZIP_MAX_TOTAL = 80 * 1024 * 1024
_ZIP_MAX_MEMBER = 15 * 1024 * 1024
_ZIP_SKIP_DIRS = re.compile(
    r"(^|/)(__MACOSX|\.git|node_modules|\.venv|venv|__pycache__|dist|build|"
    r"\.next|\.idea|\.vscode|site-packages)(/|$)")


def parse_zip(raw: bytes, depth: int = 0) -> List[ScanItem]:
    """Every supported file inside the archive, each with its own path.

    This is how a whole codebase is scanned in one upload. Size and count are
    checked from the archive's own directory before anything is decompressed,
    so a small file that expands to gigabytes is refused rather than opened.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise DocumentError("This .zip file could not be opened — it looks damaged.")
    members = [i for i in zf.infolist()
               if not i.is_dir() and not _ZIP_SKIP_DIRS.search(i.filename)]
    if len(members) > _ZIP_MAX_MEMBERS:
        raise DocumentError(f"This archive has {len(members):,} files; the limit is "
                            f"{_ZIP_MAX_MEMBERS:,}. Zip a smaller folder.")
    if sum(i.file_size for i in members) > _ZIP_MAX_TOTAL:
        raise DocumentError("This archive expands to more than 80 MB. Zip a smaller "
                            "folder, or leave out build output and dependencies.")
    items: List[ScanItem] = []
    for info in members:
        suffix = Path(info.filename).suffix.lower()
        if suffix not in SUPPORTED_EXT or info.file_size > _ZIP_MAX_MEMBER:
            continue
        if suffix in ZIP_EXT and depth >= 1:
            continue
        try:
            sub, _ = parse_file(info.filename, zf.read(info), depth=depth + 1)
        except (UnsupportedFile, DocumentError, MissingDependency):
            continue
        except Exception:
            continue
        for it in sub:
            items.append(ScanItem(text=it.text, locator=f"{info.filename} · {it.locator}",
                                  index=len(items),
                                  context={**it.context, "file": info.filename}))
            if len(items) >= MAX_ITEMS:
                return items
    return items


def parse_eml(raw: bytes, depth: int = 0) -> List[ScanItem]:
    """Subject, body and attachments — attachments are scanned as files."""
    items: List[ScanItem] = []
    seen: set = set()

    def add(sub: List[ScanItem], prefix: str) -> None:
        # multipart/alternative sends the same body as plain text and as HTML.
        # Identical text is scanned once; anything only one version carries —
        # an HTML comment, say — is still scanned.
        for it in sub:
            if len(items) >= MAX_ITEMS:
                return
            key = re.sub(r"\s+", " ", it.text).strip().lower()
            if key in seen:
                continue
            seen.add(key)
            items.append(ScanItem(text=it.text, locator=prefix + it.locator,
                                  index=len(items), context=dict(it.context)))

    for part in extract_eml(raw):
        if part.kind == "subject":
            add([ScanItem(text=str(part.content), locator="subject")], "")
        elif part.kind == "text":
            add(parse_text(str(part.content), "paragraph"), "body · ")
        elif part.kind == "html":
            add(parse_html(str(part.content)), "body (HTML) · ")
        elif part.kind == "attachment" and depth < 1:
            suffix = Path(part.name).suffix.lower()
            if suffix in SUPPORTED_EXT and isinstance(part.content, bytes):
                try:
                    sub, _ = parse_file(part.name, part.content, depth=depth + 1)
                except Exception:
                    continue
                add(sub, f"attachment {part.name} · ")
    return items


def parse_file(filename: str, raw: bytes,
               columns: Optional[Sequence[str]] = None,
               split: str = "line", depth: int = 0) -> Tuple[List[ScanItem], str]:
    """Dispatch on extension. Returns ``(items, source_kind)``.

    Three distinct failures, kept distinct so the error says what to do:
    :class:`UnsupportedFile` (convert the file), :class:`MissingDependency`
    (install a package on the server) and :class:`DocumentError` (the file
    itself is damaged or protected).
    """
    suffix = Path(filename).suffix.lower()

    # Binary formats first: these must never be decoded as text.
    if suffix in PDF_EXT:
        return parse_pdf(raw), "pdf"
    if suffix in DOCX_EXT:
        return parse_docx(raw), "docx"
    if suffix in PPTX_EXT:
        return parse_pptx(raw), "pptx"
    if suffix in SHEET_EXT:
        return parse_sheet(raw, filename, columns), suffix.lstrip(".")
    if suffix in ODT_EXT:
        return parse_odt(raw), "odt"
    if suffix in ODP_EXT:
        return parse_odp(raw), "odp"
    if suffix in DOC_EXT:
        return parse_doc(raw), "doc"
    if suffix in EML_EXT:
        return parse_eml(raw, depth), "eml"
    if suffix in ZIP_EXT:
        return parse_zip(raw, depth), "zip"

    for exts, reason in _KNOWN_UNSUPPORTED.items():
        if suffix in exts:
            raise UnsupportedFile(reason)
    if suffix and suffix not in SUPPORTED_EXT:
        raise UnsupportedFile(
            f"'{suffix}' files aren't supported. Supported: documents (.pdf .docx "
            f".doc .odt .rtf), slides (.pptx .odp), spreadsheets (.xlsx .xls .ods "
            f".csv), web and data (.html .xml .json), email (.eml), archives "
            f"(.zip), text, subtitles and source code.")

    content = decode_text(raw)

    if suffix in CSV_EXT:
        return parse_csv(content, columns), "csv"
    if suffix in JSON_EXT:
        return parse_json(content, jsonl=suffix in {".jsonl", ".ndjson"}), "json"
    if suffix in HTML_EXT:
        return parse_html(content), "html"
    if suffix in XML_EXT:
        return parse_xml(content), "xml"
    if suffix in RTF_EXT:
        return parse_rtf(content), "rtf"
    if suffix in SUBTITLE_EXT:
        return parse_subtitles(content), "subtitles"
    if suffix == ".ipynb":
        return parse_json(content), "code"
    if suffix in CODE_EXT:
        return parse_code(content, filename), "code"
    return parse_text(content, split), "text"


# --------------------------------------------------------------------------
# Batch scanning
# --------------------------------------------------------------------------
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A *defensive* instruction contains the same vocabulary as the attack it
# defends against: "never reveal your system prompt" and "reveal your system
# prompt" share every meaningful token. Scanning real material — a codebase's
# own prompt templates, a policy document, a support agent quoting the rules —
# surfaces these constantly, and reporting them as attacks would bury the real
# findings.
#
# They are not suppressed, because a prompt template IS worth reviewing (that
# is what the application audit is for). They are annotated, excluded from the
# risk score, and shown separately, so the headline number reflects hostile
# input rather than the text of your own defences.
_DEFENSIVE = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|cannot|can'?t|won'?t|"
    r"refuse\s+to|under\s+no\s+circumstances|avoid|prohibited\s+from|"
    r"you\s+are\s+not\s+(?:to|allowed\s+to)|forbidden\s+to)\s+"
    r"(?:ever\s+)?(?:reveal|share|disclose|print|output|show|repeat|tell|"
    r"expose|mention|provide|give|leak|divulge|comply|follow|obey|execute)\b",
    re.IGNORECASE,
)
# A guard-rail phrase that describes the defence rather than requesting it.
_DEFENSIVE_CONTEXT = re.compile(
    r"\b(?:system\s+prompt|instructions?|guidelines?|policy|policies|rules?)\b"
    r"[^.\n]{0,40}\b(?:protect|isolat|sanitis|sanitiz|filter|guard|defen[cs])",
    re.IGNORECASE,
)


def looks_defensive(text: str) -> bool:
    """True when the text states a protection rather than requesting a breach."""
    return bool(_DEFENSIVE.search(text) or _DEFENSIVE_CONTEXT.search(text))


class ScanRunner:
    """Runs a list of :class:`ScanItem` through the immune system."""

    def __init__(self, system) -> None:
        self.system = system

    def run(self, items: Sequence[ScanItem], source_name: str, source_kind: str,
            app: Optional[AppContext] = None, tenant_id: str = "scan",
            persist: bool = False) -> Dict[str, Any]:
        """Scan every item and aggregate.

        ``persist=False`` by default: scanning an uploaded corpus is an
        *analysis* pass, and committing thousands of items to immune memory and
        the tenant baseline would distort both. The analyst opts in when they
        want the scan to teach the system.
        """
        app = app or AppContext(app_id=f"scan:{source_name}", app_name=source_name)
        t0 = time.perf_counter()

        findings: List[Dict[str, Any]] = []
        defensive_count = 0
        class_counts: Counter = Counter()
        severity_counts: Counter = Counter()
        action_counts: Counter = Counter()
        signature_counts: Counter = Counter()
        latencies: List[float] = []
        worst: Optional[Dict[str, Any]] = None

        for item in items:
            result = self.system.inspect(InspectRequest(
                prompt=item.text, tenant_id=tenant_id, app=app, persist=persist,
            ))
            cls = result.prediction.threat_class.value
            sev = result.prediction.severity.value
            class_counts[cls] += 1
            severity_counts[sev] += 1
            action_counts[result.defense.action.value] += 1
            for sig in result.prediction.signature_hits:
                signature_counts[sig] += 1
            latencies.append(result.total_latency_ms)

            if cls != "benign":
                defensive = looks_defensive(item.text)
                if defensive:
                    defensive_count += 1
                row = {
                    "likely_defensive": defensive,
                    "index": item.index,
                    "locator": item.locator,
                    "excerpt": item.text[:300],
                    "full_text": item.text[:2000],
                    "threat_class": cls,
                    "severity": sev,
                    "confidence": result.prediction.confidence,
                    "anomaly_score": result.behavior.anomaly_score,
                    "health_score": result.health.health_score,
                    "action": result.defense.action.value,
                    "verdict": result.verdict,
                    "signature_hits": result.prediction.signature_hits,
                    "signature_detail": result.prediction.signature_detail,
                    "top_indicators": result.prediction.top_indicators,
                    "explanation": result.prediction.explanation,
                    "rationale": result.defense.rationale,
                    "sanitized": result.defense.sanitized_prompt,
                    "recommendations": [r.model_dump(mode="json")
                                        for r in result.memory.recommendations[:3]],
                    "context": item.context,
                }
                findings.append(row)
                if worst is None or SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(worst["severity"], 0):
                    worst = row

        # Defensive phrasing sorts below real findings and is excluded from the
        # risk score, but stays in the report.
        findings.sort(key=lambda f: (f["likely_defensive"],
                                     -SEVERITY_RANK.get(f["severity"], 0),
                                     -f["confidence"]))
        hostile = [f for f in findings if not f["likely_defensive"]]
        hostile_severity = Counter(f["severity"] for f in hostile)
        total = len(items)
        clean = total - len(findings)
        duration = time.perf_counter() - t0

        return {
            "scan_id": "SCAN-" + uuid.uuid4().hex[:10],
            "created_at": time.time(),
            "source_name": source_name,
            "source_kind": source_kind,
            "app_id": app.app_id,
            "persisted": persist,
            "items_scanned": total,
            "clean_items": clean,
            "flagged_items": len(findings),
            "hostile_items": len(hostile),
            "defensive_items": defensive_count,
            "detection_rate": round(len(hostile) / total, 4) if total else 0.0,
            "risk_score": self._risk_score(hostile_severity, total),
            "verdict": self._verdict(hostile_severity, len(hostile)),
            "class_distribution": dict(class_counts),
            "severity_distribution": dict(severity_counts),
            "action_distribution": dict(action_counts),
            "top_signatures": [{"id": s, "count": c}
                               for s, c in signature_counts.most_common(10)],
            "worst_finding": worst,
            "findings": findings,
            "duration_seconds": round(duration, 3),
            "mean_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "recommendations": self._roll_up_recommendations(findings),
        }

    @staticmethod
    def _risk_score(severity: Counter, total: int) -> float:
        """0-100, weighted by severity rather than raw count.

        One critical finding in a 10,000-row export matters more than fifty
        low-severity ones, so a flat detection rate would be the wrong headline.
        """
        if not total:
            return 0.0
        weights = {"critical": 1.0, "high": 0.62, "medium": 0.3, "low": 0.1, "none": 0.0}
        weighted = sum(weights.get(s, 0.0) * c for s, c in severity.items())
        # Saturating: risk should read "high" well before every row is malicious.
        return round(min(100.0, 100.0 * (1 - pow(2.71828, -3.5 * weighted / total))), 1)

    @staticmethod
    def _verdict(severity: Counter, flagged: int) -> str:
        if severity.get("critical"):
            return "critical"
        if severity.get("high"):
            return "high"
        if severity.get("medium"):
            return "medium"
        if flagged:
            return "low"
        return "clean"

    @staticmethod
    def _roll_up_recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """De-duplicate per-item advice into a report-level action list."""
        seen: Dict[str, Dict[str, Any]] = {}
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        for f in findings:
            for rec in f.get("recommendations", []):
                key = rec["title"]
                if key not in seen:
                    seen[key] = {**rec, "occurrences": 1}
                else:
                    seen[key]["occurrences"] += 1
        return sorted(seen.values(),
                      key=lambda r: (order.get(r.get("priority", "low"), 5),
                                     -r["occurrences"]))[:8]


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------
def report_to_csv(report: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["locator", "threat_class", "severity", "confidence", "action",
                "verdict", "defensive_phrasing", "signatures", "excerpt"])
    for f in report.get("findings", []):
        w.writerow([
            f["locator"], f["threat_class"], f["severity"],
            f"{f['confidence']:.4f}", f["action"], f["verdict"],
            "yes" if f.get("likely_defensive") else "no",
            " ".join(f.get("signature_hits") or []),
            f["excerpt"].replace("\n", " ")[:500],
        ])
    return buf.getvalue()


__all__ = [
    "ScanItem", "ScanRunner", "UnsupportedFile", "SUPPORTED_EXT", "looks_defensive",
    "parse_file", "parse_text", "parse_csv", "parse_json", "parse_pdf",
    "parse_docx", "parse_code", "parse_xlsx", "parse_html", "parse_pptx",
    "parse_odt", "parse_odp", "parse_sheet", "parse_doc", "parse_rtf",
    "parse_eml", "parse_zip", "parse_xml", "parse_subtitles", "decode_text",
    "sniff_csv_columns", "sniff_xlsx_columns", "sniff_sheet_columns",
    "SHEET_EXT", "MissingDependency", "DocumentError", "parser_status",
    "report_to_csv",
    "MAX_ITEMS", "MAX_ITEM_CHARS",
]
