"""Text extraction from document formats, with provenance.

Every Office format in common use — Word, PowerPoint and Excel since 2007, and
the OpenDocument formats LibreOffice writes — is a ZIP archive of XML. Reading
them needs nothing beyond Python's standard library, so that is what this
module uses.

That choice is deliberate. An earlier version read Word files through the
``python-docx`` package. It was never added to ``requirements.txt``, so on a
fresh install every ``.docx`` upload failed — and the failure surfaced as "415
Unsupported Media Type", which reads as "wrong kind of file" rather than
"missing library". Parsing the XML directly removes that whole class of
failure: there is no package to be missing.

Two formats genuinely need a library, and say so plainly when it is absent:

    PDF   pdfplumber — PDF is a page-description language, not markup
    XLS   xlrd       — the pre-2007 binary Excel format

Every extractor returns :class:`Block` records — a piece of text plus a
human-readable locator ("slide 4 · notes", "table 2 · row 3 · cell 1") — and
leaves the conversion to scan items to the scanner, so this module has no
dependency on the rest of the package.

Hidden content is kept on purpose. Text formatted invisible, speaker notes,
document comments and HTML comments are exactly where an indirect prompt
injection is placed: a human reviewer never sees it, and a model reading the
extracted text sees all of it. Where the format marks text as hidden, the block
says so.
"""
from __future__ import annotations

import email
import email.policy
import io
import posixpath
import re
import zipfile
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple
from xml.etree import ElementTree as ET


class Block(NamedTuple):
    """A unit of extracted text and where it came from."""

    locator: str
    text: str
    context: Dict


class MissingDependency(RuntimeError):
    """A format needs a package that is not installed.

    Kept distinct from an unsupported format on purpose: the fix is to install
    something, not to convert the file, and the error has to say which.
    """

    def __init__(self, package: str, fmt: str) -> None:
        self.package = package
        self.fmt = fmt
        super().__init__(
            f"Reading {fmt} files needs the '{package}' package, which is not "
            f"installed on the server. Install it with: "
            f"pip install -r backend/requirements.txt"
        )


class DocumentError(ValueError):
    """The file has a supported extension but cannot be read."""


# A sheet is a title plus rows; each row keeps its real row number, so a
# finding in row 88 says row 88 even when rows 40-87 were blank.
Sheet = Tuple[str, List[Tuple[int, List[str]]]]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _local(tag: str) -> str:
    """``{namespace}name`` -> ``name``."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _open_zip(raw: bytes, fmt: str) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        hint = ""
        if fmt in ("Word", "Excel", "PowerPoint"):
            hint = (f" If it was saved by an old version of Office, it may really be "
                    f"the pre-2007 format with a new extension — open it and use "
                    f"Save As to write a genuine modern {fmt} file.")
        raise DocumentError(f"This {fmt} file could not be opened — it looks "
                            f"damaged or is not really a {fmt} file.{hint}")


def _read_xml(zf: zipfile.ZipFile, name: str) -> Optional[ET.Element]:
    try:
        data = zf.read(name)
    except KeyError:
        return None
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        return None


def _rels(zf: zipfile.ZipFile, part: str) -> Dict[str, Tuple[str, str]]:
    """Relationship id -> (type, resolved target path) for an OOXML part."""
    folder, fname = posixpath.split(part)
    root = _read_xml(zf, posixpath.join(folder, "_rels", fname + ".rels"))
    out: Dict[str, Tuple[str, str]] = {}
    if root is None:
        return out
    for rel in root:
        target = rel.get("Target", "")
        if rel.get("TargetMode") == "External":
            continue
        path = (target.lstrip("/") if target.startswith("/")
                else posixpath.normpath(posixpath.join(folder, target)))
        out[rel.get("Id", "")] = (rel.get("Type", ""), path)
    return out


def _squash(text: str) -> str:
    return re.sub(r"[ \t\u00a0]+", " ", text).strip()


# ---------------------------------------------------------------------------
# Word (.docx, .docm, .dotx)
# ---------------------------------------------------------------------------
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_paragraph(p: ET.Element) -> Tuple[str, bool]:
    """Paragraph text, and whether any of it is formatted to be invisible.

    Two hiding techniques are recognised: the "hidden" character property
    (``w:vanish``) and white text (``w:color`` FFFFFF), the latter being the
    classic way to plant an instruction a human reviewer cannot see.
    """
    parts: List[str] = []
    hidden = False
    for run in p.iter(_W + "r"):
        rpr = run.find(_W + "rPr")
        if rpr is not None:
            if rpr.find(_W + "vanish") is not None:
                hidden = True
            colour = rpr.find(_W + "color")
            if colour is not None and (colour.get(_W + "val") or "").upper() in ("FFFFFF", "FFF"):
                hidden = True
        for node in run:
            tag = _local(node.tag)
            if tag == "t" and node.text:
                parts.append(node.text)
            elif tag == "tab":
                parts.append("\t")
            elif tag in ("br", "cr"):
                parts.append("\n")
    return _squash("".join(parts)), hidden


def _docx_part(root: ET.Element, prefix: str) -> Iterator[Block]:
    """Walk a Word part in reading order: body paragraphs, then tables."""
    body = root.find(_W + "body")
    container = body if body is not None else root
    para_no = 0
    table_no = 0
    for child in container:
        tag = _local(child.tag)
        if tag == "p":
            para_no += 1
            text, hidden = _docx_paragraph(child)
            if text:
                loc = f"{prefix}paragraph {para_no}" + (" (hidden text)" if hidden else "")
                yield Block(loc, text, {"paragraph": para_no, "hidden": hidden})
        elif tag == "tbl":
            table_no += 1
            for r, row in enumerate(child.iter(_W + "tr"), start=1):
                for c, cell in enumerate(row.findall(_W + "tc"), start=1):
                    texts, hidden = [], False
                    for p in cell.iter(_W + "p"):
                        t, h = _docx_paragraph(p)
                        hidden = hidden or h
                        if t:
                            texts.append(t)
                    text = "\n".join(texts)
                    if text:
                        loc = (f"{prefix}table {table_no} · row {r} · cell {c}"
                               + (" (hidden text)" if hidden else ""))
                        yield Block(loc, text, {"table": table_no, "row": r,
                                                "cell": c, "hidden": hidden})


def extract_docx(raw: bytes) -> List[Block]:
    """Body, then headers, footers, footnotes, endnotes and comments.

    The last four are all places a human skims past and an extractor does not.
    """
    zf = _open_zip(raw, "Word")
    main = _read_xml(zf, "word/document.xml")
    if main is None:
        raise DocumentError("This Word file has no document body — it may be "
                            "damaged, or a template with no content.")
    blocks = list(_docx_part(main, ""))

    names = sorted(zf.namelist())
    for kind in ("header", "footer"):
        for n, name in enumerate([x for x in names
                                  if re.fullmatch(rf"word/{kind}\d*\.xml", x)], start=1):
            root = _read_xml(zf, name)
            if root is not None:
                blocks += list(_docx_part(root, f"{kind} {n} · "))

    for part, label in (("footnotes", "footnote"), ("endnotes", "endnote"),
                        ("comments", "comment")):
        root = _read_xml(zf, f"word/{part}.xml")
        if root is None:
            continue
        n = 0
        for item in root:
            texts = [t for t, _ in (_docx_paragraph(p) for p in item.iter(_W + "p")) if t]
            if texts:
                n += 1
                blocks.append(Block(f"{label} {n}", "\n".join(texts), {label: n}))
    return blocks


# ---------------------------------------------------------------------------
# PowerPoint (.pptx, .pptm, .potx)
# ---------------------------------------------------------------------------
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


def _drawing_paragraphs(root: ET.Element) -> List[str]:
    out = []
    for p in root.iter(_A + "p"):
        text = _squash("".join(t.text or "" for t in p.iter(_A + "t")))
        if text:
            out.append(text)
    return out


def extract_pptx(raw: bytes) -> List[Block]:
    """Slide text in presentation order, then each slide's speaker notes.

    Order comes from ``presentation.xml``, not the file names — slides that
    have been reordered keep their original ``slideN.xml`` names.
    """
    zf = _open_zip(raw, "PowerPoint")
    pres = _read_xml(zf, "ppt/presentation.xml")
    slide_paths: List[str] = []
    if pres is not None:
        rels = _rels(zf, "ppt/presentation.xml")
        for sid in pres.iter():
            if _local(sid.tag) == "sldId":
                rid = sid.get(_REL_NS + "id")
                if rid in rels:
                    slide_paths.append(rels[rid][1])
    if not slide_paths:
        slide_paths = sorted(
            (n for n in zf.namelist() if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)),
            key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)))

    blocks: List[Block] = []
    for s, path in enumerate(slide_paths, start=1):
        root = _read_xml(zf, path)
        if root is None:
            continue
        for p, text in enumerate(_drawing_paragraphs(root), start=1):
            blocks.append(Block(f"slide {s} · paragraph {p}", text,
                                {"slide": s, "paragraph": p}))
        for rtype, target in _rels(zf, path).values():
            if rtype.endswith("/notesSlide"):
                notes = _read_xml(zf, target)
                if notes is not None:
                    # Notes slides repeat the slide number as a placeholder;
                    # a bare digit is not something anyone wrote.
                    text = "\n".join(t for t in _drawing_paragraphs(notes)
                                     if not t.strip().isdigit())
                    if text:
                        blocks.append(Block(f"slide {s} · speaker notes", text,
                                            {"slide": s, "notes": True}))
    return blocks


# ---------------------------------------------------------------------------
# Excel (.xlsx, .xlsm, .xltx)
# ---------------------------------------------------------------------------
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _col_index(ref: str) -> int:
    """``"C12"`` -> 2 (zero-based column)."""
    n = 0
    for ch in ref:
        if ch.isalpha():
            n = n * 26 + (ord(ch.upper()) - 64)
        else:
            break
    return max(0, n - 1)


def extract_xlsx(raw: bytes) -> List[Sheet]:
    """Every worksheet as ``(title, [(row_number, cells), ...])``.

    Strings live in a shared table and cells hold an index into it, so the
    table is read first. A formula's cached result is used rather than its
    source — ``=A1&B1`` is not something anyone typed.
    """
    zf = _open_zip(raw, "Excel")
    shared: List[str] = []
    sst = _read_xml(zf, "xl/sharedStrings.xml")
    if sst is not None:
        for si in sst.findall(_S + "si"):
            # A string is either one <t>, or rich-text runs <r><t>. Phonetic
            # guides (<rPh>) are siblings of those and are reading aids, not
            # cell content, so only direct <t> and run <t> are taken.
            parts: List[str] = []
            direct = si.find(_S + "t")
            if direct is not None and direct.text:
                parts.append(direct.text)
            for run in si.findall(_S + "r"):
                rt = run.find(_S + "t")
                if rt is not None and rt.text:
                    parts.append(rt.text)
            shared.append("".join(parts))

    book = _read_xml(zf, "xl/workbook.xml")
    if book is None:
        raise DocumentError("This Excel file has no workbook — it may be damaged.")
    rels = _rels(zf, "xl/workbook.xml")
    sheets: List[Sheet] = []
    for sh in book.iter(_S + "sheet"):
        rid = sh.get(_REL_NS + "id")
        if rid not in rels:
            continue
        root = _read_xml(zf, rels[rid][1])
        if root is None:
            continue
        rows: List[Tuple[int, List[str]]] = []
        for row in root.iter(_S + "row"):
            cells: Dict[int, str] = {}
            for c in row.findall(_S + "c"):
                idx = _col_index(c.get("r", "A"))
                kind = c.get("t")
                v = c.find(_S + "v")
                if kind == "s" and v is not None and v.text is not None:
                    try:
                        val = shared[int(v.text)]
                    except (ValueError, IndexError):
                        val = ""
                elif kind == "inlineStr":
                    val = "".join(t.text or "" for t in c.iter(_S + "t"))
                else:
                    val = v.text if v is not None and v.text is not None else ""
                if val.strip():
                    cells[idx] = val
            if cells:
                width = max(cells) + 1
                rows.append((int(row.get("r", len(rows) + 1)),
                             [cells.get(i, "") for i in range(width)]))
        if rows:
            sheets.append((sh.get("name", f"Sheet{len(sheets) + 1}"), rows))
    return sheets


# ---------------------------------------------------------------------------
# Legacy Excel (.xls) — the one Office format that needs a library
# ---------------------------------------------------------------------------
def extract_xls(raw: bytes) -> List[Sheet]:
    try:
        import xlrd
    except ImportError:
        raise MissingDependency("xlrd", "legacy Excel (.xls)")
    try:
        book = xlrd.open_workbook(file_contents=raw)
    except Exception as exc:
        raise DocumentError(f"This .xls file could not be read: {exc}")
    sheets: List[Sheet] = []
    for sh in book.sheets():
        rows = []
        for r in range(sh.nrows):
            cells = ["" if v is None else str(v) for v in sh.row_values(r)]
            if any(c.strip() for c in cells):
                rows.append((r + 1, cells))
        if rows:
            sheets.append((sh.name, rows))
    return sheets


# ---------------------------------------------------------------------------
# OpenDocument (.odt, .odp, .ods) — LibreOffice / Google Docs export
# ---------------------------------------------------------------------------
_TEXT = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
_TABLE = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"
_DRAW = "{urn:oasis:names:tc:opendocument:xmlns:drawing:1.0}"


def _odf_text(el: ET.Element) -> str:
    parts: List[str] = []

    def walk(node: ET.Element) -> None:
        if node.text:
            parts.append(node.text)
        for child in node:
            tag = _local(child.tag)
            if tag == "s":
                parts.append(" " * int(child.get(_TEXT + "c", "1") or 1))
            elif tag == "tab":
                parts.append("\t")
            elif tag == "line-break":
                parts.append("\n")
            elif tag not in ("annotation",):
                walk(child)
            if child.tail:
                parts.append(child.tail)

    walk(el)
    return _squash("".join(parts))


def _odf_content(raw: bytes, fmt: str) -> ET.Element:
    zf = _open_zip(raw, fmt)
    root = _read_xml(zf, "content.xml")
    if root is None:
        raise DocumentError(f"This {fmt} file has no content — it may be damaged.")
    return root


def extract_odt(raw: bytes) -> List[Block]:
    root = _odf_content(raw, "OpenDocument text")
    # A comment's text sits in ordinary <text:p> elements inside the
    # annotation, so without this a comment would be reported twice: once as
    # a comment and once as a paragraph.
    annotations = [el for el in root.iter() if _local(el.tag) == "annotation"]
    inside = {id(p) for a in annotations for p in a.iter(_TEXT + "p")}
    blocks: List[Block] = []
    n = 0
    for el in root.iter():
        if el.tag in (_TEXT + "p", _TEXT + "h") and id(el) not in inside:
            text = _odf_text(el)
            if text:
                n += 1
                blocks.append(Block(f"paragraph {n}", text, {"paragraph": n}))
    for c, a in enumerate(annotations, start=1):
        text = "\n".join(t for t in (_odf_text(p) for p in a.iter(_TEXT + "p")) if t)
        if text:
            blocks.append(Block(f"comment {c}", text, {"comment": c}))
    return blocks


# Field placeholders LibreOffice writes into slide and notes masters.
_ODF_PLACEHOLDER = re.compile(r"^<(?:number|date/time|footer|header|slide-name|page-name)>$")


def extract_odp(raw: bytes) -> List[Block]:
    root = _odf_content(raw, "OpenDocument presentation")
    blocks: List[Block] = []
    for s, page in enumerate(root.iter(_DRAW + "page"), start=1):
        notes = [el for el in page if _local(el.tag) == "notes"]
        in_notes = {id(p) for n in notes for p in n.iter(_TEXT + "p")}
        p = 0
        for el in page.iter(_TEXT + "p"):
            if id(el) in in_notes:
                continue
            text = _odf_text(el)
            if text and not _ODF_PLACEHOLDER.match(text):
                p += 1
                blocks.append(Block(f"slide {s} · paragraph {p}", text,
                                    {"slide": s, "paragraph": p}))
        note_text = "\n".join(
            t for t in (_odf_text(el) for n in notes for el in n.iter(_TEXT + "p"))
            if t and not _ODF_PLACEHOLDER.match(t) and not t.isdigit())
        if note_text:
            blocks.append(Block(f"slide {s} · speaker notes", note_text,
                                {"slide": s, "notes": True}))
    return blocks


def extract_ods(raw: bytes) -> List[Sheet]:
    """Spreadsheets, expanding ODF's run-length encoding carefully.

    ODF compresses repeated rows and cells; an empty sheet routinely declares
    a million repeated blank rows. Only rows with content are expanded, and
    column repeats are capped, so a small sheet stays small.
    """
    root = _odf_content(raw, "OpenDocument spreadsheet")
    sheets: List[Sheet] = []
    for table in root.iter(_TABLE + "table"):
        rows: List[Tuple[int, List[str]]] = []
        rownum = 0
        for row in table.iter(_TABLE + "table-row"):
            cells: List[str] = []
            for cell in row:
                if _local(cell.tag) not in ("table-cell", "covered-table-cell"):
                    continue
                text = "\n".join(_odf_text(p) for p in cell.iter(_TEXT + "p")).strip()
                rep = min(int(cell.get(_TABLE + "number-columns-repeated", "1") or 1), 256)
                cells.extend([text] * (rep if text else min(rep, 256)))
            while cells and not cells[-1]:
                cells.pop()
            rrep = int(row.get(_TABLE + "number-rows-repeated", "1") or 1)
            if cells:
                for _ in range(min(rrep, 100)):
                    rownum += 1
                    rows.append((rownum, list(cells)))
            else:
                rownum += min(rrep, 1_000_000)
        if rows:
            sheets.append((table.get(_TABLE + "name", f"Sheet{len(sheets) + 1}"), rows))
    return sheets


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def pdf_paragraphs(text: str) -> List[str]:
    """Rejoin a PDF page's visual lines into paragraphs.

    A PDF stores lines, not paragraphs: a sentence that wraps is two lines.
    Splitting on every line break would cut an instruction in half — and a
    half-sentence can slip past a detector the whole one would trip — so
    lines are joined until one ends a sentence, or is short enough to be a
    heading.
    """
    lines = [ln.strip() for ln in text.splitlines()]
    widest = max((len(ln) for ln in lines), default=0)
    paras: List[str] = []
    buf: List[str] = []
    for ln in lines:
        if not ln:
            if buf:
                paras.append(" ".join(buf)); buf = []
            continue
        buf.append(ln)
        ends_sentence = ln[-1] in ".!?:;\u201d\""
        is_heading = len(ln) < 0.6 * widest and not ln[-1] in ",-"
        if ends_sentence or is_heading:
            paras.append(" ".join(buf)); buf = []
    if buf:
        paras.append(" ".join(buf))
    return [p for p in paras if p]


def extract_pdf(raw: bytes) -> List[Tuple[int, str]]:
    """``[(page_number, text), ...]`` for pages that have a text layer."""
    try:
        import pdfplumber
    except ImportError:
        raise MissingDependency("pdfplumber", "PDF")
    pages: List[Tuple[int, str]] = []
    try:
        with pdfplumber.open(io.BytesIO(raw)) as pdf:
            for p, page in enumerate(pdf.pages, start=1):
                text = (page.extract_text() or "").strip()
                if text:
                    pages.append((p, text))
    except Exception as exc:
        msg = str(exc).lower()
        if "password" in msg or "encrypt" in msg or type(exc).__name__.startswith("PDFPassword"):
            raise DocumentError("This PDF is password-protected. Remove the password "
                                "(or print it to a new PDF) and upload it again.")
        raise DocumentError(f"This PDF could not be read — it may be damaged. ({exc})")
    return pages


# ---------------------------------------------------------------------------
# Rich Text Format (.rtf)
# ---------------------------------------------------------------------------
# Destinations whose content is formatting, metadata or embedded binary data,
# never text a person wrote. Dropped with everything inside them.
_RTF_SKIP = {
    "fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "objdata",
    "themedata", "colorschememapping", "datastore", "latentstyles", "listtable",
    "listoverridetable", "rsidtbl", "generator", "xmlnstbl", "filetbl",
    "revtbl", "fldinst", "shppict", "nonshppict", "blipuid", "mmathPr",
    "passwordhash", "pgptbl", "private", "userprops", "wgrffmtfilter",
}
_RTF_TOKEN = re.compile(
    r"\\([a-zA-Z]{1,32})(-?\d{1,10})? ?|\\'([0-9a-fA-F]{2})|\\([^a-zA-Z])|([{}])|[\r\n]+|([^\\{}\r\n]+)")


def rtf_to_text(rtf: str) -> str:
    stack: List[Tuple[bool, int]] = []
    ignorable, uc_skip, skip = False, 1, 0
    out: List[str] = []
    for m in _RTF_TOKEN.finditer(rtf):
        word, arg, hexcode, char, brace, text = m.groups()
        if brace == "{":
            stack.append((ignorable, uc_skip))
            continue
        if brace == "}":
            if stack:
                ignorable, uc_skip = stack.pop()
            continue
        if char is not None:
            if char == "*":
                ignorable = True
            elif not ignorable and char in "\\{}":
                out.append(char)
            elif not ignorable and char == "~":
                out.append("\u00a0")
            continue
        if word is not None:
            if word == "annotation":
                # Comments are written as an optional destination ({\*\annotation
                # ...}), which tells a reader it may skip them. A comment is
                # exactly where a hidden instruction goes, so this one is read.
                ignorable = False
                out.append("\n")
                continue
            if word in _RTF_SKIP:
                ignorable = True
            elif ignorable:
                continue
            elif word in ("par", "line", "sect", "page", "row", "cell", "nestcell"):
                # A table cell is its own unit of text; without a break here
                # adjacent cells run together ("RegionNoteSouth").
                out.append("\n")
            elif word == "tab":
                out.append("\t")
            elif word == "uc":
                uc_skip = int(arg or 1)
            elif word == "u" and arg is not None:
                cp = int(arg)
                out.append(chr(cp + 65536 if cp < 0 else cp))
                skip = uc_skip
            continue
        if hexcode is not None:
            if skip:
                skip -= 1
            elif not ignorable:
                out.append(bytes([int(hexcode, 16)]).decode("cp1252", errors="replace"))
            continue
        if text is not None and not ignorable:
            if skip:
                drop = min(skip, len(text))
                text, skip = text[drop:], skip - drop
            out.append(text)
    return "".join(out)


# ---------------------------------------------------------------------------
# Email (.eml)
# ---------------------------------------------------------------------------
class EmailPart(NamedTuple):
    kind: str          # subject | text | html | attachment
    name: str
    content: object    # str, or bytes for an attachment


def extract_eml(raw: bytes) -> List[EmailPart]:
    """Subject, body parts and attachments.

    An email is the textbook indirect-injection carrier: anyone can send one,
    and an assistant that reads a mailbox reads every word of it.
    """
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        raise DocumentError(f"This email could not be read: {exc}")
    parts: List[EmailPart] = []
    subject = str(msg.get("subject") or "").strip()
    if subject:
        parts.append(EmailPart("subject", "subject", subject))
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            parts.append(EmailPart("attachment", filename or "attachment", payload))
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                body = part.get_content()
            except Exception:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            if isinstance(body, bytes):
                body = body.decode("utf-8", "replace")
            if body.strip():
                parts.append(EmailPart("html" if ctype == "text/html" else "text",
                                       ctype, body))
    return parts


# ---------------------------------------------------------------------------
# Legacy Word (.doc) — best effort
# ---------------------------------------------------------------------------
def extract_doc(raw: bytes) -> List[Block]:
    """Recover prose from a pre-2007 binary Word file, without a library.

    The ``.doc`` format stores its text either as UTF-16 or as single-byte
    characters, inside a compound file alongside style tables, font names and
    document properties. This pulls out runs that look like prose — long
    enough, mostly letters, several words — and discards the rest.

    It is honest about being approximate: it can miss text in heavily edited
    ("fast-saved") documents and occasionally keep a line of metadata. For
    detection that is acceptable — an injected instruction is prose, and prose
    is what survives the filter. For a faithful reading, save the file as
    .docx first.
    """
    if not raw.startswith(b"\xd0\xcf\x11\xe0"):
        raise DocumentError("This does not look like a Word .doc file.")
    candidates: List[str] = []
    for run in re.findall(rb"(?:[\x20-\x7e\xa0-\xff][\x00]){20,}", raw):
        candidates.append(run.decode("utf-16le", errors="ignore"))
    for run in re.findall(rb"[\x20-\x7e\x91-\x97\xa0-\xff\r\t]{40,}", raw):
        candidates.append(run.decode("cp1252", errors="ignore"))

    seen, blocks = set(), []
    for cand in candidates:
        for line in re.split(r"[\r\n\x07\x0b\x0c]+", cand):
            line = _squash(line)
            words = line.split()
            letters = sum(ch.isalpha() for ch in line)
            if (len(words) >= 4 and len(line) >= 20
                    and letters / max(1, len(line)) >= 0.6 and line not in seen):
                seen.add(line)
                blocks.append(Block(f"text block {len(blocks) + 1}", line,
                                    {"best_effort": True}))
    return blocks


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------
def extract_xml(text: str) -> List[Block]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise DocumentError(f"This XML file is not well-formed: {exc}")
    blocks: List[Block] = []

    def walk(el: ET.Element, path: str) -> None:
        counts: Dict[str, int] = {}
        for child in el:
            tag = _local(child.tag)
            counts[tag] = counts.get(tag, 0) + 1
            walk(child, f"{path}/{tag}[{counts[tag]}]")
        body = _squash(el.text or "")
        if body:
            blocks.append(Block(path, body, {"path": path}))
        for name, value in el.attrib.items():
            value = _squash(value)
            if len(value.split()) >= 3:            # prose, not an id or a flag
                blocks.append(Block(f"{path}/@{_local(name)}", value,
                                    {"path": path, "attribute": _local(name)}))

    walk(root, "/" + _local(root.tag))
    return blocks


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------
def parser_status() -> Dict[str, Dict[str, object]]:
    """Which library-backed formats will actually work on this machine.

    Surfaced by the API and the upload page, so a missing package is a visible
    warning before anyone uploads a file rather than a baffling error after.
    """
    status: Dict[str, Dict[str, object]] = {}
    for ext, package, label in ((".pdf", "pdfplumber", "PDF"),
                                (".xls", "xlrd", "legacy Excel")):
        try:
            __import__(package)
            ok = True
        except ImportError:
            ok = False
        status[ext] = {"available": ok, "package": package, "label": label}
    return status


__all__ = [
    "Block", "Sheet", "EmailPart", "MissingDependency", "DocumentError",
    "extract_docx", "extract_pptx", "extract_xlsx", "extract_xls",
    "extract_odt", "extract_odp", "extract_ods", "extract_pdf",
    "rtf_to_text", "extract_eml", "extract_doc", "extract_xml", "parser_status",
]
