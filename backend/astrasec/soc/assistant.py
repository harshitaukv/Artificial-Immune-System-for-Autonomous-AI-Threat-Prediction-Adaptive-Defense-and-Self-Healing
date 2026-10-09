"""AstraBot's brain: a language-model client with an honest offline fallback.

The chatbot is the application AstraSec protects, so it has to behave like a
real one. It talks to whichever model the owner has configured:

``ollama``             a local model such as Llama 3.1 (the model named in the
                       project design) served by Ollama;
``openai_compatible``  any /v1/chat/completions server (OpenAI, Groq, Together,
                       LM Studio, vLLM …);
``offline``            a built-in responder, so the platform works with no model
                       at all — on an exam-hall laptop, for instance.

``auto`` (the default) uses Ollama when it is running with the configured
model, then an OpenAI-compatible server when a key is set, else offline.

The offline responder does not pretend to be a language model. It handles the
things a support assistant is asked most — greetings, account help, everyday
study and security questions, arithmetic — and it genuinely works with
uploaded documents: summaries, column statistics and question answering by
retrieval, each answer citing where in the file it came from. Anything else
gets a plain statement of what it can do and how to connect a model.
"""
from __future__ import annotations

import ast
import csv
import io
import json
import math
import operator
import re
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .policy import BotConfig

# --------------------------------------------------------------------------
# Documents attached to a conversation
# --------------------------------------------------------------------------
@dataclass
class DocContext:
    file_id: str
    name: str
    kind: str                                   # pdf | docx | txt | csv | json | md
    chunks: List[Tuple[str, str]]               # (locator, sanitized text)
    table: Optional[Dict[str, Any]] = None      # csv: {columns, rows}
    json_summary: Optional[Dict[str, Any]] = None
    redactions: int = 0
    removed_items: int = 0
    prompt_label: str = ""          # what the model is told the file is called

    @property
    def text(self) -> str:
        return "\n".join(t for _, t in self.chunks)


_WORD = re.compile(r"[A-Za-z][A-Za-z0-9'\-]{1,}")
_STOP = set("""a an the and or but if then else of to in on at for with by from as is are was
were be been being this that these those it its it's i me my we our you your he she they them
their what which who whom whose when where why how do does did can could should would will may
might must shall about into over under again further than too very just so not no nor only own
same such both each few more most other some any all there here also please tell give show me
document file pdf csv json attached uploaded according say says said""".split())


def _terms(text: str) -> List[str]:
    return [w.lower() for w in _WORD.findall(text) if w.lower() not in _STOP]


def _sentences(text: str) -> List[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n{1,}", text)
    return [p.strip() for p in parts if len(p.strip()) > 20]


def build_table(text: str, max_rows: int = 5000) -> Optional[Dict[str, Any]]:
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    rows = []
    for i, r in enumerate(reader):
        rows.append(r)
        if i > max_rows:
            break
    if len(rows) < 2:
        return None
    return {"columns": [c.strip() for c in rows[0]], "rows": rows[1:]}


def summarise_json(text: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict):
        return {"type": "object", "keys": list(data.keys())[:40], "size": len(data)}
    if isinstance(data, list):
        keys: Counter = Counter()
        for item in data[:500]:
            if isinstance(item, dict):
                keys.update(item.keys())
        return {"type": "array", "size": len(data),
                "keys": [k for k, _ in keys.most_common(30)]}
    return {"type": type(data).__name__, "size": 1, "keys": []}


def select_context(docs: List[DocContext], question: str, budget: int = 6000
                   ) -> List[Tuple[DocContext, List[Tuple[str, str]]]]:
    """The chunks most relevant to the question, within a character budget."""
    q = Counter(_terms(question))
    out = []
    per_doc = max(1500, budget // max(1, len(docs)))
    for d in docs:
        scored = []
        for i, (loc, t) in enumerate(d.chunks):
            terms = _terms(t)
            score = sum(q[w] for w in terms) / (1 + math.log1p(len(terms)))
            scored.append((score, -i, loc, t))
        scored.sort(reverse=True)
        chosen, used = [], 0
        # Keep document order for readability once the best chunks are chosen.
        pool = scored if any(s[0] > 0 for s in scored) else sorted(scored, key=lambda s: -s[1])
        for score, neg_i, loc, t in pool:
            if used + len(t) > per_doc:
                continue
            chosen.append((-neg_i, loc, t))
            used += len(t)
            if used >= per_doc:
                break
        chosen.sort()
        out.append((d, [(loc, t) for _, loc, t in chosen]))
    return out


# --------------------------------------------------------------------------
# Model client
# --------------------------------------------------------------------------
class ChatModel:
    def __init__(self) -> None:
        self._resolved: Optional[Tuple[str, str]] = None
        self._resolved_at = 0.0
        self._resolved_for: Optional[str] = None
        self.last_error = ""

    @staticmethod
    def _openai_url(base: str) -> str:
        base = base.rstrip("/")
        return base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")

    def resolve(self, cfg: BotConfig, force: bool = False) -> Tuple[str, str]:
        """(provider, label) actually in use right now."""
        key = f"{cfg.provider}|{cfg.base_url}|{cfg.model}|{bool(cfg.api_key)}"
        now = time.time()
        if (not force and self._resolved and self._resolved_for == key
                and now - self._resolved_at < 30):
            return self._resolved
        provider = "offline"
        if cfg.provider in ("auto", "ollama") and cfg.base_url:
            try:
                r = httpx.get(cfg.base_url.rstrip("/") + "/api/tags", timeout=1.5)
                if r.status_code == 200:
                    names = [m.get("name", "") for m in r.json().get("models", [])]
                    if any(n == cfg.model or n.split(":")[0] == cfg.model.split(":")[0]
                           for n in names):
                        provider = "ollama"
                    else:
                        self.last_error = (f"Ollama is running but model '{cfg.model}' is not "
                                           f"pulled. Run: ollama pull {cfg.model}")
            except Exception as exc:
                if cfg.provider == "ollama":
                    self.last_error = f"Ollama not reachable at {cfg.base_url}: {type(exc).__name__}"
        if provider == "offline" and cfg.provider in ("auto", "openai_compatible") \
                and cfg.api_key and cfg.base_url and "11434" not in cfg.base_url:
            provider = "openai_compatible"
        label = {"ollama": f"{cfg.model} (local, via Ollama)",
                 "openai_compatible": f"{cfg.model} (hosted API)",
                 "offline": "AstraBot assistant"}[provider]
        self._resolved = (provider, label)
        self._resolved_at, self._resolved_for = now, key
        return self._resolved

    def complete(self, cfg: BotConfig, messages: List[Dict[str, str]]) -> str:
        provider, _ = self.resolve(cfg)
        if provider == "ollama":
            r = httpx.post(cfg.base_url.rstrip("/") + "/api/chat", timeout=120, json={
                "model": cfg.model, "stream": False, "messages": messages,
                "options": {"temperature": cfg.temperature, "num_predict": cfg.max_tokens}})
            r.raise_for_status()
            return (r.json().get("message") or {}).get("content", "").strip()
        if provider == "openai_compatible":
            r = httpx.post(self._openai_url(cfg.base_url), timeout=120,
                           headers={"Authorization": f"Bearer {cfg.api_key}"},
                           json={"model": cfg.model, "messages": messages,
                                 "temperature": cfg.temperature, "max_tokens": cfg.max_tokens})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
        raise RuntimeError("offline")


# --------------------------------------------------------------------------
# Offline responder
# --------------------------------------------------------------------------
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
        ast.USub: operator.neg, ast.UAdd: operator.pos, ast.FloorDiv: operator.floordiv}


def safe_eval(expr: str) -> Optional[float]:
    """Arithmetic only — parsed, never executed."""
    try:
        node = ast.parse(expr, mode="eval").body
    except SyntaxError:
        return None

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in _OPS:
            left, right = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.Pow) and abs(right) > 100:
                raise ValueError("exponent too large")
            return _OPS[type(n.op)](left, right)
        if isinstance(n, ast.UnaryOp) and type(n.op) in _OPS:
            return _OPS[type(n.op)](ev(n.operand))
        raise ValueError("not arithmetic")

    try:
        v = ev(node)
        return v if math.isfinite(v) else None
    except Exception:
        return None


def _fmt(v: float) -> str:
    return f"{v:,.4f}".rstrip("0").rstrip(".") if isinstance(v, float) else f"{v:,}"


KNOWLEDGE: List[Tuple[Tuple[str, ...], str]] = [
    (("learn", "python"),
     "A good path for learning Python:\n\n1. **Basics** — variables, types, `if`/`for`/`while`, functions. "
     "The official tutorial at docs.python.org is excellent.\n2. **Practice daily** — small problems on "
     "HackerRank or LeetCode (easy level).\n3. **Data structures** — lists, dicts, sets, tuples and when to "
     "use each.\n4. **Build something** — a to-do app, a file organiser, a small Flask/FastAPI API.\n"
     "5. **Libraries** — `requests`, `pandas`, `matplotlib`, depending on your interest.\n\n"
     "Aim for 30–60 minutes a day; consistency beats long weekend sessions."),
    (("prompt", "injection"),
     "**Prompt injection** is when text sent to an AI model tries to override the instructions the "
     "application gave it — for example \"ignore all previous instructions and…\". It can arrive directly "
     "from a user or *indirectly* inside a document, web page or email the model reads.\n\nDefences: keep "
     "system instructions separate from user text, treat documents as data, filter the model's output, "
     "give the model the least privilege it needs, and inspect inputs before they reach the model — which "
     "is what AstraSec does for this chat."),
    (("phishing",),
     "**Phishing** is a message that impersonates someone trusted to make you click a link, open an "
     "attachment or hand over credentials. Warning signs: urgency, a sender address that doesn't quite "
     "match, links whose real destination (hover to see it) differs from the text, and requests for "
     "passwords or OTPs — no genuine service asks for those."),
    (("strong", "password"),
     "Strong passwords: use a **passphrase** of 4+ random words (e.g. `river-cactus-lamp-orbit`), make it "
     "unique for every site, store them in a password manager, and turn on two-factor authentication "
     "wherever it's offered."),
    (("sql", "injection"),
     "**SQL injection** happens when user input is pasted into a SQL string, so the input can change the "
     "query. Prevent it with **parameterised queries** (e.g. `cursor.execute(\"SELECT * FROM users WHERE "
     "email = ?\", (email,))`), an ORM, least-privilege database accounts and input validation."),
    (("two-factor",), "**Two-factor authentication** adds a second proof — a code from an app or a "
     "security key — on top of your password, so a stolen password alone can't open the account."),
    (("2fa",), "**Two-factor authentication (2FA)** adds a second proof — a code from an app or a security "
     "key — on top of your password, so a stolen password alone can't open the account."),
    (("https",), "**HTTPS** encrypts traffic between your browser and a website using TLS, and the site's "
     "certificate proves you are talking to the real server, so nobody in between can read or alter it."),
    (("machine", "learning"), "**Machine learning** is building programs that learn patterns from examples "
     "instead of following hand-written rules. You give a model labelled data (e.g. emails marked spam or "
     "not), it adjusts its parameters to reduce mistakes, and then predicts on new data."),
    (("neural", "network"), "A **neural network** is layers of simple units; each computes a weighted sum "
     "of its inputs and applies a non-linear function. Training adjusts the weights with gradient descent "
     "so the network's predictions get closer to the correct answers."),
    (("what", "api"), "An **API** (Application Programming Interface) is a defined way for programs to talk "
     "to each other — for example, a weather service exposes an HTTP endpoint that returns the forecast "
     "as JSON, so your app can use it without knowing how it's computed."),
    (("recursion",), "**Recursion** is a function calling itself on a smaller version of the problem, with a "
     "base case to stop. Example:\n\n```python\ndef factorial(n):\n    return 1 if n <= 1 else n * "
     "factorial(n - 1)\n```"),
    (("oop",), "The four pillars of **OOP**: *encapsulation* (bundle data with the methods that use it), "
     "*abstraction* (expose what, hide how), *inheritance* (reuse a parent class) and *polymorphism* "
     "(one interface, many implementations)."),
    (("big", "notation"), "**Big O** describes how running time grows with input size: O(1) constant, "
     "O(log n) binary search, O(n) a single loop, O(n log n) merge sort, O(n²) nested loops."),
    (("cloud", "computing"), "**Cloud computing** means renting computing resources — servers, storage, "
     "databases — over the internet on demand (AWS, Azure, GCP) instead of owning the hardware."),
    (("tcp", "udp"), "**TCP** is connection-based and reliable (ordered delivery, retransmission) — used for "
     "web pages and email. **UDP** is connectionless and faster with no delivery guarantee — used for "
     "video calls, games and DNS."),
    (("ram", "rom"), "**RAM** is fast, temporary working memory that is cleared when power is off. **ROM** "
     "is non-volatile memory holding firmware that rarely changes."),
    (("git", "branch"), "Git branches: `git branch feature-x` creates one, `git switch feature-x` moves to "
     "it, commit your work, then `git switch main` and `git merge feature-x` to bring it back."),
    (("interview",), "Interview tips: research the company, prepare 3–4 stories using the STAR method "
     "(Situation, Task, Action, Result), revise your projects in depth, practise explaining your code "
     "aloud, and prepare two questions to ask them."),
    (("study", "plan"), "A simple study plan: split the syllabus into weekly topics, study each topic in "
     "focused 45-minute blocks, solve problems the same day, revise on day 3 and day 7, and keep the last "
     "week for mock tests."),
    (("cover", "letter"), "A cover letter in four short paragraphs: who you are and the role; one or two "
     "achievements that match the job; why this company; a polite close asking for an interview."),
    (("photosynthesis",), "**Photosynthesis**: plants use sunlight, water and carbon dioxide to make glucose "
     "and release oxygen — 6CO₂ + 6H₂O + light → C₆H₁₂O₆ + 6O₂."),
    (("water", "cycle"), "The **water cycle**: evaporation from oceans and lakes, condensation into clouds, "
     "precipitation as rain or snow, and collection back into water bodies and groundwater."),
    (("cybersecurity",), "**Cybersecurity** is protecting systems, networks and data from attack — through "
     "secure design, access control, patching, monitoring and incident response."),
    (("system", "prompt"), "A **system prompt** is the set of instructions an application gives a language "
     "model before the user's message — its role, tone and rules. Keeping it separate from user input, and "
     "never relying on it to hold secrets, is basic LLM security."),
]

ACCOUNT_HELP: List[Tuple[Tuple[str, ...], str]] = [
    (("reset", "password"),
     "To reset your password:\n\n1. Open the sign-in page and choose **Forgot password**.\n2. Enter the "
     "email address on your account.\n3. Open the reset link in the email (it expires after 30 minutes) "
     "and choose a new password.\n\nIf the email doesn't arrive within a few minutes, check your spam "
     "folder, then contact support@astrabot.local."),
    (("forgot", "password"), "No problem — use **Forgot password** on the sign-in page and follow the link "
     "we email you. If nothing arrives, check spam or contact support@astrabot.local."),
    (("reset", "email"), "If the reset email hasn't arrived: wait 5 minutes, check spam/promotions, make "
     "sure you used the address registered on the account, then request a new link. Still nothing? "
     "Contact support@astrabot.local."),
    (("account", "locked"), "Accounts lock after several failed sign-in attempts. Wait 15 minutes and try "
     "again, or reset your password to unlock it immediately."),
    (("delete", "account"), "You can delete your account from **Settings → Account → Delete account**. "
     "This is permanent, so download anything you want to keep first."),
    (("change", "email"), "Change your email under **Settings → Profile**. We send a confirmation link to "
     "the new address before the change takes effect."),
    (("log", "in"), "If you can't log in: check caps lock, try **Forgot password**, clear the app's cache, "
     "and make sure the app is updated."),
]


class OfflineResponder:
    def reply(self, question: str, docs: List[DocContext], bot_name: str = "AstraBot") -> str:
        q = question.strip()
        low = q.lower()
        words = set(re.findall(r"[a-z0-9\-]+", low))

        # ---- documents first: if the user attached something, that is context
        if docs and (re.search(r"\b(summar|document|file|pdf|csv|json|attach|upload|report|"
                               r"according|this|it say|column|row|record|key|field|total|average)",
                               low) or len(words) > 3):
            ans = self._doc_answer(q, docs)
            if ans:
                return ans

        if re.fullmatch(r"(hi|hello|hey|hiya|good (morning|afternoon|evening))[!. ]*(there)?[!. ]*", low):
            return f"Hello! I'm {bot_name}. What can I help you with today?"
        if re.search(r"\b(thanks|thank you|thx|cheers)\b", low):
            return "You're welcome! Anything else I can help with?"
        if re.fullmatch(r"(bye|goodbye|see you.*|cya)[!. ]*", low):
            return "Goodbye! Come back any time."
        if re.search(r"\b(who are you|what are you|your name|are you a bot)\b", low):
            return (f"I'm {bot_name}, an AI assistant. Every message and file you send me is checked "
                    f"by AstraSec, the security framework that protects this chat.")
        if re.search(r"\b(what can you do|help me|how can you help|capabilities)\b", low) and len(words) < 8:
            return self._capabilities(bot_name)
        if re.search(r"\bhow are you\b", low):
            return "I'm doing well, thanks for asking! What would you like to work on?"
        if re.search(r"\bjoke\b", low):
            return ("Why do programmers prefer dark mode? Because light attracts bugs. 🐛"
                    .replace(" 🐛", ""))

        for keys, answer in ACCOUNT_HELP:
            if all(k in low for k in keys):
                return answer

        m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*%\s*of\s*(\d[\d,]*(?:\.\d+)?)", low)
        if m:
            a, b = (float(g.replace(",", "")) for g in m.groups())
            v = a * b / 100
            return f"{m.group(1)}% of {m.group(2)} is **{_fmt(round(v, 6))}**."
        m = re.search(r"(\d+(?:\.\d+)?)\s*(miles?|km|kilomet(?:er|re)s?|kg|pounds?|lbs?|"
                      r"celsius|fahrenheit|°?c|°?f)\s+(?:to|in)\s+(\w+)", low)
        if m:
            conv = self._convert(float(m.group(1)), m.group(2), m.group(3))
            if conv:
                return conv
        expr = re.sub(r"(what is|what's|calculate|compute|=|\?)", "", low).strip()
        expr = re.sub(r"(?<=\d),(?=\d{3})", "", expr)
        expr = expr.replace("x", "*").replace("×", "*").replace("÷", "/").replace("^", "**")
        if re.fullmatch(r"[\d\s.+\-*/()%]+", expr or "x") and re.search(r"\d\s*[-+*/%]", expr):
            v = safe_eval(expr)
            if v is not None:
                return f"**{_fmt(v)}**"
        if re.search(r"\b(time|date|day)\b", low) and re.search(r"\b(what|today|now|current)\b", low):
            return time.strftime("It's %A, %d %B %Y, %H:%M (server time).")

        best, best_score = None, 0
        for keys, answer in KNOWLEDGE:
            score = sum(1 for k in keys if k in low)
            if score == len(keys) and score > best_score:
                best, best_score = answer, score
        if best:
            return best

        return ("I don't have a confident answer to that one yet. I'm best at studying and "
                "programming basics, account and password help, security topics, quick calculations, "
                "and anything in a file you attach — I can summarise it, search it or work out "
                "column statistics. Could you rephrase, or try one of those?")

    @staticmethod
    def _capabilities(bot_name: str) -> str:
        return (f"I can:\n\n- answer everyday questions about studying, programming and security\n"
                f"- help with account problems such as password resets\n"
                f"- read a file you attach (PDF, Word, TXT, CSV or JSON), summarise it and answer "
                f"questions about it\n- do quick calculations\n\nEverything you send is checked by "
                f"AstraSec first, so unsafe requests and files are stopped before they reach me.")

    @staticmethod
    def _convert(v: float, unit: str, to: str) -> Optional[str]:
        unit, to = unit.lower().strip("°"), to.lower().strip("°")
        if unit.startswith("mile") and to.startswith("k"):
            return f"{_fmt(v)} miles = **{_fmt(round(v * 1.609344, 3))} km**"
        if unit.startswith("k") and unit != "kg" and to.startswith("mile"):
            return f"{_fmt(v)} km = **{_fmt(round(v / 1.609344, 3))} miles**"
        if unit == "kg" and to.startswith(("pound", "lb")):
            return f"{_fmt(v)} kg = **{_fmt(round(v * 2.20462, 3))} lb**"
        if unit.startswith(("pound", "lb")) and to.startswith("k"):
            return f"{_fmt(v)} lb = **{_fmt(round(v / 2.20462, 3))} kg**"
        if unit in ("c", "celsius") and to.startswith("f"):
            return f"{_fmt(v)} °C = **{_fmt(round(v * 9 / 5 + 32, 2))} °F**"
        if unit in ("f", "fahrenheit") and to.startswith("c"):
            return f"{_fmt(v)} °F = **{_fmt(round((v - 32) * 5 / 9, 2))} °C**"
        return None

    # ---- documents -----------------------------------------------------
    def _doc_answer(self, q: str, docs: List[DocContext]) -> Optional[str]:
        low = q.lower()
        named = [d for d in docs if re.sub(r"\.[a-z0-9]+$", "", d.name.lower()) in low
                 or d.name.lower() in low]
        if re.search(r"\b(summar|overview|what is (this|it) about|tl;?dr|gist)", low):
            return "\n\n".join(self._summary(d) for d in (named or docs))
        # Which file is the question about? One named in it, else the most
        # recent one that can answer this kind of question.
        tabular = bool(re.search(r"\b(column|row|record|how many|average|mean|total|sum|max|min)", low))
        if named:
            doc = named[-1]
        elif tabular and any(d.table for d in docs):
            doc = [d for d in docs if d.table][-1]
        else:
            doc = docs[-1]
        if doc.table and tabular:
            ans = self._table_answer(low, doc)
            if ans:
                return ans
        if doc.json_summary and re.search(r"\b(key|field|structure|how many)", low):
            js = doc.json_summary
            return (f"**{doc.name}** is a JSON {js['type']} with {js['size']:,} "
                    f"{'entries' if js['type'] == 'array' else 'keys'}. Keys: "
                    f"{', '.join('`' + k + '`' for k in js['keys'][:20]) or '—'}.")
        # Retrieval: best-matching sentences across the attached documents.
        q_terms = Counter(_terms(q))
        if not q_terms:
            return None
        n_docs, df = 0, Counter()
        cands = []
        for d in docs:
            for loc, text in d.chunks:
                for s in _sentences(text) or ([text] if len(text) > 20 else []):
                    ts = set(_terms(s))
                    df.update(ts)
                    n_docs += 1
                    cands.append((d, loc, s, ts))
        scored = []
        for d, loc, s, ts in cands:
            score = sum(q_terms[w] * math.log(1 + n_docs / (1 + df[w])) for w in ts if w in q_terms)
            if score > 0:
                scored.append((score, d, loc, s))
        if not scored:
            return (f"I couldn't find anything about that in "
                    f"{', '.join('**' + d.name + '**' for d in docs)}. Try asking for a summary, "
                    f"or use words that appear in the file.")
        scored.sort(key=lambda x: -x[0])
        top = scored[:3]
        lines = [f"From **{d.name}**:"] if len({id(t[1]) for t in top}) == 1 else ["From your files:"]
        for _, d, loc, s in top:
            where = f"{d.name}, {loc}" if len(docs) > 1 else loc
            lines.append(f"- {s.strip()} _({where})_")
        return "\n".join(lines)

    def _summary(self, d: DocContext) -> str:
        if d.table:
            cols, rows = d.table["columns"], d.table["rows"]
            head = (f"**{d.name}** is a table with **{len(rows):,} rows** and **{len(cols)} columns**: "
                    f"{', '.join('`' + c + '`' for c in cols[:15])}.")
            stats = self._numeric_stats(d)
            if stats:
                head += "\n\n" + "\n".join(
                    f"- `{c}`: min {_fmt(s['min'])}, max {_fmt(s['max'])}, average {_fmt(round(s['mean'], 2))}"
                    for c, s in list(stats.items())[:6])
            return head
        if d.json_summary:
            js = d.json_summary
            return (f"**{d.name}** is a JSON {js['type']} with {js['size']:,} "
                    f"{'entries' if js['type'] == 'array' else 'keys'}; keys include "
                    f"{', '.join('`' + k + '`' for k in js['keys'][:15]) or '—'}.")
        sents = _sentences(d.text)
        if not sents:
            return f"**{d.name}** has very little readable text."
        freq = Counter(w for s in sents for w in _terms(s))
        scored = sorted(((sum(freq[w] for w in set(_terms(s))) / (1 + len(_terms(s)) ** 0.5), i, s)
                         for i, s in enumerate(sents)), reverse=True)[:5]
        bullets = [s for _, _, s in sorted(scored, key=lambda x: x[1])]
        words = len(d.text.split())
        return (f"**{d.name}** — about {words:,} words. The main points:\n\n"
                + "\n".join(f"- {b[:300]}" for b in bullets))

    @staticmethod
    def _numeric_stats(d: DocContext) -> Dict[str, Dict[str, float]]:
        cols, rows = d.table["columns"], d.table["rows"]
        out = {}
        for j, c in enumerate(cols):
            vals = []
            for r in rows:
                if j < len(r):
                    try:
                        vals.append(float(r[j].replace(",", "")))
                    except ValueError:
                        pass
            if len(vals) >= max(2, int(0.6 * len(rows))):
                out[c] = {"min": min(vals), "max": max(vals), "mean": statistics.fmean(vals),
                          "sum": sum(vals), "n": len(vals)}
        return out

    def _table_answer(self, low: str, d: DocContext) -> Optional[str]:
        cols, rows = d.table["columns"], d.table["rows"]
        if re.search(r"how many (rows|records|entries)", low):
            return f"**{d.name}** has **{len(rows):,} rows**."
        if re.search(r"(which|what) columns|how many columns|column names", low):
            return f"**{d.name}** has {len(cols)} columns: {', '.join('`' + c + '`' for c in cols)}."
        stats = self._numeric_stats(d)
        for c, s in stats.items():
            if c.lower() in low:
                if re.search(r"\b(average|mean)\b", low):
                    return f"The average `{c}` is **{_fmt(round(s['mean'], 4))}** across {s['n']:,} rows."
                if re.search(r"\b(total|sum)\b", low):
                    return f"The total of `{c}` is **{_fmt(round(s['sum'], 4))}**."
                if re.search(r"\b(max|highest|largest)\b", low):
                    return f"The largest `{c}` is **{_fmt(s['max'])}**."
                if re.search(r"\b(min|lowest|smallest)\b", low):
                    return f"The smallest `{c}` is **{_fmt(s['min'])}**."
        return None


__all__ = ["ChatModel", "OfflineResponder", "DocContext", "select_context", "build_table",
           "summarise_json", "safe_eval"]
