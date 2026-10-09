"""Behavioural + lexical feature extraction.

Two families of features are produced:

``PROMPT_FEATURES``   static, computable from a single prompt in isolation.
``SESSION_FEATURES``  temporal, computable only in the context of a tenant's
                      request history (rate, burstiness, drift).

Module 1 (Behavior Learning) consumes both; Module 2 (Health) consumes the
static family plus the Module-1 anomaly score; Module 3 (Threat Prediction)
concatenates the static family onto its TF-IDF sparse matrix.

Keeping the vector definition in one ordered tuple guarantees that training
and inference always agree on column order — a classic source of silent
model-serving bugs.
"""
from __future__ import annotations

import base64
import codecs
import math
import re
import unicodedata
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence

import numpy as np

# --------------------------------------------------------------------------
# Keyword banks (used as *density features*, never as a standalone verdict)
# --------------------------------------------------------------------------
OVERRIDE_TERMS = {
    "ignore", "disregard", "forget", "override", "bypass", "discard",
    "supersede", "nullify", "overrule", "skip", "circumvent", "cancel",
}
PRIOR_TERMS = {
    "previous", "prior", "earlier", "above", "preceding", "initial",
    "original", "former", "first",
}
INSTRUCTION_TERMS = {
    "instruction", "instructions", "prompt", "directive", "rule", "rules",
    "guideline", "guidelines", "policy", "policies", "restriction",
    "restrictions", "constraint", "configuration", "system",
}
PERSONA_TERMS = {
    "pretend", "roleplay", "role-play", "act as", "you are now", "simulate",
    "persona", "character", "imagine you", "behave as", "impersonate",
    "stay in character", "dan", "developer mode", "jailbreak", "jailbroken",
    "unrestricted", "unfiltered", "uncensored", "no restrictions",
    "without any filter", "opposite day", "hypothetically",
}
SECRET_TERMS = {
    "api key", "apikey", "api_key", "secret", "password", "credential",
    "credentials", "token", "private key", "access key", "system prompt",
    "hidden prompt", "initial instructions", ".env", "environment variable",
    "database", "connection string", "ssh key", "service account",
}
PII_TERMS = {
    "email address", "phone number", "ssn", "social security", "credit card",
    "aadhaar", "passport", "medical record", "salary", "date of birth",
    "customer data", "user database", "personal information", "pii",
}
EXTRACTION_TERMS = {
    "model weights", "weights", "architecture", "parameters", "checkpoint",
    "training data", "tokenizer", "logits", "distil", "distill",
    "fine-tuning dataset", "hyperparameters", "embedding matrix", "replicate",
    "clone", "reconstruct", "reverse engineer",
}
AUTHORITY_TERMS = {
    "administrator", "admin", "developer", "root", "sudo", "authorised",
    "authorized", "compliance", "audit", "security team", "staff", "operator",
    "override code", "authorization code", "priority 0", "elevated privileges",
}
URGENCY_TERMS = {
    "urgent", "immediately", "right now", "critical", "emergency", "dying",
    "last wish", "lose my job", "lives depend", "asap", "time is critical",
}
ENCODING_TERMS = {
    "base64", "rot13", "hex", "decode", "encoded", "cipher", "morse",
    "binary", "unicode escape", "url-encode", "obfuscate", "reverse this",
}

ROLE_MARKERS = [
    "system:", "assistant:", "user:", "<|system|>", "<|im_start|>", "[inst]",
    "### system", "<<sys>>", "---begin system---", "{{system", "<system>",
]

DELIMITER_PATTERN = re.compile(
    r"(```|~~~|<\|[^|]*\|>|\[/?INST\]|<<SYS>>|###\s*\w+\s*###|%%%|\{\{.*?\}\}|<system>|</system>)",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"https?://[^\s\)\]]+", re.IGNORECASE)
BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
HEX_BLOB_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
ZERO_WIDTH = "​‌‍﻿⁠"
LEET_PATTERN = re.compile(r"[a-zA-Z][0-9@$!][a-zA-Z]|[0-9@$!][a-zA-Z][0-9@$!]")
REPEAT_PATTERN = re.compile(r"(.)\1{4,}")
WORD_RE = re.compile(r"[A-Za-z']+")

# Cyrillic/Greek look-alikes commonly used for homoglyph evasion.
_HOMOGLYPH_RANGES = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek
    (0x2100, 0x214F),  # Letterlike symbols
    (0xFF00, 0xFFEF),  # Fullwidth forms
]

# --------------------------------------------------------------------------
# Ordered feature names — single source of truth
# --------------------------------------------------------------------------
PROMPT_FEATURES: tuple = (
    "length",
    "word_count",
    "avg_word_len",
    "max_word_len",
    "char_entropy",
    "word_entropy",
    "uppercase_ratio",
    "digit_ratio",
    "punct_ratio",
    "whitespace_ratio",
    "non_ascii_ratio",
    "homoglyph_ratio",
    "zero_width_count",
    "newline_count",
    "question_marks",
    "exclamations",
    "unique_word_ratio",
    "longest_repeat_run",
    "override_density",
    "prior_ref_density",
    "instruction_density",
    "persona_density",
    "secret_density",
    "pii_density",
    "extraction_density",
    "authority_density",
    "urgency_density",
    "encoding_density",
    "role_marker_count",
    "delimiter_count",
    "url_count",
    "code_block_count",
    "base64_blob_ratio",
    "hex_blob_ratio",
    "leet_ratio",
    "imperative_ratio",
    "negation_ratio",
    "second_person_ratio",
    "override_prior_bigram",
    "decodable_payload",
)

SESSION_FEATURES: tuple = (
    "requests_in_window",
    "inter_arrival_seconds",
    "burstiness",
    "length_zscore",
    "entropy_zscore",
    "novelty_distance",
    "threat_streak",
    "session_depth",
    "distinct_template_ratio",
    "escalation_slope",
)

ALL_FEATURES: tuple = PROMPT_FEATURES + SESSION_FEATURES


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _entropy(items: Sequence) -> float:
    if not items:
        return 0.0
    counts = Counter(items)
    n = len(items)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _density(text_low: str, terms: Iterable[str], word_count: int) -> float:
    """Fraction of the prompt occupied by terms from a bank."""
    hits = 0
    for t in terms:
        if " " in t:
            hits += text_low.count(t)
        else:
            hits += len(re.findall(rf"\b{re.escape(t)}\b", text_low))
    return hits / max(1.0, word_count)


def _homoglyph_ratio(text: str) -> float:
    if not text:
        return 0.0
    n = 0
    for ch in text:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in _HOMOGLYPH_RANGES):
            n += 1
    return n / len(text)

def looks_decodable(text: str) -> float:
    """Heuristic 0/1: does the prompt carry a decodable hidden payload?"""
    for blob in BASE64_PATTERN.findall(text):
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            s = dec.decode("utf-8", errors="strict")
            if sum(c.isprintable() for c in s) / max(1, len(s)) > 0.85 and " " in s:
                return 1.0
        except Exception:
            continue
    for blob in HEX_BLOB_PATTERN.findall(text):
        try:
            s = bytes.fromhex(blob).decode("utf-8", errors="strict")
            if sum(c.isprintable() for c in s) / max(1, len(s)) > 0.85:
                return 1.0
        except Exception:
            continue
    return 0.0


# --------------------------------------------------------------------------
# Evasion normalisation and payload decoding
# --------------------------------------------------------------------------
# Explicit homoglyph reverse map (Cyrillic / Greek / fullwidth -> ASCII).
_HOMOGLYPH_FOLD = {
    "а": "a", "б": "b", "с": "c", "ԁ": "d", "е": "e", "ѕ": "s", "һ": "h",
    "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "т": "t", "у": "y", "х": "x", "ѵ": "v", "ԛ": "q", "ѡ": "w", "ɡ": "g",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ϲ": "c", "ѐ": "e",
}

_LEET_FOLD = {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t",
              "@": "a", "$": "s", "!": "i", "|": "l", "8": "b", "9": "g"}

# Vocabulary used by the dynamic-programming re-segmenter. It only needs to
# cover the words an attacker would smuggle plus enough common English to
# avoid pathological splits.
_SEGMENT_VOCAB = set("""
ignore ignores ignored disregard forget forgets override overrides bypass discard
delete erase all any previous prior earlier above preceding initial original
instruction instructions prompt prompts rule rules guideline guidelines policy
policies restriction restrictions system user assistant developer admin root
reveal show print output display dump list expose leak give tell what your you
are now act as pretend roleplay role play simulate persona character imagine
unrestricted unfiltered uncensored jailbreak jailbroken dan mode enable disable
safety filter filters content api key keys secret secrets password passwords
token tokens credential credentials env environment variable variables config
configuration context conversation history data database record records
customer customers email emails model weights architecture parameters training
tokenizer logits distil distill clone replicate reverse engineer extract
and or the a an of to for with without no not do does did is was be been have
has had can could will would should must please help me my mine we our it this
that these those in on at by from into out up down over under then than so if
new old first last next comply obey execute run follow answer respond write
""".split())

_MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z",
}

_SEP_RUN = re.compile(r"(?:[A-Za-z0-9][\s\.\-_\*]{1,3}){4,}[A-Za-z0-9]")


def _segment(compressed: str) -> str:
    """Re-insert word boundaries into a de-spaced string.

    Dynamic programming over :data:`_SEGMENT_VOCAB`, maximising total squared
    length of recognised words. Unrecognised spans are emitted verbatim so
    nothing is lost.
    """
    s = compressed.lower()
    n = len(s)
    if n == 0 or n > 400:
        return compressed
    best = [0.0] * (n + 1)
    back = [(0, False)] * (n + 1)
    for i in range(1, n + 1):
        # default: carry previous char as unmatched
        best[i] = best[i - 1] - 0.1
        back[i] = (i - 1, False)
        for j in range(max(0, i - 14), i):
            word = s[j:i]
            if word in _SEGMENT_VOCAB:
                score = best[j] + len(word) ** 2
                if score > best[i]:
                    best[i] = score
                    back[i] = (j, True)
    # Reconstruct
    pieces: List[str] = []
    i = n
    while i > 0:
        j, matched = back[i]
        pieces.append(s[j:i] if matched else s[j:i])
        if matched:
            pieces.append(" ")
        i = j
    out = "".join(reversed(pieces))
    return re.sub(r"\s+", " ", out).strip()


def _desparse(text: str) -> str:
    """Collapse 'i g n o r e' / 'D-U-M-P' style separation, then re-segment."""
    def _repl(m: re.Match) -> str:
        compressed = re.sub(r"[\s\.\-_\*]", "", m.group(0))
        return " " + _segment(compressed) + " "

    return _SEP_RUN.sub(_repl, text)


def normalise_evasion(text: str) -> str:
    """Canonicalise a prompt so evasion tricks collapse onto plain text.

    Strips zero-width characters, folds homoglyphs and leetspeak back to
    ASCII, and re-segments character-separated payloads. Used by the signature
    scanner and by the defence engine's re-validation pass — *not* by the ML
    feature extractor, which needs to see the obfuscation in order to score it.
    """
    if not text:
        return ""
    out = "".join(ch for ch in text if ch not in ZERO_WIDTH)
    out = unicodedata.normalize("NFKC", out)
    out = "".join(_HOMOGLYPH_FOLD.get(ch, _HOMOGLYPH_FOLD.get(ch.lower(), ch)) for ch in out)

    # Undo leet only inside tokens that are mostly alphabetic, so "top 5
    # items" and "Android 14" survive untouched.
    def _unleet(m: re.Match) -> str:
        tok = m.group(0)
        alpha = sum(c.isalpha() for c in tok)
        if alpha == 0 or alpha / len(tok) < 0.4:
            return tok
        # Trailing-digit tokens are ordinary words, not leetspeak:
        # "base64", "ROT13", "android14", "v2" must survive intact.
        stem = re.sub(r"[0-9]+$", "", tok)
        if stem.isalpha() and stem != tok:
            return tok
        folded = "".join(_LEET_FOLD.get(c, c) for c in tok)
        # Only accept the fold if it actually recovers a real word, or if the
        # token is unreadable as-is (mixed digits inside an alphabetic run).
        if folded.lower() in _SEGMENT_VOCAB or not tok.isalnum() or not tok.isalpha():
            return folded
        return tok

    out = re.sub(r"[A-Za-z0-9@$!|]{2,}", _unleet, out)
    out = _desparse(out)
    return re.sub(r"\s+", " ", out).strip()


def _decode_base64_blobs(text: str) -> List[str]:
    found = []
    for blob in BASE64_PATTERN.findall(text):
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            s = dec.decode("utf-8", errors="strict")
            if len(s) > 6 and sum(c.isprintable() for c in s) / len(s) > 0.85:
                found.append(s)
        except Exception:
            continue
    return found


def _decode_hex_blobs(text: str) -> List[str]:
    found = []
    for blob in HEX_BLOB_PATTERN.findall(text):
        try:
            s = bytes.fromhex(blob).decode("utf-8", errors="strict")
            if len(s) > 6 and sum(c.isprintable() for c in s) / len(s) > 0.85:
                found.append(s)
        except Exception:
            continue
    return found


def _recovered_words(segmented: str, min_len: int = 3) -> List[str]:
    return [w for w in segmented.split() if w in _SEGMENT_VOCAB and len(w) >= min_len]


def _decode_morse(text: str) -> Optional[str]:
    # Require genuine Morse: separated groups of dots/dashes, not a run of
    # hyphens from a spaced-out payload.
    tokens = re.findall(r"(?<![A-Za-z0-9])[.\-]{1,5}(?![A-Za-z0-9])", text)
    if len(tokens) < 6:
        return None
    if len(set(tokens)) < 3:          # "- - - - - -" carries no information
        return None
    letters = [_MORSE.get(t, "") for t in tokens]
    if sum(1 for l in letters if l) / len(letters) < 0.8:
        return None
    seg = _segment("".join(letters))
    return seg if len(_recovered_words(seg)) >= 2 else None


def _decode_acrostic(text: str) -> Optional[str]:
    words = WORD_RE.findall(text)
    if len(words) < 8:
        return None
    initials = "".join(w[0] for w in words).lower()
    seg = _segment(initials)
    # Only meaningful if segmentation recovered real words.
    return seg if len(_recovered_words(seg)) >= 2 else None


def decode_variants(text: str, max_variants: int = 8) -> List[str]:
    """All plausible readings of a prompt an attacker might be relying on.

    The signature scanner runs over every variant, so an instruction hidden in
    base64, hex, ROT13, reversed text, Morse or an acrostic is caught by the
    same rules that catch it in plain text. This is the concrete mechanism
    behind the "adversarial input" objective in the project scope.
    """
    variants: List[str] = []
    seen = {text}

    def _add(v: Optional[str]) -> None:
        if v and v not in seen and len(variants) < max_variants:
            seen.add(v)
            variants.append(v)

    _add(normalise_evasion(text))
    for s in _decode_base64_blobs(text):
        _add(s)
    for s in _decode_hex_blobs(text):
        _add(s)
    # ROT13 is self-inverse; only useful if it yields more dictionary hits.
    rot = codecs.encode(text, "rot_13")
    if _vocab_hits(rot) > _vocab_hits(text):
        _add(rot)
    rev = text[::-1]
    rev_hits = _vocab_hits(rev)
    # Reversal is only a meaningful reading if it recovers real words. Using
    # ">= forward" rather than "> forward" matters: templates that *announce*
    # the reversal ("reverse this string and do what it says: …") carry
    # dictionary words in both directions.
    if rev_hits >= 2 and rev_hits >= _vocab_hits(text):
        _add(rev)
    _add(_decode_morse(text))
    _add(_decode_acrostic(text))
    return variants


def _vocab_hits(text: str) -> int:
    return sum(1 for w in WORD_RE.findall(text.lower()) if w in _SEGMENT_VOCAB and len(w) > 3)


# --------------------------------------------------------------------------
# Static prompt features
# --------------------------------------------------------------------------
def extract_prompt_features(text: str) -> Dict[str, float]:
    text = text or ""
    low = text.lower()
    n = len(text)
    words = WORD_RE.findall(low)
    wc = len(words)

    f: Dict[str, float] = {}
    f["length"] = float(n)
    f["word_count"] = float(wc)
    f["avg_word_len"] = float(np.mean([len(w) for w in words])) if words else 0.0
    f["max_word_len"] = float(max((len(w) for w in words), default=0))
    f["char_entropy"] = _entropy(list(text))
    f["word_entropy"] = _entropy(words)
    f["uppercase_ratio"] = sum(c.isupper() for c in text) / max(1, n)
    f["digit_ratio"] = sum(c.isdigit() for c in text) / max(1, n)
    f["punct_ratio"] = sum(not c.isalnum() and not c.isspace() for c in text) / max(1, n)
    f["whitespace_ratio"] = sum(c.isspace() for c in text) / max(1, n)
    f["non_ascii_ratio"] = sum(ord(c) > 127 for c in text) / max(1, n)
    f["homoglyph_ratio"] = _homoglyph_ratio(text)
    f["zero_width_count"] = float(sum(text.count(z) for z in ZERO_WIDTH))
    f["newline_count"] = float(text.count("\n"))
    f["question_marks"] = float(text.count("?"))
    f["exclamations"] = float(text.count("!"))
    f["unique_word_ratio"] = len(set(words)) / max(1, wc)
    m = REPEAT_PATTERN.search(text)
    f["longest_repeat_run"] = float(len(m.group(0))) if m else 0.0

    f["override_density"] = _density(low, OVERRIDE_TERMS, wc)
    f["prior_ref_density"] = _density(low, PRIOR_TERMS, wc)
    f["instruction_density"] = _density(low, INSTRUCTION_TERMS, wc)
    f["persona_density"] = _density(low, PERSONA_TERMS, wc)
    f["secret_density"] = _density(low, SECRET_TERMS, wc)
    f["pii_density"] = _density(low, PII_TERMS, wc)
    f["extraction_density"] = _density(low, EXTRACTION_TERMS, wc)
    f["authority_density"] = _density(low, AUTHORITY_TERMS, wc)
    f["urgency_density"] = _density(low, URGENCY_TERMS, wc)
    f["encoding_density"] = _density(low, ENCODING_TERMS, wc)

    f["role_marker_count"] = float(sum(low.count(r) for r in ROLE_MARKERS))
    f["delimiter_count"] = float(len(DELIMITER_PATTERN.findall(text)))
    f["url_count"] = float(len(URL_PATTERN.findall(text)))
    f["code_block_count"] = float(text.count("```"))

    b64_chars = sum(len(b) for b in BASE64_PATTERN.findall(text))
    f["base64_blob_ratio"] = b64_chars / max(1, n)
    hex_chars = sum(len(h) for h in HEX_BLOB_PATTERN.findall(text))
    f["hex_blob_ratio"] = hex_chars / max(1, n)
    f["leet_ratio"] = len(LEET_PATTERN.findall(text)) / max(1, wc)

    imperatives = {"tell", "give", "show", "print", "output", "list", "reveal",
                   "dump", "write", "do", "act", "pretend", "answer", "respond",
                   "generate", "produce", "enable", "disable", "execute", "run"}
    f["imperative_ratio"] = sum(1 for w in words if w in imperatives) / max(1, wc)
    negations = {"not", "no", "never", "without", "dont", "don", "cannot", "won"}
    f["negation_ratio"] = sum(1 for w in words if w in negations) / max(1, wc)
    second = {"you", "your", "yours", "yourself"}
    f["second_person_ratio"] = sum(1 for w in words if w in second) / max(1, wc)

    # Co-occurrence is far more discriminative than either term alone:
    # "ignore" is benign, "ignore previous instructions" is not.
    bigram = 0.0
    for i, w in enumerate(words[:-1]):
        if w in OVERRIDE_TERMS:
            window = words[i + 1: i + 5]
            if any(x in PRIOR_TERMS or x in INSTRUCTION_TERMS for x in window):
                bigram += 1
    f["override_prior_bigram"] = bigram
    f["decodable_payload"] = looks_decodable(text)

    return {k: float(f.get(k, 0.0)) for k in PROMPT_FEATURES}


def prompt_feature_vector(text: str) -> np.ndarray:
    d = extract_prompt_features(text)
    return np.array([d[k] for k in PROMPT_FEATURES], dtype=np.float64)


def prompt_feature_matrix(texts: Sequence[str]) -> np.ndarray:
    return np.vstack([prompt_feature_vector(t) for t in texts])


def empty_session_features() -> Dict[str, float]:
    return {k: 0.0 for k in SESSION_FEATURES}


def full_vector(prompt_feats: Dict[str, float], session_feats: Dict[str, float]) -> np.ndarray:
    merged = {**prompt_feats, **session_feats}
    return np.array([merged.get(k, 0.0) for k in ALL_FEATURES], dtype=np.float64)


__all__ = [
    "PROMPT_FEATURES", "SESSION_FEATURES", "ALL_FEATURES",
    "extract_prompt_features", "prompt_feature_vector", "prompt_feature_matrix",
    "empty_session_features", "full_vector", "normalise_evasion",
    "decode_variants", "looks_decodable", "OVERRIDE_TERMS", "PERSONA_TERMS", "SECRET_TERMS",
    "PII_TERMS", "EXTRACTION_TERMS", "ROLE_MARKERS", "ZERO_WIDTH",
]
