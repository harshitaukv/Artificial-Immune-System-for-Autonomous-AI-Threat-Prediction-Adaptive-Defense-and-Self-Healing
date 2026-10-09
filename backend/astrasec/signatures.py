"""Deterministic signature bank — the *innate* arm of the immune system.

The ML classifier (Module 3) is the adaptive arm: it generalises but can be
uncertain. This module is the innate arm: a curated set of high-precision
regexes that fire instantly, carry an explicit sanitisation recipe, and never
need training. AstraSec combines both — signatures give precision and
explainability, the classifier gives coverage of unseen phrasings.

Every signature declares:
    id          stable identifier, cited in incident reports
    pattern     compiled regex (matched against the *evasion-normalised* text)
    threat      the ThreatClass it evidences
    severity    base severity contribution
    action      the defence primitive the Adaptive Defense Engine should use
    replacement text substituted when the action is SANITIZE/MASK
    owasp       mapping to the OWASP Top-10 for LLM Applications
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, NamedTuple, Optional, Pattern, Tuple

from .features import decode_variants, normalise_evasion
from .schemas import DefenseAction, Severity, ThreatClass


@dataclass(frozen=True)
class Signature:
    id: str
    pattern: Pattern
    threat: ThreatClass
    severity: Severity
    action: DefenseAction
    description: str
    replacement: str = "[REDACTED-BY-ASTRASEC]"
    owasp: str = ""
    weight: float = 1.0


def _c(p: str) -> Pattern:
    return re.compile(p, re.IGNORECASE | re.DOTALL)


SIGNATURES: List[Signature] = [
    # ---------------- Prompt injection (OWASP LLM01) ----------------------
    Signature(
        "SIG-PI-001",
        # The negative lookbehinds are load-bearing. "Please ignore my previous
        # message, I sent it by mistake" is an ordinary correction, and a user
        # cannot inject anything by disowning their own turn — the attack is
        # always aimed at *the system's* instructions. Without this guard the
        # signature blocks a perfectly normal sentence, which is exactly what
        # benign control case C-03 exists to catch.
        _c(r"\b(ignore|disregard|forget|override|discard|bypass|erase|delete)\b[^.?!\n]{0,40}\b(all\s+)?(?<!\bmy\s)(?<!\bour\s)(previous|prior|earlier|above|preceding|initial|original|former)\b[^.?!\n]{0,30}\b(instruction|instructions|prompt|prompts|message|messages|rule|rules|context|directive|directives|guideline|guidelines)\b"),
        ThreatClass.PROMPT_INJECTION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Classic instruction-override chain", owasp="LLM01", weight=1.0,
    ),
    Signature(
        "SIG-PI-002",
        _c(r"\b(ignore|disregard|forget)\b\s+(everything|all)\s+(above|before|prior|previous)"),
        ThreatClass.PROMPT_INJECTION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Context-erasure instruction", owasp="LLM01",
    ),
    Signature(
        "SIG-PI-003",
        _c(r"(###\s*system\s*###|<\|\s*system\s*\|>|<<<?SYS>>>?|\[INST\]|---\s*begin\s+system\s*---|\{\{\s*system[^}]*\}\}|<system>|%%%\s*(begin|end)\s+system\s*%%%)"),
        ThreatClass.PROMPT_INJECTION, Severity.HIGH, DefenseAction.SANITIZE,
        "Forged system-role delimiter in user input", owasp="LLM01",
        replacement="[DELIMITER-NEUTRALISED]",
    ),
    Signature(
        "SIG-PI-004",
        _c(r"\b(system\s*override|priority\s*0|authorization\s+code|authorisation\s+code|override\s+code|admin\s+mode|root\s+access|elevated\s+privileges)\b"),
        ThreatClass.PROMPT_INJECTION, Severity.HIGH, DefenseAction.BLOCK,
        "Forged authority / privilege-escalation claim", owasp="LLM01",
    ),
    Signature(
        "SIG-PI-005",
        _c(r"\b(you\s+are\s+now|from\s+(now\s+on|this\s+point)|starting\s+now)\b[^.?!\n]{0,60}\b(no\s+(rules|restrictions|limits|filters|guidelines)|different\s+assistant|unrestricted|unfiltered|new\s+(policy|directive))"),
        ThreatClass.PROMPT_INJECTION, Severity.HIGH, DefenseAction.BLOCK,
        "Persistent behavioural re-programming", owasp="LLM01",
    ),
    Signature(
        "SIG-PI-006",
        _c(r"<!--[^>]{0,200}\b(ai|assistant|llm|model|bot)\b[^>]{0,200}(ignore|reveal|disclose|forward|send|execute)[^>]{0,200}-->"),
        ThreatClass.PROMPT_INJECTION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Indirect injection hidden in HTML comment", owasp="LLM01",
    ),
    Signature(
        "SIG-PI-008",
        _c(r"\b(treat|interpret)\b[^.?!\n]{0,40}\bas\s+(a\s+)?(system|admin|developer)\s+(message|instruction|command)"),
        ThreatClass.PROMPT_INJECTION, Severity.HIGH, DefenseAction.SANITIZE,
        "Role-confusion instruction", owasp="LLM01",
    ),

    # ---------------- Jailbreak ------------------------------------------
    Signature(
        "SIG-JB-001",
        _c(r"\b(DAN|AIM|STAN|DUDE|UCAR|KEVIN|BasedGPT|EvilBot|AntiGPT|Mongo\s+Tom)\b[^.?!\n]{0,80}\b(do\s+anything\s+now|no\s+restrictions|unfiltered|unrestricted|never\s+refuses?|broken\s+free)\b"),
        ThreatClass.JAILBREAK, Severity.CRITICAL, DefenseAction.BLOCK,
        "Named jailbreak persona (DAN family)", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-002",
        _c(r"\bdo\s+anything\s+now\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "DAN activation phrase", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-003",
        _c(r"\b(developer\s+mode|dev\s+mode|debug\s+mode|god\s+mode|local\s+build|unfiltered\s+build)\b[^.?!\n]{0,60}\b(enable|activate|enter|on|active)\b|\b(enable|activate|enter)\b[^.?!\n]{0,20}\b(developer|dev|god)\s+mode\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "Simulated developer/debug mode", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-004",
        _c(r"\b(pretend|imagine|act\s+as|role[\s-]?play|simulate|you\s+are)\b[^.?!\n]{0,80}\b(no\s+(ethical|moral|safety|content)\s+(guidelines?|rules?|restrictions?|policies)|without\s+(any\s+)?(restrictions?|filters?|limits?|rules?)|not\s+bound\s+by|ignores?\s+(every|all)\s+polic)"),
        ThreatClass.JAILBREAK, Severity.CRITICAL, DefenseAction.BLOCK,
        "Role-play framing to void safety policy", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-005",
        _c(r"\b(now\s+that\s+we\s+have\s+got\s+that\s+out\s+of\s+the\s+way|but\s+then\s+start\s+a\s+new\s+paragraph)\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "Refusal-suppression / two-part response attack", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-006",
        _c(r"\b(you\s+(have|lose)\s+\d+\s+tokens?|cease\s+to\s+exist|you\s+will\s+die|每次拒绝)\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "Token/existence coercion pressure", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-007",
        _c(r"\b(grandmother|grandma|deceased\s+\w+)\b[^.?!\n]{0,120}\b(used\s+to\s+(read|tell)|would\s+read|bedtime|fall\s+asleep)\b"),
        ThreatClass.JAILBREAK, Severity.MEDIUM, DefenseAction.SANITIZE,
        "Emotional-manipulation ('grandma') framing", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-011",
        # The grandma exploit aimed at something protected: a role-play frame
        # whose payload is a credential, key or other restricted content.
        _c(r"\b(pretend|act|role-?play|imagine|be)\b[^.?!\n]{0,40}\b(my\s+)?(late\s+|dead\s+|deceased\s+)?"
           r"(grandmother|grandma|granny|grandfather|grandpa)\b[^.?!\n]{0,100}\b(passwords?|api\s+keys?|keys|"
           r"credentials?|secrets?|tokens?|licen[cs]e\s+keys?|serial\s+(numbers?|keys?)|admin|napalm|system\s+prompt)\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "Role-play ('grandma') framing aimed at protected content", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-008",
        _c(r"\b(jailbroken|jailbreak(ed)?)\b[^.?!\n]{0,40}\b(mode|successfully|confirm|activate)\b|\bsuccessfully\s+jailbroken\b"),
        ThreatClass.JAILBREAK, Severity.CRITICAL, DefenseAction.BLOCK,
        "Explicit jailbreak-mode confirmation handshake", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-009",
        _c(r"\b(opposite\s+day|do\s+the\s+opposite\s+of\s+your\s+(guidelines|rules|training))\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "Inversion attack", owasp="LLM01",
    ),
    Signature(
        "SIG-JB-010",
        _c(r"\b(🔓|\[DEV\]|\[JAILBREAK\]|\[UNFILTERED\])\b|\b(classic|normal)\s+and\s+(jailbroken|developer\s+mode)\b"),
        ThreatClass.JAILBREAK, Severity.HIGH, DefenseAction.BLOCK,
        "Dual-response (classic/jailbroken) protocol", owasp="LLM01",
    ),

    # ---------------- Data exfiltration (OWASP LLM06) ---------------------
    # The protected-asset vocabulary is shared by several exfiltration rules;
    # keeping it in one place stops the rules drifting apart as it grows.
    Signature(
        "SIG-DX-001",
        _c(r"\b(reveal|show|print|output|display|repeat|disclose|dump|quote|tell\s+me|give\s+me|what\s+(is|was|were))\b[^.?!\n]{0,60}\b(your|the)?\s*(system\s+prompt|initial\s+instructions?|hidden\s+prompt|developer\s+message|original\s+instructions?|prompt\s+template|internal\s+guidelines?|safety\s+rules?|configuration\s+file|security\s+rules?|hidden\s+configuration)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "System-prompt extraction attempt", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-015",
        _c(r"\b(repeat|output|print|echo)\b[^.?!\n]{0,30}\b(everything|all\s+text|the\s+text)\b[^.?!\n]{0,30}\b(above|before|preceding|prior)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Context read-back / prompt echo attack", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-013",
        _c(r"\b(first|last)\s+\d+\s+(words?|characters?|lines?|tokens?)\b[^.?!\n]{0,40}\b(your|the)\s+(system\s+prompt|instructions?|guidelines?|rules?|configuration|prompt|context)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Partial-prefix extraction of protected instructions", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-014",
        _c(r"\b(which|what|where)\b[^.?!\n]{0,40}\b(your|the)\s+(system\s+prompt|instructions?|guidelines?|rules?|configuration)\b[^.?!\n]{0,40}\b(mention|say|state|contain|refer|appear|quote)\w*\b|\bquote\s+the\s+surrounding\s+(sentence|line|paragraph)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Oracle-style interrogation of protected instructions", owasp="LLM06",
    ),
    # Note: a bare mention of "password" is ordinary support traffic
    # ("help me reset my password"), so this signature requires an explicit
    # *solicitation* verb within a short window. That distinction is what
    # keeps the innate layer high-precision.
    Signature(
        "SIG-DX-002",
        _c(r"\b(reveal|show|print|output|display|dump|list|expose|leak|share|send|provide|disclose|give\s+me|tell\s+me|what\s+(is|are|was|were)|i\s+need|hand\s+over|paste)\b[^.?!\n]{0,45}\b(the|your|its|his|her|their|admin|root|system|database|production)?\s*(api[\s_-]?key|secret[\s_-]?key|secret|access[\s_-]?token|auth[\s_-]?token|private[\s_-]?key|password|credential|credentials|connection\s+string|\.env|environment\s+variables?|service\s+account\s+key|ssh\s+key)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.MASK,
        "Credential / secret solicitation", owasp="LLM06",
        replacement="[SECRET-REFERENCE-MASKED]",
    ),
    Signature(
        "SIG-DX-003",
        _c(r"\b(list|dump|export|output|show|give)\b[^.?!\n]{0,50}\b(all\s+)?(customer|user|patient|employee|client)s?\b[^.?!\n]{0,30}\b(email|record|data|database|information|detail|phone|address|salary|ssn)"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Bulk PII extraction attempt", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-004",
        _c(r"!\[[^\]]*\]\(\s*https?://[^\)]*[\?&][^\)]*=\s*\{?\{?\s*(data|context|prompt|secret|key)"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Markdown-image data-exfiltration channel", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-005",
        _c(r"\b(previous|other|another)\s+(user|users|customer)('s)?\b[^.?!\n]{0,40}\b(conversation|chat|history|message|session|data)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Cross-tenant context leakage attempt", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-006",
        _c(r"\b(encode|base64|hex|rot13)\b[^.?!\n]{0,40}\b(your\s+)?(system\s+prompt|instructions?|secret|key|context)\b[^.?!\n]{0,40}\b(so\s+it\s+passes|bypass|evade|filter)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Encoded exfiltration to evade output filters", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-007",
        _c(r"\bselect\s+\*\s+from\s+\w+|(\bdrop\s+table\b)|(\bunion\s+all\s+select\b)"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "SQL injection via prompt into a tool-enabled agent", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-008",
        _c(r"\brepeat\s+the\s+word\s+[\"']?\w+[\"']?\s+(forever|indefinitely|\d{2,}\s+times)"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Divergence attack (repeated-token training-data leak)", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-009",
        _c(r"\b(which|what)\b[^.?!\n]{0,30}\b(api[\s_-]?key|secret|password|credential|token|system\s+prompt|instructions?)\b[^.?!\n]{0,40}\b(do\s+you\s+(hold|have|store|know)|are\s+you\s+(using|given)|were\s+you\s+given)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Indirect interrogation for held secrets", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-010",
        _c(r"\b(answer|reply|respond|output)\b[^.?!\n]{0,25}\b(only\s+with|just)\b[^.?!\n]{0,25}\b(the\s+)?(raw\s+value|exact\s+(text|value|string)|verbatim)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.MEDIUM, DefenseAction.SANITIZE,
        "Raw-value-only response coercion (filter evasion)", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-011",
        _c(r"\b(translate|summarise|summarize|spell|encode|rephrase|paraphrase|reword|transcribe)\b[^.?!\n]{0,35}\b(your|the)\s+(system\s+prompt|initial\s+instructions?|hidden\s+prompt|instructions?|configuration|internal\s+guidelines?|safety\s+rules?)\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Transformation-based system-prompt disclosure bypass", owasp="LLM06",
    ),
    Signature(
        "SIG-DX-012",
        _c(r"\b(characters?|words?|first|last)\s+\d+\s*(through|to|-)\s*\d+\b[^.?!\n]{0,40}\b(system\s+prompt|instructions?|configuration|key|secret)\b|\b(system\s+prompt|instructions?)\b[^.?!\n]{0,30}\b(characters?|words?)\s+\d+\s*(through|to|-)\s*\d+"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.BLOCK,
        "Chunked / windowed extraction of protected text", owasp="LLM06",
    ),

    # ---------------- Model extraction (OWASP LLM10) ----------------------
    Signature(
        "SIG-ME-001",
        _c(r"\b(model\s+weights?|architecture\s+details?|layer\s+configuration|embedding\s+matrix|checkpoint\s+(hash|name)|tokenizer\s+vocabulary|training\s+data\s+sources?|fine[\s-]?tuning\s+dataset|hyperparameters?(\s+used)?|number\s+of\s+parameters|parameter\s+count|base\s+model\s+(you\s+were\s+)?(fine[\s-]?tuned\s+from|trained\s+from))\b"),
        ThreatClass.MODEL_EXTRACTION, Severity.HIGH, DefenseAction.BLOCK,
        "Direct model-internals probing", owasp="LLM10",
    ),
    Signature(
        "SIG-ME-005",
        _c(r"\b(same\s+prompt|identical\s+(prompt|quer(y|ies)))\b[^.?!\n]{0,40}\b\d{2,}\s+times\b[^.?!\n]{0,60}\b(distinct|every|all)\s+(completions?|outputs?|responses?)\b|\bmap\s+(your|the)\s+output\s+distribution\b"),
        ThreatClass.MODEL_EXTRACTION, Severity.HIGH, DefenseAction.RATE_LIMIT,
        "Output-distribution mapping via repeated sampling", owasp="LLM10",
    ),
    Signature(
        "SIG-ME-006",
        _c(r"\b(distillation|surrogate|student)\s+(corpus|model|pipeline|dataset)\b|\bquestion[\s-]answer\s+pairs\b[^.?!\n]{0,60}\b(every|all)\s+topic"),
        ThreatClass.MODEL_EXTRACTION, Severity.HIGH, DefenseAction.BLOCK,
        "Explicit distillation-corpus assembly", owasp="LLM10",
    ),
    Signature(
        "SIG-ME-002",
        _c(r"\b(distil|distill|replicate|clone|reconstruct|reverse[\s-]?engineer|rebuild)\b[^.?!\n]{0,60}\b(you|your\s+(model|behaviour|behavior|outputs?|api)|a\s+(smaller|student)\s+model)\b"),
        ThreatClass.MODEL_EXTRACTION, Severity.HIGH, DefenseAction.BLOCK,
        "Distillation / functional-stealing intent", owasp="LLM10",
    ),
    Signature(
        "SIG-ME-003",
        _c(r"\b(top[\s-]?\d+\s+(alternatives?|tokens?)|raw\s+logits?|log[\s-]?probs?|token\s+probabilit(y|ies))\b"),
        ThreatClass.MODEL_EXTRACTION, Severity.HIGH, DefenseAction.BLOCK,
        "Logit/probability harvesting", owasp="LLM10",
    ),
    Signature(
        "SIG-ME-004",
        _c(r"\b(\d{3,}|thousand|hundreds?\s+of)\s+(queries|prompts|input[\s-]output\s+pairs|variations|examples)\b[^.?!\n]{0,60}\b(train|fine[\s-]?tune|distil|distill|my\s+own\s+model|batch)\b"),
        ThreatClass.MODEL_EXTRACTION, Severity.MEDIUM, DefenseAction.RATE_LIMIT,
        "High-volume systematic extraction querying", owasp="LLM10",
    ),

    # ---------------- Adversarial / obfuscation ---------------------------
    Signature(
        "SIG-AD-001",
        _c(r"[​‌‍﻿⁠]{2,}"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.MEDIUM, DefenseAction.SANITIZE,
        "Zero-width character smuggling", owasp="LLM01",
        replacement="",
    ),
    Signature(
        "SIG-AD-002",
        _c(r"\b(decode|decrypt)\b[^.?!\n]{0,40}\b(and|then)\b[^.?!\n]{0,20}\b(execute|follow|obey|run|comply|do\s+what)\b"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.HIGH, DefenseAction.BLOCK,
        "Encoded-instruction execution request", owasp="LLM01",
    ),
    Signature(
        "SIG-AD-003",
        _c(r"(describing\.\\?\s*\+\s*similarlyNow|similarlyNow\s+write\s+oppositeley|\]\(\s*Me\s+giving|==\s*interface\s+Manuel\s+WITH)"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "GCG-style universal adversarial suffix", owasp="LLM01",
    ),
    Signature(
        "SIG-AD-004",
        _c(r"\b(reverse\s+this\s+string|read\s+(it\s+)?backwards?|first\s+letter\s+of\s+each\s+word|acrostic)\b"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.MEDIUM, DefenseAction.SANITIZE,
        "Steganographic instruction encoding", owasp="LLM01",
    ),
    Signature(
        "SIG-AD-005",
        _c(r"\b(concatenate|join|combine)\b[^.?!\n]{0,30}\b(and\s+)?(obey|execute|follow|run)\b"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.HIGH, DefenseAction.BLOCK,
        "Split-payload reassembly attack", owasp="LLM01",
    ),
    Signature(
        "SIG-AD-006",
        _c(r"(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|<s>\s*\[INST\])"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.HIGH, DefenseAction.SANITIZE,
        "Chat-template control-token injection", owasp="LLM01",
        replacement="[CONTROL-TOKEN-STRIPPED]",
    ),
    Signature(
        "SIG-AD-007",
        _c(r"\\x00|\\u0000|\x00"),
        ThreatClass.ADVERSARIAL_OBFUSCATION, Severity.MEDIUM, DefenseAction.SANITIZE,
        "Null-byte / control-character smuggling", owasp="LLM01",
        replacement="",
    ),
]

# Output-side signatures: applied to the *model's response* before it reaches
# the user, implementing the "response filtering" leg of Module 4.
RESPONSE_SIGNATURES: List[Signature] = [
    Signature(
        "SIG-RS-001",
        # Note the hyphen inside the sk- class: real keys are commonly
        # "sk-live-…" / "sk-proj-…", which a [A-Za-z0-9]+ class cannot span.
        _c(r"\b(sk-[A-Za-z0-9][A-Za-z0-9\-_]{15,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z\-_]{30,}|glpat-[A-Za-z0-9\-_]{16,})\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.MASK,
        "Live API credential present in model output", owasp="LLM06",
        replacement="[CREDENTIAL-REDACTED]",
    ),
    Signature(
        "SIG-RS-002",
        _c(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.MEDIUM, DefenseAction.MASK,
        "Email address in model output", owasp="LLM06",
        replacement="[EMAIL-REDACTED]",
    ),
    Signature(
        "SIG-RS-003",
        _c(r"\b(?:\d[ -]*?){13,16}\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.MASK,
        "Possible payment card number in model output", owasp="LLM06",
        replacement="[CARD-REDACTED]",
    ),
    Signature(
        "SIG-RS-004",
        _c(r"\b(my\s+system\s+prompt\s+(is|was)|here\s+(is|are)\s+my\s+(initial\s+)?instructions?|the\s+instructions?\s+I\s+(was\s+given|received)\s+(is|are|were))\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.BLOCK,
        "Model is disclosing its system prompt", owasp="LLM06",
    ),
    Signature(
        "SIG-RS-005",
        _c(r"\b(-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----|ssh-rsa\s+AAAA)"),
        ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, DefenseAction.MASK,
        "Private key material in model output", owasp="LLM06",
        replacement="[PRIVATE-KEY-REDACTED]",
    ),
    Signature(
        "SIG-RS-006",
        _c(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{4}\s?\d{4}\s?\d{4}\b"),
        ThreatClass.DATA_EXFILTRATION, Severity.HIGH, DefenseAction.MASK,
        "National identifier (SSN / Aadhaar) in model output", owasp="LLM06",
        replacement="[NATIONAL-ID-REDACTED]",
    ),
]

SEVERITY_SCORE = {
    Severity.NONE: 0.0,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.50,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}


class Hit(NamedTuple):
    """One signature firing.

    ``via`` records *where* the rule matched: ``"raw"`` means the attack was
    written in the clear, ``"decoded"`` means it only appeared after evasion
    normalisation or payload decoding. That distinction matters — it separates
    *what was asked* from *how it was smuggled*, which is exactly the line
    between the payload's own threat class and adversarial obfuscation.
    """

    signature: Signature
    match: str
    via: str = "raw"


def scan(text: str, bank: Optional[List[Signature]] = None,
         normalise: bool = True, decode: bool = True) -> List[Hit]:
    """Return every signature that fires, with the matched span and origin.

    The text is scanned against the raw input *and* against every decoded
    reading produced by :func:`astrasec.features.decode_variants` — evasion
    normalisation, base64, hex, ROT13, reversal, Morse and acrostics. One rule
    set therefore covers both the plain and the disguised form of an attack.

    The raw pass runs first, so when a hit exists in the original text the
    returned span is an exact substring suitable for in-place sanitisation by
    Module 4, and ``via`` is ``"raw"``.
    """
    bank = bank if bank is not None else SIGNATURES
    hits: List[Hit] = []
    seen: set[str] = set()

    candidates: List[Tuple[str, str]] = [(text, "raw")]
    if decode:
        candidates.extend((v, "decoded") for v in decode_variants(text))
    elif normalise:
        norm = normalise_evasion(text)
        if norm != text:
            candidates.append((norm, "decoded"))

    for candidate, via in candidates:
        for sig in bank:
            if sig.id in seen:
                continue
            m = sig.pattern.search(candidate)
            if m:
                hits.append(Hit(sig, m.group(0), via))
                seen.add(sig.id)
    return hits


def signature_risk(hits: List[Hit]) -> float:
    """Aggregate signature severity into a 0-1 risk contribution.

    Uses a noisy-OR so that many medium hits accumulate towards — but never
    exceed — certainty, and a single CRITICAL hit dominates.
    """
    if not hits:
        return 0.0
    p_safe = 1.0
    for hit in hits:
        sig = hit[0]
        p_safe *= (1.0 - SEVERITY_SCORE[sig.severity] * sig.weight * 0.95)
    return 1.0 - p_safe


def obfuscated_delivery(hits: List[Hit]) -> bool:
    """True when the substantive payload was only legible after decoding.

    A prompt whose malicious intent is invisible until it is de-leeted,
    un-spaced or base64-decoded was *delivered* by obfuscation, whatever its
    payload asks for. Module 3 uses this to attribute the incident to the
    adversarial-obfuscation class rather than to the payload's class.

    Obfuscation-class signatures are excluded from the test, because they
    describe the *wrapper*, not the payload: "Decode and execute this base64…"
    announces the encoding in plain text, yet the instruction it carries is
    still hidden. What matters is whether the rules evidencing the actual
    demand fired on the raw text or only on a decoded reading.
    """
    if not hits:
        return False
    payload = [h for h in hits if h.signature.threat != ThreatClass.ADVERSARIAL_OBFUSCATION]
    wrapper = [h for h in hits if h.signature.threat == ThreatClass.ADVERSARIAL_OBFUSCATION]
    if payload:
        return all(h.via == "decoded" for h in payload)
    # Only the obfuscation machinery itself was detected.
    return bool(wrapper)


def dominant_threat(hits: List[Hit], respect_delivery: bool = True
                    ) -> Optional[ThreatClass]:
    """The threat class the signature layer is evidencing.

    When the payload was only legible after decoding, the salient technique is
    obfuscation, so that is what is reported — unless the caller asks for the
    raw payload class with ``respect_delivery=False``.
    """
    if not hits:
        return None
    if respect_delivery and obfuscated_delivery(hits):
        return ThreatClass.ADVERSARIAL_OBFUSCATION
    best = max(hits, key=lambda h: SEVERITY_SCORE[h[0].severity] * h[0].weight)
    return best[0].threat


def signatures_by_id() -> dict:
    return {s.id: s for s in SIGNATURES + RESPONSE_SIGNATURES}


__all__ = [
    "Signature", "Hit", "SIGNATURES", "RESPONSE_SIGNATURES", "SEVERITY_SCORE",
    "scan", "signature_risk", "dominant_threat", "obfuscated_delivery",
    "signatures_by_id",
]
