"""Pluggable LLM advisor for Module 5.

The project specifies Llama 3.1 for generating security recommendations. A
security control must not *depend* on an optional component, so this advisor
is strictly additive:

``offline``            deterministic template + retrieval engine (default).
``ollama``             local Llama 3.1 via the Ollama HTTP API.
``openai_compatible``  any server exposing /v1/chat/completions.

Every provider falls back to the offline engine on timeout, connection error
or malformed output, so the pipeline's latency and availability never depend
on a model server being up. Set ``ASTRASEC_LLM_PROVIDER=ollama`` and run
``ollama pull llama3.1`` to enable generative recommendations.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from ..config import settings

SYSTEM_PROMPT = (
    "You are the security intelligence module of AstraSec, an artificial immune "
    "system that protects AI applications. You are given a structured incident "
    "summary. Reply with STRICT JSON only: an array of at most 4 objects, each "
    '{"title": str, "detail": str, "priority": "low"|"medium"|"high"|"critical", '
    '"category": str}. Recommendations must be specific, actionable defensive '
    "hardening steps for the operator of the protected AI application. Never "
    "include attack instructions. No prose outside the JSON array."
)


class LLMAdvisor:
    """Thin, fault-tolerant client around an optional local LLM."""

    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None,
                 base_url: Optional[str] = None, api_key: Optional[str] = None) -> None:
        self.provider = (provider or settings.llm_provider).lower()
        self.model = model or settings.llm_model
        self.base_url = (base_url or settings.llm_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.llm_api_key
        self.timeout = settings.llm_timeout_seconds
        self._available: Optional[bool] = None
        self._last_check: float = 0.0
        self.last_error: str = ""
        self.calls = 0
        self.failures = 0

    # ------------------------------------------------------------------
    def available(self, force: bool = False) -> bool:
        """Cheap liveness probe, cached for 60 seconds."""
        if self.provider == "offline":
            return False
        now = time.time()
        if not force and self._available is not None and now - self._last_check < 60:
            return self._available
        self._last_check = now
        try:
            if self.provider == "ollama":
                r = httpx.get(f"{self.base_url}/api/tags", timeout=3.0)
                self._available = r.status_code == 200
            else:
                headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
                r = httpx.get(f"{self.base_url}/v1/models", headers=headers, timeout=3.0)
                self._available = r.status_code < 500
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._available = False
        return bool(self._available)

    # ------------------------------------------------------------------
    def generate(self, incident_summary: Dict[str, Any]) -> Optional[List[Dict[str, str]]]:
        """Return LLM recommendations, or ``None`` to signal 'use offline'."""
        if self.provider == "offline" or not self.available():
            return None

        user_prompt = json.dumps(incident_summary, indent=2, default=str)[:6000]
        self.calls += 1
        try:
            if self.provider == "ollama":
                raw = self._call_ollama(user_prompt)
            else:
                raw = self._call_openai_compatible(user_prompt)
            parsed = self._parse(raw)
            if parsed:
                return parsed
            self.failures += 1
            self.last_error = "LLM returned unparseable output"
            return None
        except Exception as exc:
            self.failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None

    def _call_ollama(self, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2, "num_predict": settings.llm_max_tokens},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }
        r = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")

    def _call_openai_compatible(self, user_prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": settings.llm_max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }
        r = httpx.post(f"{self.base_url}/v1/chat/completions", json=payload,
                       headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    # ------------------------------------------------------------------
    @staticmethod
    def _parse(raw: str) -> Optional[List[Dict[str, str]]]:
        """Parse strict-JSON output defensively.

        Model output is untrusted input like any other: it is parsed, shape-
        checked and field-clamped before a single value reaches the dashboard.
        """
        if not raw:
            return None
        text = raw.strip()
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            text = m.group(0)
        else:
            m2 = re.search(r"\{.*\}", text, re.DOTALL)
            if m2:
                text = "[" + m2.group(0) + "]"
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            for key in ("recommendations", "items", "results", "data"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            return None

        valid_priority = {"low", "medium", "high", "critical"}
        out: List[Dict[str, str]] = []
        for item in data[:4]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()[:160]
            detail = str(item.get("detail", item.get("description", ""))).strip()[:800]
            if not title or not detail:
                continue
            priority = str(item.get("priority", "medium")).strip().lower()
            if priority not in valid_priority:
                priority = "medium"
            out.append({
                "title": title,
                "detail": detail,
                "priority": priority,
                "category": str(item.get("category", "hardening")).strip()[:60] or "hardening",
            })
        return out or None

    def info(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url if self.provider != "offline" else None,
            "available": self.available(),
            "calls": self.calls,
            "failures": self.failures,
            "last_error": self.last_error or None,
        }


__all__ = ["LLMAdvisor", "SYSTEM_PROMPT"]
