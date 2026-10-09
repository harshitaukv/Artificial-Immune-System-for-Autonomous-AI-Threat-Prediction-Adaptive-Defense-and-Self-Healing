"""Wiring for the Security Center: one place that owns the live objects."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from ..schemas import AppContext
from .alerts import AlertDispatcher
from .auth import OwnerAuth
from .bot import AstraBot
from .gateway import SecurityGateway
from .store import SOCStore

BOT_APP = AppContext(
    app_id="astrabot", app_name="AstraBot", model_name="llama3.1",
    system_prompt_protected=True, output_filtering_enabled=True,
    tool_calling_enabled=False, retrieval_enabled=True, pii_redaction_enabled=True,
    authentication_required=False, logging_enabled=True, rate_limiting_enabled=True,
    sandbox_enabled=True, dependencies=["fastapi", "scikit-learn", "httpx", "pdfplumber"],
    last_security_review_days=7,
)


class Runtime:
    store: Optional[SOCStore] = None
    auth: Optional[OwnerAuth] = None
    dispatcher: Optional[AlertDispatcher] = None
    gateway: Optional[SecurityGateway] = None
    bot: Optional[AstraBot] = None
    enforce_auth: bool = True

    persist_memory: bool = True

    def start(self, system, push: Optional[Callable[[Dict[str, Any]], None]] = None,
              db_path: Optional[str] = None, persist_memory: bool = True) -> "Runtime":
        self.persist_memory = persist_memory
        self.store = SOCStore(db_path)
        self.auth = OwnerAuth(self.store)
        self.dispatcher = AlertDispatcher(self.store, push)
        if system is not None:
            self.attach(system)
        return self

    def attach(self, system) -> None:
        self.gateway = SecurityGateway(system, self.store, self.dispatcher, BOT_APP)
        self.gateway.persist_memory = self.persist_memory
        self.bot = AstraBot(self.gateway, self.store)

    def stop(self) -> None:
        if self.gateway is not None and self.persist_memory:
            try:
                self.gateway.system.memory.save()
            except Exception:
                pass
        if self.store is not None:
            self.store.close()


runtime = Runtime()

__all__ = ["runtime", "Runtime", "BOT_APP"]
