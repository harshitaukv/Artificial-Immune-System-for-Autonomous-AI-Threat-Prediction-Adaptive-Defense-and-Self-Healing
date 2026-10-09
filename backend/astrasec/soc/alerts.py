"""Owner alerts.

An alert tells the application owner that something happened and where to
look. It deliberately does **not** carry the offending prompt or file content:
alerts travel over email and chat webhooks, which are exactly the places a
leaked secret or a working jailbreak should not end up. The full (redacted)
evidence stays in the Security Center behind the owner login.

Delivery:

* **In-app** — always. Stored, counted as unread, pushed live to any open
  dashboard over the WebSocket (which also raises a browser notification).
* **Email** — optional, SMTP with STARTTLS.
* **Webhook** — optional; Slack, Discord or generic JSON.

Email and webhook delivery run on a worker thread, so a slow mail server can
never delay a chat reply. Each alert records what happened on every channel.
"""
from __future__ import annotations

import re
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from typing import Any, Callable, Dict, Optional

import httpx

from .policy import AlertChannels
from .store import SOCStore

SEVERITY_HEADLINE = {
    "critical": "CRITICAL SECURITY ALERT",
    "high": "HIGH-RISK SECURITY ALERT",
    "medium": "SECURITY ALERT",
    "low": "Security notice",
}


def _clean(s: Any, limit: int = 80) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


class AlertDispatcher:
    def __init__(self, store: SOCStore, push: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.store = store
        self.push = push

    def channels(self) -> AlertChannels:
        return AlertChannels(**(self.store.get("alert_channels") or {}))

    def raise_alert(self, *, incident: Dict[str, Any], app_name: str) -> Dict[str, Any]:
        sev = incident["severity"] if incident["severity"] in SEVERITY_HEADLINE else "high"
        threat = incident["threat_class"].replace("_", " ").title()
        source = {"prompt": "chat message", "file": "uploaded file",
                  "response": "model response", "session": "client session"}.get(
            incident["source"], incident["source"])
        lines = [
            f"Application: {_clean(app_name, 60)}",
            f"Threat: {threat}",
            f"Source: {source}" + (f" ({_clean(incident.get('file_name'), 60)})"
                                   if incident.get("file_name") else ""),
            f"Risk: {round(incident['risk'])}/100",
            f"Action: {incident['action'].replace('_', ' ').upper()}",
            f"Incident: {incident['id']}",
        ]
        alert = self.store.create_alert({
            "incident_id": incident["id"], "severity": sev,
            "title": f"{SEVERITY_HEADLINE[sev]} — {threat}",
            "message": "\n".join(lines), "app_id": incident.get("app_id"),
        })
        status: Dict[str, str] = {"in_app": "sent"}
        if self.push:
            try:
                self.push({"type": "alert", **{k: alert[k] for k in
                                               ("id", "ts", "incident_id", "severity", "title",
                                                "message")}})
            except Exception:
                pass
        cfg = self.channels()
        status["email"] = "pending" if cfg.email.enabled else "off"
        status["webhook"] = "pending" if cfg.webhook.enabled else "off"
        self.store.set_alert_channels(alert["id"], status)
        if cfg.email.enabled or cfg.webhook.enabled:
            threading.Thread(target=self._deliver, args=(alert, cfg, status), daemon=True).start()
        alert["channels"] = status
        return alert

    # ------------------------------------------------------------------
    def _deliver(self, alert: Dict[str, Any], cfg: AlertChannels, status: Dict[str, str]) -> None:
        if cfg.email.enabled:
            status["email"] = self._send_email(alert, cfg)
        if cfg.webhook.enabled:
            status["webhook"] = self._send_webhook(alert, cfg)
        try:
            self.store.set_alert_channels(alert["id"], status)
        except Exception:
            pass

    @staticmethod
    def _send_email(alert: Dict[str, Any], cfg: AlertChannels) -> str:
        e = cfg.email
        if not (e.smtp_host and e.recipient and (e.sender or e.username)):
            return "failed: SMTP host, sender and recipient are required"
        msg = EmailMessage()
        msg["Subject"] = f"[AstraSec] {alert['title']}"
        msg["From"] = e.sender or e.username
        msg["To"] = e.recipient
        msg.set_content(alert["message"] + "\n\nOpen the AstraSec Security Center for the "
                        "evidence and to update the incident.\n\n— AstraSec")
        try:
            with smtplib.SMTP(e.smtp_host, e.smtp_port, timeout=15) as s:
                if e.use_tls:
                    s.starttls(context=ssl.create_default_context())
                if e.username:
                    s.login(e.username, e.password)
                s.send_message(msg)
            return "sent"
        except Exception as exc:
            return f"failed: {type(exc).__name__}: {str(exc)[:120]}"

    @staticmethod
    def _send_webhook(alert: Dict[str, Any], cfg: AlertChannels) -> str:
        w = cfg.webhook
        text = f"🚨 *{alert['title']}*\n" + alert["message"]
        if w.format == "slack":
            payload: Dict[str, Any] = {"text": text}
        elif w.format == "discord":
            payload = {"content": text.replace("*", "**")[:1900]}
        else:
            payload = {"source": "astrasec", "alert_id": alert["id"],
                       "incident_id": alert["incident_id"], "severity": alert["severity"],
                       "title": alert["title"], "message": alert["message"], "ts": alert["ts"]}
        try:
            r = httpx.post(w.url, json=payload, timeout=10)
            return "sent" if r.status_code < 300 else f"failed: HTTP {r.status_code}"
        except Exception as exc:
            return f"failed: {type(exc).__name__}"

    def test(self) -> Dict[str, str]:
        """Send a test message on every enabled channel, synchronously."""
        cfg = self.channels()
        fake = {"id": "ALT-TEST", "incident_id": "INC-TEST", "severity": "low", "ts": time.time(),
                "title": "Test alert — channels are working",
                "message": "This is a test alert from the AstraSec Security Center."}
        out = {"in_app": "sent"}
        out["email"] = self._send_email(fake, cfg) if cfg.email.enabled else "off"
        out["webhook"] = self._send_webhook(fake, cfg) if cfg.webhook.enabled else "off"
        return out


__all__ = ["AlertDispatcher"]
