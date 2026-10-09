"""Owner authentication for the Security Center.

The chatbot is public; the Security Center is not. It shows other people's
(redacted) messages, the incident record and the controls that decide what
reaches the model, so it sits behind an owner password.

* The password is stored as PBKDF2-HMAC-SHA256 (310,000 iterations, random
  salt). It is never logged or returned.
* A session is an HMAC-signed token in an ``HttpOnly``, ``SameSite=Strict``
  cookie, valid for 12 hours. Changing the password rotates the signing key,
  which ends every existing session at once.
* Five failed logins from one address in five minutes locks that address out
  for five minutes.
* Until a password is set, the Security Center is reachable **only from this
  computer** (loopback), so a fresh install is never open on the network.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from .store import SOCStore

COOKIE = "astrasec_owner"
TOKEN_TTL = 12 * 3600
ITERATIONS = 310_000


def is_loopback(host: Optional[str]) -> bool:
    if not host:
        return False
    if host in ("localhost", "testclient"):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


class OwnerAuth:
    def __init__(self, store: SOCStore) -> None:
        self.store = store
        self._fails: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        env = os.environ.get("ASTRASEC_OWNER_PASSWORD", "")
        if env and not self.configured():
            self.set_password(env)

    # ------------------------------------------------------------ password
    def configured(self) -> bool:
        return bool(self.store.get("owner"))

    def set_password(self, password: str) -> None:
        ok, why = self.password_ok(password)
        if not ok:
            raise ValueError(why)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
        self.store.put("owner", {"salt": salt.hex(), "hash": digest.hex(),
                                 "iterations": ITERATIONS, "set_at": time.time()})
        self.store.put("token_key", secrets.token_hex(32))     # rotate: ends all sessions

    @staticmethod
    def password_ok(pw: str) -> Tuple[bool, str]:
        if len(pw or "") < 8:
            return False, "Use at least 8 characters."
        if len(pw) > 256:
            return False, "That password is too long."
        if pw.lower() in {"password", "12345678", "password1", "astrasec", "qwertyui", "admin123"}:
            return False, "That password is too common."
        return True, ""

    def check_password(self, password: str) -> bool:
        rec = self.store.get("owner")
        if not rec:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", (password or "").encode(),
                                     bytes.fromhex(rec["salt"]), int(rec["iterations"]))
        return hmac.compare_digest(digest.hex(), rec["hash"])

    # ------------------------------------------------------------ lockout
    def locked_out(self, ip: str) -> bool:
        q = self._fails[ip]
        now = time.time()
        while q and now - q[0] > 300:
            q.popleft()
        return len(q) >= 5

    def record_failure(self, ip: str) -> None:
        self._fails[ip].append(time.time())

    def clear_failures(self, ip: str) -> None:
        self._fails.pop(ip, None)

    # ------------------------------------------------------------ tokens
    def _key(self) -> bytes:
        key = self.store.get("token_key")
        if not key:
            key = secrets.token_hex(32)
            self.store.put("token_key", key)
        return bytes.fromhex(key)

    def issue(self) -> str:
        payload = f"{int(time.time()) + TOKEN_TTL}.{secrets.token_hex(8)}"
        sig = hmac.new(self._key(), payload.encode(), hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=") + "." + sig

    def verify(self, token: Optional[str]) -> bool:
        if not token or token.count(".") != 1:
            return False
        b64, sig = token.split(".")
        try:
            payload = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).decode()
            exp = int(payload.split(".")[0])
        except Exception:
            return False
        good = hmac.new(self._key(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(good, sig) and exp > time.time()

    def logout_everywhere(self) -> None:
        self.store.put("token_key", secrets.token_hex(32))


__all__ = ["OwnerAuth", "COOKIE", "TOKEN_TTL", "is_loopback"]
