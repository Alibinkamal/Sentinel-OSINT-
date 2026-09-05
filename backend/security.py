"""
Security hardening helpers:
  * password policy
  * login rate limiting / lockout (in-memory)
  * SSRF guard (block private / reserved network targets)
  * security-headers middleware
No extra dependencies — standard library only.
"""
import re
import time
import socket
import ipaddress

from starlette.middleware.base import BaseHTTPMiddleware


# --------------------------------------------------------------- password policy
_PW_MIN = 8


def validate_password(pw: str):
    """Return (ok: bool, message: str)."""
    if pw is None or len(pw) < _PW_MIN:
        return False, f"Password must be at least {_PW_MIN} characters."
    if not re.search(r"[A-Za-z]", pw):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", pw):
        return False, "Password must contain at least one digit."
    return True, "ok"


# --------------------------------------------------------------- login limiter
class LoginRateLimiter:
    """Per-IP failed-login limiter. In-memory (single process)."""

    def __init__(self, max_fail=5, window=900, lock=900):
        self.max_fail = max_fail
        self.window = window          # count failures within this many seconds
        self.lock = lock              # lock duration after threshold
        self._state = {}              # ip -> {"fails":[ts...], "until":ts}

    def _prune(self, ip, now):
        s = self._state.get(ip)
        if not s:
            return None
        s["fails"] = [t for t in s["fails"] if now - t < self.window]
        return s

    def retry_after(self, ip):
        """Seconds the caller must wait, or 0 if allowed."""
        now = time.time()
        s = self._prune(ip, now)
        if s and s.get("until", 0) > now:
            return int(s["until"] - now)
        return 0

    def record_failure(self, ip):
        now = time.time()
        s = self._state.setdefault(ip, {"fails": [], "until": 0})
        self._prune(ip, now)
        s["fails"].append(now)
        if len(s["fails"]) >= self.max_fail:
            s["until"] = now + self.lock
            s["fails"] = []

    def record_success(self, ip):
        self._state.pop(ip, None)


login_limiter = LoginRateLimiter()


def client_ip(request) -> str:
    # honour a single proxy hop if present, else the socket peer
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --------------------------------------------------------------- SSRF guard
def _ip_is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def check_public_ip(ip_str: str):
    """(ok, reason) — for the IP-intel module."""
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "Not a valid IP address."
    if not _ip_is_public(ip_str):
        return False, "Private, loopback or reserved IP addresses are blocked."
    return True, "ok"


def check_public_host(host: str):
    """
    Resolve a hostname and ensure every address it maps to is public.
    Blocks SSRF to internal services via a hostname that resolves to a
    private/loopback IP. (ok, reason)
    """
    host = (host or "").strip().replace("https://", "").replace("http://", "").strip("/")
    host = host.split("/")[0].split(":")[0]
    if not host:
        return False, "Empty host."
    # literal IP?
    try:
        ipaddress.ip_address(host)
        return check_public_ip(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False, "Host does not resolve."
    for info in infos:
        addr = info[4][0]
        if not _ip_is_public(addr):
            return False, "Host resolves to a private/reserved address (blocked)."
    return True, "ok"


# --------------------------------------------------------------- security headers
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    CSP = (
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "object-src 'none'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'"
    )

    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("Content-Security-Policy", self.CSP)
        # HSTS is honoured only over HTTPS; harmless otherwise.
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains")
        return resp
