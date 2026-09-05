"""Classify a selector string into its OSINT type (mirrors the UI detector)."""
import re

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_DOMAIN = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.I)
_PHONE = re.compile(r"^\+?[\d][\d\s().-]{6,}$")
_MD5 = re.compile(r"^[a-f0-9]{32}$", re.I)
_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.I)
_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.I)


def classify(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "unknown"
    if _EMAIL.match(v):
        return "email"
    if _IPV4.match(v):
        return "ipv4"
    if _MD5.match(v):
        return "md5"
    if _SHA1.match(v):
        return "sha1"
    if _SHA256.match(v):
        return "sha256"
    if _PHONE.match(v) and sum(c.isdigit() for c in v) >= 7 and " " not in v.strip() or _PHONE.match(v) and v.startswith("+"):
        return "phone"
    if _DOMAIN.match(v):
        return "domain"
    return "username"
