"""
Email & breach exposure.
  * Format + MX validation (real, keyless)
  * Breach lookup via HaveIBeenPwned v3 (requires hibp_api_key)
When no HIBP key is present the module still returns validity + guidance,
so the screen is useful out of the box and richer once a key is added.
"""
import re
import requests

import config

try:
    import dns.resolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com",
               "tempmail.com", "trashmail.com", "yopmail.com"}


def _mx(domain):
    if not _HAS_DNS:
        return []
    try:
        r = dns.resolver.Resolver()
        r.lifetime = 6
        return sorted(str(x.exchange).rstrip(".") for x in r.resolve(domain, "MX"))
    except Exception:
        return []


def _severity_for(record_count):
    if record_count >= 100_000_000:
        return "critical"
    if record_count >= 1_000_000:
        return "medium"
    return "low"


def hibp(email):
    key = config.get("hibp_api_key")
    if not key:
        return {"configured": False,
                "note": "Add a HaveIBeenPwned API key in Settings to pull real breach records."}
    kw = config.request_kwargs()
    kw.setdefault("headers", {})
    kw["headers"]["hibp-api-key"] = key
    kw["headers"]["User-Agent"] = "Sentinel-OSINT"
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        r = requests.get(url, **kw)
        if r.status_code == 404:
            return {"configured": True, "breaches": [], "count": 0}
        if r.status_code == 200:
            breaches = []
            for b in r.json():
                pc = b.get("PwnCount", 0)
                breaches.append({
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "date": b.get("BreachDate"),
                    "records": pc,
                    "data_classes": b.get("DataClasses", [])[:6],
                    "severity": _severity_for(pc),
                })
            breaches.sort(key=lambda x: x["date"], reverse=True)
            return {"configured": True, "breaches": breaches, "count": len(breaches)}
        return {"configured": True, "error": f"HIBP HTTP {r.status_code}"}
    except Exception as e:
        return {"configured": True, "error": type(e).__name__}


def analyze(email):
    email = (email or "").strip().lower()
    valid = bool(_EMAIL_RE.match(email))
    domain = email.split("@")[-1] if "@" in email else ""
    mx = _mx(domain) if valid else []
    breach = hibp(email) if valid else {"configured": False}
    n = breach.get("count", 0)
    if breach.get("breaches"):
        worst = max((b["severity"] for b in breach["breaches"]),
                    key=lambda s: {"low": 1, "medium": 2, "critical": 3}.get(s, 0))
        risk = {"critical": "High", "medium": "Medium", "low": "Low"}.get(worst, "Low")
    else:
        risk = "Unknown" if not breach.get("configured") else "Clean"
    return {
        "selector": email,
        "type": "email",
        "valid_format": valid,
        "domain": domain,
        "mx": mx,
        "has_mx": bool(mx),
        "disposable": domain in _DISPOSABLE,
        "breach": breach,
        "risk": risk,
    }
