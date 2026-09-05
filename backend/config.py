"""
Central configuration + API-key management.

Secrets are read from (in order of precedence):
  1. data/settings.json   (editable live from the Settings screen)
  2. environment variables (.env)
  3. built-in defaults

Nothing here is required to run — every OSINT module degrades gracefully
when a key is missing.
"""
import os
import json
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SETTINGS_FILE = DATA_DIR / "settings.json"
DB_FILE = DATA_DIR / "sentinel.db"
FRONTEND_DIR = BASE_DIR / "frontend"

# JWT secret — persisted so tokens survive restarts
_SECRET_FILE = DATA_DIR / ".jwt_secret"
if _SECRET_FILE.exists():
    JWT_SECRET = _SECRET_FILE.read_text().strip()
else:
    JWT_SECRET = secrets.token_hex(32)
    _SECRET_FILE.write_text(JWT_SECRET)

JWT_ALG = "HS256"
JWT_TTL_HOURS = 12

# Keys that the Settings screen can manage
KEY_FIELDS = [
    "hibp_api_key",       # HaveIBeenPwned  (email breaches)
    "shodan_api_key",     # Shodan          (exposed services / ports)
    "virustotal_api_key", # VirusTotal      (IP / domain reputation)
]
CONFIG_FIELDS = KEY_FIELDS + ["http_proxy", "request_timeout", "user_agent"]

_DEFAULTS = {
    "hibp_api_key": "",
    "shodan_api_key": "",
    "virustotal_api_key": "",
    "http_proxy": "",
    "request_timeout": 12,
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
}


def _load_file() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def get_settings() -> dict:
    """Merged settings (file > env > defaults). API keys are returned masked=False here;
    the API layer masks them before sending to the browser."""
    merged = dict(_DEFAULTS)
    for k in CONFIG_FIELDS:
        env = os.environ.get(k.upper())
        if env:
            merged[k] = env
    merged.update({k: v for k, v in _load_file().items() if k in CONFIG_FIELDS})
    return merged


def get(key: str, default=None):
    return get_settings().get(key, default)


def save_settings(update: dict) -> dict:
    current = _load_file()
    for k, v in update.items():
        if k in CONFIG_FIELDS:
            current[k] = v
    SETTINGS_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return get_settings()


def get_allowed_origins() -> list:
    """CORS allow-list. Same-origin by default; override with ALLOWED_ORIGINS
    (comma-separated) for a hosted deployment."""
    env = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if env:
        return [o.strip() for o in env.split(",") if o.strip()]
    port = os.environ.get("PORT", "8000")
    return [f"http://localhost:{port}", f"http://127.0.0.1:{port}",
            "http://localhost:8000", "http://127.0.0.1:8000"]


def request_kwargs() -> dict:
    """Common kwargs for every outbound requests call."""
    s = get_settings()
    kw = {
        "timeout": int(s.get("request_timeout") or 12),
        "headers": {"User-Agent": s.get("user_agent")},
    }
    proxy = s.get("http_proxy")
    if proxy:
        kw["proxies"] = {"http": proxy, "https": proxy}
    return kw
