"""
IP intelligence.
  * Geolocation + network ownership via ip-api.com (free, no key)
  * Exposed services/ports via Shodan (requires shodan_api_key)
  * Reputation via VirusTotal (requires virustotal_api_key)
"""
import socket
import requests

import config


def geolocate(ip: str) -> dict:
    url = (f"http://ip-api.com/json/{ip}"
           "?fields=status,message,country,countryCode,region,regionName,city,"
           "lat,lon,timezone,isp,org,as,reverse,query")
    kw = config.request_kwargs()
    try:
        r = requests.get(url, **kw)
        data = r.json()
        if data.get("status") == "success":
            return data
        return {"error": data.get("message", "lookup failed")}
    except Exception as e:
        return {"error": type(e).__name__}


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def shodan_host(ip: str) -> dict:
    key = config.get("shodan_api_key")
    if not key:
        return {"configured": False, "note": "Add a Shodan API key in Settings to see open ports & services."}
    kw = config.request_kwargs()
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}", **kw)
        if r.status_code == 200:
            d = r.json()
            ports = []
            for item in d.get("data", []):
                ports.append({
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product") or item.get("_shodan", {}).get("module", ""),
                    "banner": (item.get("data", "") or "").strip()[:120],
                })
            return {"configured": True, "ports": d.get("ports", []), "services": ports,
                    "os": d.get("os"), "hostnames": d.get("hostnames", [])}
        detail = ""
        try:
            detail = (r.json() or {}).get("error", "") or r.text[:200]
        except Exception:
            detail = r.text[:200]
        return {"configured": True, "error": f"Shodan HTTP {r.status_code}: {detail}",
                "key_used": (key[:4] + "…" + key[-4:]) if len(key) > 8 else "short-key"}
    except Exception as e:
        return {"configured": True, "error": type(e).__name__}


def virustotal(ip: str) -> dict:
    key = config.get("virustotal_api_key")
    if not key:
        return {"configured": False}
    kw = config.request_kwargs()
    kw.setdefault("headers", {})["x-apikey"] = key
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", **kw)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"configured": True, "stats": stats}
        return {"configured": True, "error": f"VT HTTP {r.status_code}"}
    except Exception as e:
        return {"configured": True, "error": type(e).__name__}


def analyze(ip: str) -> dict:
    ip = (ip or "").strip()
    # SSRF guard: refuse private / loopback / reserved targets
    from security import check_public_ip
    ok, reason = check_public_ip(ip)
    if not ok:
        return {"selector": ip, "type": "ipv4", "blocked": True, "error": reason}
    geo = geolocate(ip)
    return {
        "selector": ip,
        "type": "ipv4",
        "geo": geo,
        "reverse_dns": geo.get("reverse") or reverse_dns(ip),
        "shodan": shodan_host(ip),
        "reputation": virustotal(ip),
    }
