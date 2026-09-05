"""
Domain & DNS intelligence — real DNS resolution + subdomain discovery.

  * DNS records via dnspython (A, AAAA, MX, NS, TXT, CNAME, SOA)
  * Subdomains via crt.sh certificate-transparency logs (free, no key)
  * Mail-auth posture derived from the TXT/SPF/DMARC records
"""
import concurrent.futures as cf
import requests

import config

try:
    import dns.resolver
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolve(domain, rtype):
    out = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        answers = resolver.resolve(domain, rtype)
        for a in answers:
            out.append(a.to_text())
    except Exception:
        pass
    return out


def dns_records(domain: str) -> dict:
    if not _HAS_DNS:
        return {"error": "dnspython not installed", "records": {}}
    records = {}
    with cf.ThreadPoolExecutor(max_workers=7) as ex:
        futs = {ex.submit(_resolve, domain, rt): rt for rt in RECORD_TYPES}
        for f in cf.as_completed(futs):
            rt = futs[f]
            vals = f.result()
            if vals:
                records[rt] = vals
    return {"records": records}


def _mail_posture(records: dict) -> dict:
    txt = " ".join(records.get("TXT", [])).lower()
    dmarc = _resolve("_dmarc." + records.get("_domain", ""), "TXT") if records.get("_domain") else []
    return {
        "spf": "pass" if "v=spf1" in txt else "missing",
        "dkim": "check",  # DKIM needs a selector; flagged for manual review
        "dmarc": "pass" if any("v=dmarc1" in d.lower() for d in dmarc) else "missing",
    }


def subdomains(domain: str, limit: int = 60) -> list:
    """Pull unique subdomains from crt.sh certificate transparency."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    kw = config.request_kwargs()
    kw["timeout"] = 20
    found = set()
    try:
        r = requests.get(url, **kw)
        if r.status_code == 200 and r.text.strip():
            for entry in r.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain) and "@" not in name:
                        found.add(name)
    except Exception:
        pass
    subs = sorted(found)[:limit]
    return subs


def analyze(domain: str) -> dict:
    domain = (domain or "").strip().lower().replace("https://", "").replace("http://", "").strip("/")
    rec = dns_records(domain)
    records = rec.get("records", {})
    records["_domain"] = domain
    posture = _mail_posture(records)
    records.pop("_domain", None)
    subs = subdomains(domain)
    return {
        "selector": domain,
        "type": "domain",
        "records": records,
        "record_count": len(records),
        "mail_posture": posture,
        "subdomains": subs,
        "subdomain_count": len(subs),
    }
