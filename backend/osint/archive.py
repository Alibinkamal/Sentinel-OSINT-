"""
Archive & history — Wayback Machine (Internet Archive), free & keyless.
  * CDX API for the full capture list
  * derives snapshot density per year and a compact timeline
"""
import collections
import requests

import config


def snapshots(url: str, limit: int = 400) -> dict:
    url = (url or "").strip().replace("https://", "").replace("http://", "").strip("/")
    cdx = (f"http://web.archive.org/cdx/search/cdx?url={url}"
           f"&output=json&fl=timestamp,original,statuscode,digest&collapse=digest&limit={limit}")
    kw = config.request_kwargs()
    kw["timeout"] = 20
    caps = []
    try:
        r = requests.get(cdx, **kw)
        rows = r.json() if r.status_code == 200 and r.text.strip() else []
        for row in rows[1:]:  # first row is the header
            ts = row[0]
            caps.append({
                "timestamp": ts,
                "date": f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}",
                "original": row[1],
                "status": row[2] if len(row) > 2 else "",
                "wayback": f"https://web.archive.org/web/{ts}/{row[1]}",
            })
    except Exception:
        pass

    per_year = collections.Counter(c["date"][:4] for c in caps)
    first = caps[0]["date"] if caps else None
    last = caps[-1]["date"] if caps else None
    return {
        "selector": url,
        "type": "archive",
        "total": len(caps),
        "first_capture": first,
        "last_capture": last,
        "per_year": dict(sorted(per_year.items())),
        "recent": caps[-15:][::-1],
    }
