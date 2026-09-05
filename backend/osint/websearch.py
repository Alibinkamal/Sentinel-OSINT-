"""
Web search + site index inspection.
  * DuckDuckGo Instant Answer API (keyless) for quick related results
  * Advanced query builder (site:, filetype:, exact phrase, date range, exclude)
  * Site index inspection: sitemap.xml + robots.txt
This is the module carried over from the original tool, cleaned up.
"""
import re
import requests

import config


def build_query(keywords="", exact_phrase=None, sites=None, exclude=None,
                filetype=None, date_from=None, date_to=None):
    parts = []
    if keywords:
        parts.append(keywords)
    if exact_phrase:
        parts.append(f'"{exact_phrase}"')
    if sites:
        site_terms = [f"site:{s}" for s in sites if s]
        if site_terms:
            parts.append("(" + " OR ".join(site_terms) + ")")
    for x in (exclude or []):
        if x:
            parts.append(f"-{x}")
    if filetype:
        parts.append(f"filetype:{filetype}")
    if date_from:
        parts.append(f"after:{date_from}")
    if date_to:
        parts.append(f"before:{date_to}")
    return " ".join(parts).strip()


def duckduckgo(query, max_results=15):
    kw = config.request_kwargs()
    params = {"q": query, "format": "json", "no_redirect": 1, "no_html": 1}
    results = []
    try:
        r = requests.get("https://api.duckduckgo.com/", params=params, **kw)
        data = r.json()
        if data.get("AbstractURL"):
            results.append({"title": data.get("Heading", query),
                            "url": data["AbstractURL"],
                            "snippet": data.get("AbstractText", "")})
        for topic in data.get("RelatedTopics", []):
            if "FirstURL" in topic:
                results.append({"title": topic.get("Text", "")[:120],
                                "url": topic["FirstURL"],
                                "snippet": topic.get("Text", "")})
            elif "Topics" in topic:
                for t in topic["Topics"]:
                    if "FirstURL" in t:
                        results.append({"title": t.get("Text", "")[:120],
                                        "url": t["FirstURL"],
                                        "snippet": t.get("Text", "")})
            if len(results) >= max_results:
                break
    except Exception:
        pass
    return results[:max_results]


def site_index(domain):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    # SSRF guard: the server fetches this host directly, so block internal targets
    from security import check_public_host
    ok, reason = check_public_host(domain)
    if not ok:
        return {"blocked": True, "error": reason, "sitemap_urls": [], "sitemap_count": 0, "robots": {}}
    base = f"https://{domain}"
    kw = config.request_kwargs()
    urls, robots = [], {}
    for sm in (f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"):
        try:
            r = requests.get(sm, **kw)
            if r.status_code == 200:
                urls = re.findall(r"<loc>([^<]+)</loc>", r.text)[:100]
                if urls:
                    break
        except Exception:
            continue
    try:
        r = requests.get(f"{base}/robots.txt", **kw)
        if r.status_code == 200:
            robots = {
                "allow": re.findall(r"Allow:\s*(.+)", r.text)[:20],
                "disallow": re.findall(r"Disallow:\s*(.+)", r.text)[:20],
            }
    except Exception:
        pass
    return {"sitemap_urls": urls, "sitemap_count": len(urls), "robots": robots}


def search(keywords="", exact_phrase=None, sites=None, exclude=None,
           filetype=None, date_from=None, date_to=None, max_results=15):
    query = build_query(keywords, exact_phrase, sites, exclude, filetype, date_from, date_to)
    return {
        "type": "websearch",
        "query": query,
        "results": duckduckgo(query, max_results),
    }
