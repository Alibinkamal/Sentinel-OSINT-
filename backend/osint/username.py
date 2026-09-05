"""
Username enumeration — check a handle across many platforms concurrently.

Detection strategy per platform:
  * "status"  -> profile exists if final status == 200 (and != known-404)
  * "message" -> profile is missing if a marker string appears in the body
This mirrors how Sherlock-class tools cut false positives.
"""
import concurrent.futures as cf
import requests

import config

# name, url template, method, absence-marker (if this text is in body -> NOT found)
PLATFORMS = [
    ("GitHub",      "https://github.com/{u}",              "status", None),
    ("GitLab",      "https://gitlab.com/{u}",              "status", None),
    ("Twitter/X",   "https://twitter.com/{u}",             "status", None),
    ("Instagram",   "https://www.instagram.com/{u}/",      "status", None),
    ("Reddit",      "https://www.reddit.com/user/{u}",     "message", "nobody on Reddit goes by that name"),
    ("TikTok",      "https://www.tiktok.com/@{u}",         "status", None),
    ("YouTube",     "https://www.youtube.com/@{u}",        "status", None),
    ("Twitch",      "https://www.twitch.tv/{u}",           "status", None),
    ("Pinterest",   "https://www.pinterest.com/{u}/",      "status", None),
    ("Telegram",    "https://t.me/{u}",                    "message", "tgme_page_title"),
    ("Medium",      "https://medium.com/@{u}",             "status", None),
    ("Steam",       "https://steamcommunity.com/id/{u}",   "message", "The specified profile could not be found"),
    ("Keybase",     "https://keybase.io/{u}",              "status", None),
    ("HackerNews",  "https://news.ycombinator.com/user?id={u}", "message", "No such user."),
    ("Replit",      "https://replit.com/@{u}",             "status", None),
    ("DevTo",       "https://dev.to/{u}",                  "status", None),
    ("Vimeo",       "https://vimeo.com/{u}",               "status", None),
    ("SoundCloud",  "https://soundcloud.com/{u}",          "status", None),
    ("About.me",    "https://about.me/{u}",                "status", None),
    ("Gravatar",    "https://en.gravatar.com/{u}",         "status", None),
]


def _check(entry, user):
    name, tmpl, mode, marker = entry
    url = tmpl.format(u=user)
    kw = config.request_kwargs()
    kw["timeout"] = min(kw["timeout"], 8)
    kw["headers"] = dict(kw["headers"])
    kw["headers"]["Accept"] = "text/html,application/xhtml+xml"
    result = {"platform": name, "url": url, "found": False, "status": None, "error": None}
    try:
        r = requests.get(url, allow_redirects=True, **kw)
        result["status"] = r.status_code
        if mode == "status":
            result["found"] = r.status_code == 200
        else:  # message-based
            if r.status_code == 200:
                result["found"] = (marker or "").lower() not in r.text.lower()
            else:
                result["found"] = False
    except requests.exceptions.RequestException as e:
        result["error"] = type(e).__name__
    return result


def scan(username: str, max_workers: int = 12) -> dict:
    username = (username or "").strip()
    results = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_check, p, username) for p in PLATFORMS]
        for f in cf.as_completed(futs):
            results.append(f.result())
    # keep platform order stable
    order = {p[0]: i for i, p in enumerate(PLATFORMS)}
    results.sort(key=lambda r: order.get(r["platform"], 99))
    found = [r for r in results if r["found"]]
    return {
        "selector": username,
        "type": "username",
        "checked": len(results),
        "found": len(found),
        "results": results,
    }
