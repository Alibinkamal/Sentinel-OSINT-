"""
Relationship graph — turn a case's raw findings into an entity link graph.

Each finding contributes a central node (the selector) plus edges to the
entities that finding discovered (accounts, domains, subdomains, IPs, breach
sources, GPS locations, carriers…). Nodes are de-duplicated across findings, so
selectors that share an entity become visibly connected — the core value of a
link analysis view.
"""
import db


def _add_node(nodes, nid, label, ntype):
    if not nid:
        return None
    key = f"{ntype}:{nid}".lower()
    if key not in nodes:
        nodes[key] = {"id": key, "label": str(label)[:48], "type": ntype, "degree": 0}
    return key


def _link(edges, seen, a, b, label=""):
    if not a or not b or a == b:
        return
    ek = tuple(sorted((a, b)))
    if ek in seen:
        return
    seen.add(ek)
    edges.append({"source": a, "target": b, "label": label})


def build(case_id: str) -> dict:
    case = db.get_case(case_id)
    if not case:
        return {"error": "case not found", "nodes": [], "edges": []}
    findings = db.list_findings(case_id, limit=500)

    nodes, edges, seen = {}, [], set()

    for f in findings:
        module = f["module"]
        selector = f["selector"]
        data = f.get("data") or {}

        # central node = the selector, typed by module
        stype = {"username": "handle", "email": "email", "domain": "domain",
                 "ip": "ip", "phone": "phone", "metadata": "file",
                 "archive": "url"}.get(module, "selector")
        center = _add_node(nodes, selector, selector, stype)

        if module == "username":
            for r in data.get("results", []):
                if r.get("found"):
                    n = _add_node(nodes, r["platform"] + ":" + selector, r["platform"], "account")
                    _link(edges, seen, center, n, "account")

        elif module == "email":
            dom = data.get("domain")
            if dom:
                _link(edges, seen, center, _add_node(nodes, dom, dom, "domain"), "domain")
            for b in (data.get("breach", {}) or {}).get("breaches", []):
                n = _add_node(nodes, "breach:" + (b.get("name") or ""), b.get("title") or b.get("name"), "breach")
                _link(edges, seen, center, n, "breach")

        elif module == "domain":
            for ip in (data.get("records", {}) or {}).get("A", []):
                _link(edges, seen, center, _add_node(nodes, ip, ip, "ip"), "A")
            for sub in (data.get("subdomains") or [])[:40]:
                _link(edges, seen, center, _add_node(nodes, sub, sub, "subdomain"), "sub")

        elif module == "ip":
            g = data.get("geo", {}) or {}
            if g.get("org"):
                _link(edges, seen, center, _add_node(nodes, g["org"], g["org"], "org"), "asn")
            if data.get("reverse_dns"):
                _link(edges, seen, center, _add_node(nodes, data["reverse_dns"], data["reverse_dns"], "host"), "ptr")

        elif module == "phone":
            if data.get("carrier"):
                _link(edges, seen, center, _add_node(nodes, data["carrier"], data["carrier"], "carrier"), "carrier")
            if data.get("location"):
                _link(edges, seen, center, _add_node(nodes, data["location"], data["location"], "location"), "region")

        elif module == "metadata":
            gps = data.get("gps")
            if gps:
                lbl = f"{gps['lat']},{gps['lon']}"
                _link(edges, seen, center, _add_node(nodes, lbl, lbl, "location"), "gps")
            meta = data.get("exif") or data.get("document") or {}
            author = meta.get("Author") or meta.get("author")
            if author:
                _link(edges, seen, center, _add_node(nodes, author, author, "person"), "author")

    for e in edges:
        for side in ("source", "target"):
            if e[side] in nodes:
                nodes[e[side]]["degree"] += 1

    return {
        "case_id": case_id,
        "case_name": case["name"],
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
