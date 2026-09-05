"""
Sentinel OSINT — FastAPI application (hardened edition).

Run:  python run.py           (from the project root)
or:   cd backend && uvicorn main:app --reload --port 8000

On first run a single Super Admin account is created and its randomly-generated
password is printed to the server console once. Sign in with it, then change the
password under Settings. No credential is hard-coded in the source.

Security: restricted CORS, security headers, login rate-limiting, password
policy, SSRF guards on network-facing modules, and a full audit log.
"""
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

import config
import db
import permissions as perm
import reporting
import security
from security import login_limiter, validate_password, SecurityHeadersMiddleware
from auth import current_user, issue_token, require_perm, identity
from osint import (username as m_username, domain_dns as m_domain, ip_intel as m_ip,
                   archive as m_archive, metadata as m_metadata, email_breach as m_email,
                   websearch as m_web, phone as m_phone, graph as m_graph, selectors)

db.init_db()

app = FastAPI(title="Sentinel OSINT", version="3.0.0")

# --- hardening middleware ---
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get_allowed_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def req_ip(request: Request) -> str:
    return security.client_ip(request)


def _audit(user, action, detail="", ip="", status="ok"):
    db.add_audit(user["username"] if isinstance(user, dict) else user, action, detail, ip, status)


# =============================================================== models
class LoginBody(BaseModel):
    username: str
    password: str


class RegisterBody(BaseModel):
    username: str
    password: str
    full_name: str = ""
    email: str = ""


class PasswordBody(BaseModel):
    new_password: str


class NewUserBody(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    full_name: str = ""
    email: str = ""


class RoleBody(BaseModel):
    role: str


class ActiveBody(BaseModel):
    active: bool


class CaseBody(BaseModel):
    name: str
    target: str = ""
    priority: str = "medium"
    notes: str = ""


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    notes: Optional[str] = None


class SearchBody(BaseModel):
    keywords: str = ""
    exact_phrase: Optional[str] = None
    sites: Optional[List[str]] = None
    exclude: Optional[List[str]] = None
    filetype: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None


def _log(case_id, module, result, selector, severity="info", summary=""):
    if case_id:
        db.add_finding(case_id, module, selector, summary=summary, data=result, severity=severity)


# =============================================================== auth
@app.post("/api/auth/login")
def login(body: LoginBody, ip: str = Depends(req_ip)):
    wait = login_limiter.retry_after(ip)
    if wait:
        db.add_audit(body.username, "login.blocked", f"rate-limited {wait}s", ip, "blocked")
        raise HTTPException(429, f"Too many attempts — try again in {wait} seconds.")
    user = db.verify_user(body.username, body.password)
    if not user:
        login_limiter.record_failure(ip)
        db.add_audit(body.username, "login.fail", "bad credentials", ip, "fail")
        raise HTTPException(401, "Invalid username or password")
    if not user.get("active", 1):
        db.add_audit(body.username, "login.inactive", "pending approval", ip, "fail")
        raise HTTPException(403, "Your account is pending administrator approval.")
    login_limiter.record_success(ip)
    ident = identity(db.get_user(body.username))
    db.add_audit(body.username, "login.ok", ident["role"], ip, "ok")
    return {"token": issue_token(user), "user": ident, "must_change_password": False}


@app.post("/api/auth/register")
def register(body: RegisterBody, ip: str = Depends(req_ip)):
    """Public self-registration. Saves the applicant's details and creates a
    read-only (viewer) account that stays INACTIVE until an admin approves it."""
    wait = login_limiter.retry_after(ip)
    if wait:
        raise HTTPException(429, f"Too many attempts — try again in {wait} seconds.")
    uname = (body.username or "").strip()
    if len(uname) < 3:
        raise HTTPException(400, "Username must be at least 3 characters.")
    ok, msg = validate_password(body.password)
    if not ok:
        raise HTTPException(400, msg)
    if db.get_user(uname):
        raise HTTPException(409, "That username is already taken.")
    db.create_user(uname, body.password, role="viewer",
                   full_name=(body.full_name or "").strip(),
                   email=(body.email or "").strip(), active=0)
    db.add_audit(uname, "register", f"{body.full_name} <{body.email}>", ip, "ok")
    return {"ok": True, "pending": True,
            "message": "Registration saved. An administrator must approve your account before you can sign in."}


@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return user


@app.post("/api/auth/password")
def set_password(body: PasswordBody, ip: str = Depends(req_ip), user=Depends(current_user)):
    ok, msg = validate_password(body.new_password)
    if not ok:
        raise HTTPException(400, msg)
    db.change_password(user["username"], body.new_password)
    _audit(user, "password.change", user["username"], ip)
    return {"ok": True}


# =============================================================== users & roles (RBAC)
@app.get("/api/roles")
def roles(_=Depends(require_perm("roles:view"))):
    return perm.matrix()


@app.get("/api/users")
def users(_=Depends(require_perm("users:view"))):
    out = []
    for u in db.list_users():
        r = u["role"]
        out.append({**u, "role_label": perm.ROLES.get(r, {}).get("label", r),
                    "level": perm.role_level(r)})
    return out


def _can_touch_role(actor: dict, target_role: str):
    if target_role in perm.ELEVATED_ROLES and "users:manage_admins" not in actor["permissions"]:
        raise HTTPException(403, "Only a Super Admin can manage admin-level accounts")
    if target_role not in perm.ROLES:
        raise HTTPException(400, f"Unknown role '{target_role}'")


@app.post("/api/users")
def add_user(body: NewUserBody, ip: str = Depends(req_ip), actor=Depends(require_perm("users:manage"))):
    _can_touch_role(actor, body.role)
    ok, msg = validate_password(body.password)
    if not ok:
        raise HTTPException(400, msg)
    if db.get_user(body.username):
        raise HTTPException(409, "User already exists")
    u = db.create_user(body.username, body.password, body.role,
                       full_name=body.full_name, email=body.email, active=1)
    _audit(actor, "user.create", f"{body.username} ({body.role})", ip)
    return {**u, "role_label": perm.ROLES[body.role]["label"]}


@app.patch("/api/users/{username}/role")
def change_role(username: str, body: RoleBody, ip: str = Depends(req_ip),
                actor=Depends(require_perm("users:manage"))):
    target = db.get_user(username)
    if not target:
        raise HTTPException(404, "User not found")
    _can_touch_role(actor, target["role"])
    _can_touch_role(actor, body.role)
    if target["role"] == "superadmin" and body.role != "superadmin" and db.count_role("superadmin") <= 1:
        raise HTTPException(400, "Cannot demote the last Super Admin")
    db.update_user_role(username, body.role)
    _audit(actor, "user.role", f"{username} -> {body.role}", ip)
    return {"ok": True, "username": username, "role": body.role}


@app.patch("/api/users/{username}/active")
def set_active(username: str, body: ActiveBody, ip: str = Depends(req_ip),
               actor=Depends(require_perm("users:manage"))):
    target = db.get_user(username)
    if not target:
        raise HTTPException(404, "User not found")
    _can_touch_role(actor, target["role"])
    db.set_user_active(username, body.active)
    _audit(actor, "user.active", f"{username} = {'active' if body.active else 'disabled'}", ip)
    return {"ok": True, "username": username, "active": body.active}


@app.delete("/api/users/{username}")
def remove_user(username: str, ip: str = Depends(req_ip), actor=Depends(require_perm("users:manage"))):
    target = db.get_user(username)
    if not target:
        raise HTTPException(404, "User not found")
    if username == actor["username"]:
        raise HTTPException(400, "You cannot delete your own account")
    _can_touch_role(actor, target["role"])
    if target["role"] == "superadmin" and db.count_role("superadmin") <= 1:
        raise HTTPException(400, "Cannot delete the last Super Admin")
    db.delete_user(username)
    _audit(actor, "user.delete", username, ip)
    return {"ok": True}


# =============================================================== audit log
@app.get("/api/audit")
def audit_log(limit: int = 200, _=Depends(require_perm("audit:view"))):
    return db.list_audit(min(max(limit, 1), 500))


# =============================================================== dashboard
@app.get("/api/dashboard")
def dashboard(user=Depends(require_perm("dashboard:view"))):
    s = db.stats()
    s["cases_count"] = s.pop("cases", 0)
    s["recent_findings"] = db.list_findings(limit=8)
    s["recent_cases"] = db.list_cases()[:6]
    return s


# =============================================================== OSINT modules
@app.get("/api/detect")
def detect(q: str, user=Depends(current_user)):
    return {"selector": q, "type": selectors.classify(q)}


@app.post("/api/scan/username")
def scan_username(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    handle, cid = payload.get("username", ""), payload.get("case_id")
    res = m_username.scan(handle)
    _log(cid, "username", res, handle, "medium" if res["found"] >= 5 else "info",
         f"{res['found']}/{res['checked']} platforms")
    _audit(user, "scan.username", handle, ip)
    return res


@app.post("/api/scan/email")
def scan_email(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    email, cid = payload.get("email", ""), payload.get("case_id")
    res = m_email.analyze(email)
    _log(cid, "email", res, email, {"High": "critical", "Medium": "medium"}.get(res.get("risk"), "info"),
         f"risk={res.get('risk')}")
    _audit(user, "scan.email", email, ip)
    return res


@app.post("/api/scan/phone")
def scan_phone(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    number, cid = payload.get("phone", ""), payload.get("case_id")
    res = m_phone.analyze(number, payload.get("region"))
    _log(cid, "phone", res, number, "info", f"{res.get('line_type','')} · {res.get('region','')}")
    _audit(user, "scan.phone", number, ip)
    return res


@app.post("/api/scan/domain")
def scan_domain(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    domain, cid = payload.get("domain", ""), payload.get("case_id")
    res = m_domain.analyze(domain)
    _log(cid, "domain", res, domain, "info", f"{res['subdomain_count']} subdomains")
    _audit(user, "scan.domain", domain, ip)
    return res


@app.post("/api/scan/ip")
def scan_ip(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    target, cid = payload.get("ip", ""), payload.get("case_id")
    res = m_ip.analyze(target)
    if not res.get("blocked"):
        _log(cid, "ip", res, target, "info", res.get("geo", {}).get("org", ""))
    _audit(user, "scan.ip", target, ip, "blocked" if res.get("blocked") else "ok")
    return res


@app.post("/api/scan/archive")
def scan_archive(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    url, cid = payload.get("url", ""), payload.get("case_id")
    res = m_archive.snapshots(url)
    _log(cid, "archive", res, url, "info", f"{res['total']} captures")
    _audit(user, "scan.archive", url, ip)
    return res


@app.post("/api/scan/metadata")
async def scan_metadata(request: Request, file: UploadFile = File(...), case_id: str = Form(None),
                        user=Depends(require_perm("scan:run"))):
    raw = await file.read()
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(413, "File too large (max 25 MB)")
    res = m_metadata.extract(file.filename, raw)
    _log(case_id, "metadata", res, file.filename,
         "critical" if res.get("gps") else "info",
         "GPS leak" if res.get("gps") else res.get("kind", ""))
    _audit(user, "scan.metadata", file.filename, security.client_ip(request))
    return res


@app.post("/api/scan/websearch")
def scan_web(body: SearchBody, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    _audit(user, "scan.websearch", body.keywords, ip)
    return m_web.search(**body.dict())


@app.post("/api/scan/siteindex")
def scan_siteindex(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("scan:run"))):
    domain = payload.get("domain", "")
    res = m_web.site_index(domain)
    _audit(user, "scan.siteindex", domain, ip, "blocked" if res.get("blocked") else "ok")
    return res


# =============================================================== graph
@app.get("/api/cases/{cid}/graph")
def case_graph(cid: str, user=Depends(require_perm("graph:view"))):
    return m_graph.build(cid)


# =============================================================== cases
@app.get("/api/cases")
def cases(user=Depends(require_perm("cases:view"))):
    return db.list_cases()


@app.post("/api/cases")
def new_case(body: CaseBody, ip: str = Depends(req_ip), user=Depends(require_perm("cases:create"))):
    c = db.create_case(body.name, body.target, body.priority, user["username"], body.notes)
    _audit(user, "case.create", f"{c['id']} {body.name}", ip)
    return c


@app.get("/api/cases/{cid}")
def case_detail(cid: str, user=Depends(require_perm("cases:view"))):
    c = db.get_case(cid)
    if not c:
        raise HTTPException(404, "Case not found")
    c["findings"] = db.list_findings(cid)
    return c


@app.patch("/api/cases/{cid}")
def edit_case(cid: str, body: CaseUpdate, ip: str = Depends(req_ip), user=Depends(require_perm("cases:edit"))):
    _audit(user, "case.edit", cid, ip)
    return db.update_case(cid, **body.dict())


@app.delete("/api/cases/{cid}")
def remove_case(cid: str, ip: str = Depends(req_ip), user=Depends(require_perm("cases:delete"))):
    db.delete_case(cid)
    _audit(user, "case.delete", cid, ip)
    return {"ok": True}


# =============================================================== reports
@app.get("/api/cases/{cid}/report")
def case_report(cid: str, format: str = "json", ip: str = Depends(req_ip),
                user=Depends(require_perm("reports:generate"))):
    c = db.get_case(cid)
    if not c:
        raise HTTPException(404, "Case not found")
    c["findings"] = db.list_findings(cid)
    _audit(user, "report.export", f"{cid} ({format})", ip)

    if format == "pdf":
        try:
            pdf = reporting.case_pdf(c)
        except RuntimeError as e:
            raise HTTPException(501, str(e))
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{cid}_report.pdf"'})

    if format == "html":
        rows = "".join(
            f"<tr><td>{f['module']}</td><td>{f['selector']}</td>"
            f"<td>{f['summary']}</td><td>{f['severity']}</td></tr>" for f in c["findings"])
        html = f"""<!doctype html><meta charset=utf-8><title>Report {cid}</title>
        <style>body{{font-family:system-ui;margin:40px;color:#111}}h1{{margin:0}}
        .sub{{color:#666}}table{{border-collapse:collapse;width:100%;margin-top:20px}}
        th,td{{border:1px solid #ddd;padding:8px;text-align:left;font-size:13px}}th{{background:#f4f4f5}}</style>
        <h1>{c['name']}</h1><div class=sub>Case {cid} · target {c.get('target') or '—'} ·
        status {c['status']} · {len(c['findings'])} findings</div>
        <table><thead><tr><th>Module</th><th>Selector</th><th>Summary</th><th>Severity</th></tr></thead>
        <tbody>{rows or '<tr><td colspan=4>No findings yet</td></tr>'}</tbody></table>"""
        return JSONResponse({"html": html, "case": c})

    return JSONResponse(c)


# =============================================================== settings
def _mask(v):
    if not v:
        return ""
    return v[:4] + "…" + v[-2:] if len(v) > 7 else "•••"


@app.get("/api/settings")
def get_settings(_=Depends(require_perm("settings:manage"))):
    s = config.get_settings()
    out = dict(s)
    for k in config.KEY_FIELDS:
        out[k] = _mask(s.get(k))
        out[k + "_set"] = bool(s.get(k))
    return out


@app.post("/api/settings")
def save_settings(payload: dict, ip: str = Depends(req_ip), user=Depends(require_perm("settings:manage"))):
    clean = {k: v for k, v in payload.items()
             if k in config.CONFIG_FIELDS and (v not in ("", None) or k not in config.KEY_FIELDS)}
    config.save_settings(clean)
    _audit(user, "settings.save", ",".join(clean.keys()), ip)
    return {"ok": True}


# =============================================================== frontend
if config.FRONTEND_DIR.exists():
    @app.get("/")
    def index():
        return FileResponse(config.FRONTEND_DIR / "index.html")

    app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIR), html=True), name="static")
