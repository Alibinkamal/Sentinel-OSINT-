"""
Role-Based Access Control (RBAC).

Four built-in roles, ordered by privilege level. Each role maps to a set of
fine-grained permissions. The API enforces permissions (not role names), and
the UI hides/greys anything the signed-in user lacks.
"""

# --- fine-grained capabilities -------------------------------------------------
PERMISSIONS = [
    ("dashboard:view",     "View the overview dashboard"),
    ("scan:run",           "Run collection scans (all modules)"),
    ("cases:view",         "View cases and findings"),
    ("cases:create",       "Create cases"),
    ("cases:edit",         "Edit cases and log findings"),
    ("cases:delete",       "Delete cases"),
    ("graph:view",         "View the relationship graph"),
    ("reports:generate",   "Generate / export reports"),
    ("settings:manage",    "Manage API keys & request settings"),
    ("users:view",         "View the user directory"),
    ("users:manage",       "Create / edit / delete analysts & viewers"),
    ("users:manage_admins", "Create / edit / delete admins & superadmins"),
    ("roles:view",         "View the roles & permissions matrix"),
    ("audit:view",         "View the audit log (activity trail)"),
]
ALL_PERMS = {p for p, _ in PERMISSIONS}

# --- roles ---------------------------------------------------------------------
ROLES = {
    "superadmin": {
        "label": "Super Admin",
        "level": 100,
        "desc": "Unrestricted. Manages every user, role, key and case.",
        "permissions": set(ALL_PERMS),
    },
    "admin": {
        "label": "Administrator",
        "level": 80,
        "desc": "Runs the platform: users, keys, and all investigations.",
        "permissions": {
            "dashboard:view", "scan:run", "cases:view", "cases:create",
            "cases:edit", "cases:delete", "graph:view", "reports:generate",
            "settings:manage", "users:view", "users:manage", "roles:view",
            "audit:view",
        },
    },
    "analyst": {
        "label": "Analyst",
        "level": 50,
        "desc": "Runs scans, builds cases and reports. No user or key admin.",
        "permissions": {
            "dashboard:view", "scan:run", "cases:view", "cases:create",
            "cases:edit", "cases:delete", "graph:view", "reports:generate",
        },
    },
    "viewer": {
        "label": "Viewer",
        "level": 10,
        "desc": "Read-only. Sees cases, findings, graph and reports.",
        "permissions": {
            "dashboard:view", "cases:view", "graph:view", "reports:generate",
        },
    },
}
ROLE_ORDER = ["superadmin", "admin", "analyst", "viewer"]

# roles that count as "elevated" — only a user with users:manage_admins may
# create, modify or delete accounts holding one of these.
ELEVATED_ROLES = {"admin", "superadmin"}


def perms_for(role: str) -> set:
    return ROLES.get(role, {}).get("permissions", set())


def has_perm(role: str, perm: str) -> bool:
    return perm in perms_for(role)


def role_level(role: str) -> int:
    return ROLES.get(role, {}).get("level", 0)


def matrix() -> dict:
    """Serializable role/permission matrix for the UI."""
    return {
        "permissions": [{"key": k, "label": v} for k, v in PERMISSIONS],
        "roles": [
            {
                "key": r,
                "label": ROLES[r]["label"],
                "level": ROLES[r]["level"],
                "desc": ROLES[r]["desc"],
                "permissions": sorted(ROLES[r]["permissions"]),
            }
            for r in ROLE_ORDER
        ],
    }
