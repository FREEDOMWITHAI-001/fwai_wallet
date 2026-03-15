"""Policy Agent — Rate limiting, quotas, content scanning, analytics."""

import re
import time
from datetime import datetime, timezone, timedelta

from extensions import db
from models import Secret, Tag, User, AuditLog, PolicyConfig


# ---------------------------------------------------------------------------
# In-memory rate limiting (per-process; sufficient for single-server deploys)
# ---------------------------------------------------------------------------
_rate_limit_store: dict[str, list[float]] = {}

# Defaults
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = {
    "secret_create": 20,
    "secret_edit": 30,
    "login_attempt": 10,
    "tag_create": 30,
}


def check_rate_limit(user_id: int, action: str) -> tuple[bool, str]:
    """Return (allowed, message). Prunes old entries automatically."""
    key = f"{user_id}:{action}"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    timestamps = _rate_limit_store.get(key, [])
    timestamps = [t for t in timestamps if t > window_start]

    max_allowed = RATE_LIMIT_MAX.get(action, 30)
    if len(timestamps) >= max_allowed:
        return False, f"Rate limit exceeded for {action}. Please wait and try again."

    timestamps.append(now)
    _rate_limit_store[key] = timestamps
    return True, ""


# ---------------------------------------------------------------------------
# Quotas
# ---------------------------------------------------------------------------
DEFAULT_SECRET_QUOTA = 100
DEFAULT_TAG_QUOTA = 50


def get_user_quota(user_id: int) -> dict:
    """Return quota info for a user."""
    secret_count = Secret.query.filter_by(owner_id=user_id).count()
    return {
        "secrets_used": secret_count,
        "secrets_max": DEFAULT_SECRET_QUOTA,
        "secrets_remaining": max(0, DEFAULT_SECRET_QUOTA - secret_count),
    }


def check_quota(user_id: int, resource: str = "secrets") -> tuple[bool, str]:
    """Check if user is within quota. Returns (allowed, message)."""
    quota = get_user_quota(user_id)
    if resource == "secrets" and quota["secrets_remaining"] <= 0:
        return False, f"Secret quota reached ({quota['secrets_max']}). Delete unused secrets to free up space."
    return True, ""


# ---------------------------------------------------------------------------
# Content scanning
# ---------------------------------------------------------------------------
_CREDENTIAL_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"ghp_[A-Za-z0-9_]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "API Secret Key"),
]


def validate_secret_content(fields: list[tuple[str, str]]) -> list[str]:
    """Scan field values for accidental credential patterns. Returns warnings (not blockers)."""
    warnings = []
    for fname, fvalue in fields:
        for pattern, label in _CREDENTIAL_PATTERNS:
            if pattern.search(fvalue):
                warnings.append(f"Field '{fname}' appears to contain a {label}. Make sure this is intentional.")
                break
    return warnings


# ---------------------------------------------------------------------------
# Tag policy
# ---------------------------------------------------------------------------
TAG_NAME_MAX_LENGTH = 50
TAG_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9\-_.]*$")


def check_tag_policy(tag_name: str) -> tuple[bool, str]:
    """Validate a tag name against naming policy."""
    name = tag_name.strip().lower()
    if not name:
        return False, "Tag name cannot be empty."
    if len(name) > TAG_NAME_MAX_LENGTH:
        return False, f"Tag name must be {TAG_NAME_MAX_LENGTH} characters or fewer."
    if not TAG_NAME_PATTERN.match(name):
        return False, "Tag name must start with a letter or number and contain only lowercase letters, numbers, hyphens, underscores, and dots."
    return True, ""


# ---------------------------------------------------------------------------
# Expiration warnings
# ---------------------------------------------------------------------------
ROTATION_THRESHOLD_DAYS = 90


def get_expiration_warnings(user_id: int) -> list[dict]:
    """Flag secrets older than the rotation threshold."""
    threshold = datetime.now(timezone.utc) - timedelta(days=ROTATION_THRESHOLD_DAYS)
    old_secrets = Secret.query.filter(
        Secret.owner_id == user_id,
        Secret.updated_at < threshold,
    ).order_by(Secret.updated_at.asc()).all()
    return [
        {"secret_id": s.id, "name": s.name, "days_old": (datetime.now(timezone.utc) - s.updated_at).days}
        for s in old_secrets
    ]


# ---------------------------------------------------------------------------
# Dashboard stats (admin)
# ---------------------------------------------------------------------------
def get_dashboard_stats(user_id: int | None = None) -> dict:
    """Analytics for admin dashboard."""
    total_secrets = Secret.query.count()
    total_users = User.query.count()
    total_tags = Tag.query.count()
    public_secrets = Secret.query.filter_by(visibility="public").count()
    private_secrets = Secret.query.filter_by(visibility="private").count()
    recent_audits = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()

    stats = {
        "total_secrets": total_secrets,
        "total_users": total_users,
        "total_tags": total_tags,
        "public_secrets": public_secrets,
        "private_secrets": private_secrets,
        "recent_audits": recent_audits,
    }

    if user_id:
        stats["user_quota"] = get_user_quota(user_id)
        stats["expiration_warnings"] = get_expiration_warnings(user_id)

    return stats
