"""Auth Agent — User lifecycle, audit logging, decorators."""

from datetime import datetime, timezone
from functools import wraps

import bcrypt
from flask import session, redirect, url_for, flash, request

from extensions import db
from models import User, AuditLog


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# User lifecycle
# ---------------------------------------------------------------------------
def register_user(username: str, email: str, password: str, role: str = "user") -> User:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
    )
    db.session.add(user)
    db.session.commit()
    return user


def authenticate(username: str, password: str) -> User | None:
    user = User.query.filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        return user
    return None


def get_current_user(user_id: int) -> User | None:
    return db.session.get(User, user_id)


# ---------------------------------------------------------------------------
# Admin user ops
# ---------------------------------------------------------------------------
def list_users():
    return User.query.order_by(User.created_at.desc()).all()


def toggle_user_role(user_id: int) -> User | None:
    user = db.session.get(User, user_id)
    if user:
        user.role = "user" if user.role == "admin" else "admin"
        db.session.commit()
    return user


def delete_user(user_id: int) -> User | None:
    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return user


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
def generate_audit_event(user_id: int | None, username: str, action: str,
                         detail: str = "", ip_address: str = "") -> AuditLog:
    if not ip_address:
        ip_address = request.remote_addr or ""
    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        detail=detail,
        ip_address=ip_address,
    )
    db.session.add(entry)
    db.session.commit()
    return entry


def list_audit_logs(limit: int = 100) -> list[AuditLog]:
    return AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
