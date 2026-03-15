import os
import re
import secrets
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, g, jsonify,
)

from extensions import db, csrf
from models import User, Secret, SecretField, Tag, AuditLog, PolicyConfig
from agents import vault_agent, auth_agent, policy_agent

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
# Use /tmp on Vercel (read-only filesystem), local instance dir otherwise
_is_vercel = os.environ.get("VERCEL", False)
_db_path = "/tmp/secrets.db" if _is_vercel else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "instance", "secrets.db"
)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_db_path}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_FIELDS_PER_SECRET"] = 50

db.init_app(app)
csrf.init_app(app)

# ---------------------------------------------------------------------------
# Context processor — make current user available in templates
# ---------------------------------------------------------------------------
@app.before_request
def load_current_user():
    g.current_user = None
    if "user_id" in session:
        g.current_user = auth_agent.get_current_user(session["user_id"])
        if g.current_user is None:
            session.clear()


@app.context_processor
def inject_user():
    return dict(current_user=g.current_user)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            errors.append("Username may only contain letters, numbers, and underscores.")
        if not email or "@" not in email:
            errors.append("Valid email is required.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("Username already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", username=username, email=email)

        user = auth_agent.register_user(username, email, password)
        auth_agent.generate_audit_event(user.id, username, "user_register")
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Rate limit login attempts
        allowed, msg = policy_agent.check_rate_limit(0, "login_attempt")
        if not allowed:
            flash(msg, "danger")
            return render_template("login.html", username=username)

        user = auth_agent.authenticate(username, password)
        if user:
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            auth_agent.generate_audit_event(user.id, username, "user_login")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))

        auth_agent.generate_audit_event(None, username, "login_failed")
        flash("Invalid username or password.", "danger")
        return render_template("login.html", username=username)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@auth_agent.login_required
def logout():
    auth_agent.generate_audit_event(session.get("user_id"), session.get("username", ""), "user_logout")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@auth_agent.login_required
def dashboard():
    user_id = session["user_id"]
    is_admin = session.get("role") == "admin"
    tag_filter = request.args.get("tag", "").strip() or None

    my_secrets, other_secrets = vault_agent.list_secrets_for_user(user_id, is_admin, tag_filter)
    all_tags = vault_agent.list_all_tags()

    return render_template(
        "dashboard.html",
        my_secrets=my_secrets,
        other_secrets=other_secrets,
        is_admin=is_admin,
        all_tags=all_tags,
        active_tag=tag_filter,
    )


# ---------------------------------------------------------------------------
# Secret CRUD
# ---------------------------------------------------------------------------
@app.route("/secrets/new", methods=["GET", "POST"])
@auth_agent.login_required
def secret_create():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        visibility = request.form.get("visibility", "private")
        fields = vault_agent.parse_fields(request.form, app.config["MAX_FIELDS_PER_SECRET"])
        raw_tags = request.form.get("tags", "").strip()
        tag_names = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

        errors = []
        if not name:
            errors.append("Secret name is required.")
        if visibility not in ("public", "private"):
            errors.append("Invalid visibility setting.")
        if not fields:
            errors.append("At least one field is required.")

        # Policy checks
        user_id = session["user_id"]
        allowed, msg = policy_agent.check_rate_limit(user_id, "secret_create")
        if not allowed:
            errors.append(msg)
        allowed, msg = policy_agent.check_quota(user_id)
        if not allowed:
            errors.append(msg)
        for tn in tag_names:
            ok, tmsg = policy_agent.check_tag_policy(tn)
            if not ok:
                errors.append(tmsg)

        # Content warnings (non-blocking)
        content_warnings = policy_agent.validate_secret_content(fields)
        for w in content_warnings:
            flash(w, "warning")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("secret_form.html", editing=False,
                                   name=name, description=description,
                                   visibility=visibility, fields=fields,
                                   tag_string=raw_tags)

        secret = vault_agent.create_secret(user_id, name, description, visibility, fields, tag_names)
        auth_agent.generate_audit_event(user_id, session["username"], "secret_create",
                                        detail=f"Created secret '{name}' (id={secret.id})")
        flash("Secret created successfully.", "success")
        return redirect(url_for("secret_view", secret_id=secret.id))

    return render_template("secret_form.html", editing=False, fields=[], tag_string="")


@app.route("/secrets/<int:secret_id>")
@auth_agent.login_required
def secret_view(secret_id):
    secret = vault_agent.get_secret(secret_id)
    if not secret:
        abort(404)
    if not vault_agent.can_view(secret, session["user_id"], session.get("role", "")):
        abort(403)

    decrypted_fields = vault_agent.get_decrypted_fields(secret)

    return render_template(
        "secret_view.html",
        secret=secret,
        fields=decrypted_fields,
        can_edit=vault_agent.can_edit(secret, session["user_id"], session.get("role", "")),
    )


@app.route("/secrets/<int:secret_id>/edit", methods=["GET", "POST"])
@auth_agent.login_required
def secret_edit(secret_id):
    secret = vault_agent.get_secret(secret_id)
    if not secret:
        abort(404)
    if not vault_agent.can_edit(secret, session["user_id"], session.get("role", "")):
        abort(403)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        visibility = request.form.get("visibility", "private")
        fields = vault_agent.parse_fields(request.form, app.config["MAX_FIELDS_PER_SECRET"])
        raw_tags = request.form.get("tags", "").strip()
        tag_names = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

        errors = []
        if not name:
            errors.append("Secret name is required.")
        if visibility not in ("public", "private"):
            errors.append("Invalid visibility setting.")
        if not fields:
            errors.append("At least one field is required.")

        for tn in tag_names:
            ok, tmsg = policy_agent.check_tag_policy(tn)
            if not ok:
                errors.append(tmsg)

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("secret_form.html", editing=True,
                                   secret=secret, name=name,
                                   description=description,
                                   visibility=visibility, fields=fields,
                                   tag_string=raw_tags)

        vault_agent.update_secret(secret, name, description, visibility, fields, tag_names)
        auth_agent.generate_audit_event(session["user_id"], session["username"], "secret_edit",
                                        detail=f"Updated secret '{name}' (id={secret.id})")
        flash("Secret updated successfully.", "success")
        return redirect(url_for("secret_view", secret_id=secret.id))

    # GET — populate form with existing data
    fields = [(f.field_name, vault_agent.decrypt_value(f.field_value_encrypted)) for f in secret.fields]
    tag_string = ", ".join(t.name for t in secret.tags)
    return render_template("secret_form.html", editing=True, secret=secret,
                           name=secret.name, description=secret.description,
                           visibility=secret.visibility, fields=fields,
                           tag_string=tag_string)


@app.route("/secrets/<int:secret_id>/delete", methods=["POST"])
@auth_agent.login_required
def secret_delete(secret_id):
    secret = vault_agent.get_secret(secret_id)
    if not secret:
        abort(404)
    if not vault_agent.can_edit(secret, session["user_id"], session.get("role", "")):
        abort(403)

    secret_name = secret.name
    vault_agent.delete_secret(secret)
    auth_agent.generate_audit_event(session["user_id"], session["username"], "secret_delete",
                                    detail=f"Deleted secret '{secret_name}' (id={secret_id})")
    flash("Secret deleted.", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Tag API (typeahead autocomplete)
# ---------------------------------------------------------------------------
@app.route("/api/tags/search")
@auth_agent.login_required
def api_tags_search():
    q = request.args.get("q", "").strip()
    tags = vault_agent.search_tags(q) if q else vault_agent.list_all_tags()[:20]
    return jsonify([{"id": t.id, "name": t.name, "color": t.color} for t in tags])


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@auth_agent.admin_required
def admin_users():
    users = auth_agent.list_users()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle-role", methods=["POST"])
@auth_agent.admin_required
def admin_toggle_role(user_id):
    if user_id == session["user_id"]:
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("admin_users"))

    user = auth_agent.toggle_user_role(user_id)
    if not user:
        abort(404)
    auth_agent.generate_audit_event(session["user_id"], session["username"], "admin_toggle_role",
                                    detail=f"Changed {user.username} to {user.role}")
    flash(f"{user.username} is now a{'n admin' if user.role == 'admin' else ' regular user'}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@auth_agent.admin_required
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin_users"))

    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    username = user.username
    auth_agent.delete_user(user_id)
    auth_agent.generate_audit_event(session["user_id"], session["username"], "admin_delete_user",
                                    detail=f"Deleted user '{username}'")
    flash(f"User {username} deleted.", "info")
    return redirect(url_for("admin_users"))


@app.route("/admin/secrets")
@auth_agent.admin_required
def admin_secrets():
    secrets_list = Secret.query.order_by(Secret.updated_at.desc()).all()
    return render_template("admin_secrets.html", secrets=secrets_list)


@app.route("/admin/tags")
@auth_agent.admin_required
def admin_tags():
    tags = vault_agent.list_all_tags()
    return render_template("admin_tags.html", tags=tags)


@app.route("/admin/tags/<int:tag_id>/delete", methods=["POST"])
@auth_agent.admin_required
def admin_delete_tag(tag_id):
    tag = vault_agent.delete_tag(tag_id)
    if not tag:
        abort(404)
    auth_agent.generate_audit_event(session["user_id"], session["username"], "admin_delete_tag",
                                    detail=f"Deleted tag '{tag.name}'")
    flash(f"Tag '{tag.name}' deleted.", "info")
    return redirect(url_for("admin_tags"))


@app.route("/admin/tags/<int:tag_id>/color", methods=["POST"])
@auth_agent.admin_required
def admin_update_tag_color(tag_id):
    color = request.form.get("color", "#6366f1").strip()
    tag = vault_agent.update_tag_color(tag_id, color)
    if not tag:
        abort(404)
    flash(f"Tag '{tag.name}' color updated.", "success")
    return redirect(url_for("admin_tags"))


@app.route("/admin/audit")
@auth_agent.admin_required
def admin_audit():
    logs = auth_agent.list_audit_logs(limit=200)
    return render_template("admin_audit.html", logs=logs)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


# ---------------------------------------------------------------------------
# Bootstrap admin + DB creation
# ---------------------------------------------------------------------------
def init_app():
    with app.app_context():
        db.create_all()

        # Enable WAL mode for better concurrent read performance
        with db.engine.connect() as conn:
            conn.execute(db.text("PRAGMA journal_mode=WAL"))
            conn.commit()

        # Create default admin if none exists
        if not User.query.filter_by(role="admin").first():
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "admin1234")
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@vault.local")
            admin = auth_agent.register_user(admin_user, admin_email, admin_pass, role="admin")
            print(f"[INIT] Admin user '{admin_user}' created.")


init_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
